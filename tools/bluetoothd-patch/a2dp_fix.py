#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
a2dp_fix.py — 为 macOS 26.7.2 (25G332) 的 bluetoothd 补齐 -btlfxadvsets 的 6 处补丁

背景：crazyhulk/BlueToolFixup-FixA2DP-BLE 的 -btlfxadvsets 补丁只匹配 macOS 26.4.1
(25E253)。本机 26.7.2 (25G332) 上：
  - 扩展扫描能力、广播集地址重发：字节模式仍匹配（文件里已是打过状态）
  - BT Spec 广播集能力、LE 事件掩码、广播集随机地址开关、LE 扩展建连：偏移/指令变了，没打上
本脚本把缺的补上，只改 x86_64 切片，不动 arm64e 切片，可随时用 --restore 还原。

用法：
  sudo python3 a2dp_fix.py --check            # 只检查（默认）
  sudo python3 a2dp_fix.py --patch            # 备份 + 写入
  sudo python3 a2dp_fix.py --restore <备份>    # 还原
"""

import argparse
import os
import shutil
import struct
import sys
import time

TARGET = "/usr/sbin/bluetoothd"
BACKUP_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "backup")

# (名称, 定位模式, 通配下标, 替换片段起始下标, 原字节, 新字节)
SITES = [
    (
        "BT Spec 广播集能力 (call [rcx+0x918] -> mov eax,1)",
        "488B084889C7FF91180900004189C6",
        set(), 6,
        "FF9118090000",
        "B80100000090",
    ),
    (
        "扩展扫描能力 (call [rcx+0x9a8] -> mov al,1)",
        "488B084889C7FF91A80900004189C6",
        set(), 6,
        "FF91A8090000",
        "B00190909090",
    ),
    (
        "LE 事件掩码 (cmove rdx,rax -> nop)",
        "85C0488D05????????488D15????????480F44D0",
        {5, 6, 7, 8, 12, 13, 14, 15}, 16,
        "480F44D0",
        "0F1F4000",
    ),
    (
        "广播集随机地址开关 (ja +0x2a -> jmp +7)",
        "83B83403000003772A",
        set(), 7,
        "772A",
        "EB07",
    ),
    (
        "LE 扩展建连 (movzx edi,[rbp-0xa2] -> mov edi,1)",
        "0FB6BD5EFFFFFFE8",
        set(), 0,
        "0FB6BD5EFFFFFF",
        "BF010000006690",
    ),
    (
        "广播集地址重发 (je +0x80 -> nop6)",
        "8B543A03339408????????4409C20F8480000000",
        {7, 8, 9, 10}, 14,
        "0F8480000000",
        "660F1F440000",
    ),
]


def die(msg):
    print("[!] " + msg)
    sys.exit(1)


def parse_fat(data):
    magic = struct.unpack_from(">I", data, 0)[0]
    if magic not in (0xCAFEBABE, 0xCAFEBABF):
        return None
    nfat = struct.unpack_from(">I", data, 4)[0]
    out = []
    for i in range(nfat):
        cputype, cpusub, offset, size, align = struct.unpack_from(">5I", data, 8 + i * 20)
        out.append((offset, size, cputype))
    return out


def find_all(hay, pat, wild):
    hits, n, first = [], len(pat), pat[0]
    i = hay.find(bytes([first]))
    while i >= 0:
        if i + n <= len(hay) and all(k in wild or hay[i + k] == pat[k] for k in range(n)):
            hits.append(i)
        i = hay.find(bytes([first]), i + 1)
    return hits


def parse_pattern(s):
    """把形如 '48 8B ?? 91' 的模式解析成 (bytes, 通配下标集合)"""
    s = s.replace(" ", "")
    pat, wild = bytearray(), set()
    for i in range(0, len(s), 2):
        pair = s[i:i + 2]
        if pair == "??":
            pat.append(0)
            wild.add(len(pat) - 1)
        else:
            pat.append(int(pair, 16))
    return bytes(pat), wild


def build(pat_hex, off, new_hex):
    pat, wild = parse_pattern(pat_hex)
    new = bytes.fromhex(new_hex)
    return pat, wild, new, bytes(pat[:off]) + new + bytes(pat[off + len(new):])


def analyse(hay):
    rows = []
    for name, pat_hex, _wild, off, orig_hex, new_hex in SITES:
        pat, wild, new, done_pat = build(pat_hex, off, new_hex)
        orig = bytes.fromhex(orig_hex)
        done_hits = [h + off for h in find_all(hay, done_pat, wild)]
        orig_hits = [h + off for h in find_all(hay, pat, wild)
                     if hay[h + off:h + off + len(orig)] == orig]
        state = "done" if done_hits else ("todo" if orig_hits else "missing")
        rows.append({
            "name": name, "state": state, "new": new, "orig": orig,
            "sites": done_hits if done_hits else orig_hits,
            "site_off": off,
        })
    return rows


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--target", default=TARGET)
    ap.add_argument("--check", action="store_true")
    ap.add_argument("--patch", action="store_true")
    ap.add_argument("--restore", metavar="BACKUP")
    args = ap.parse_args()

    if args.restore:
        if os.geteuid() != 0:
            die("还原需要 root：sudo python3 a2dp_fix.py --restore <备份>")
        shutil.copy2(args.restore, args.target)
        print("[+] 已还原:", args.target, "（重启后生效）")
        return

    data = bytearray(open(args.target, "rb").read())
    arches = parse_fat(data)
    if not arches:
        die("不是 Universal 二进制")
    x86 = next(((o, s) for o, s, c in arches if c == 0x01000007), None)
    if not x86:
        die("找不到 x86_64 切片")
    off, size = x86
    hay = bytes(data[off:off + size])

    rows = analyse(hay)
    print("目标   : %s" % args.target)
    print("x86_64 : offset=0x%x size=0x%x\n" % (off, size))
    for r in rows:
        label = {"done": "已打", "todo": "待打", "missing": "未找到"}[r["state"]]
        print("  [%s] %-50s %s" % (label, r["name"],
                                    ", ".join("0x%x" % s for s in r["sites"][:3])))

    todo = [r for r in rows if r["state"] == "todo"]
    missing = [r for r in rows if r["state"] == "missing"]
    print("\n合计: 已打 %d / 待打 %d / 未找到 %d" %
          (sum(r["state"] == "done" for r in rows), len(todo), len(missing)))

    if missing:
        print("\n[!] 有补丁点没找到，版本可能不符，已中止。")
        for r in missing:
            print("    -", r["name"])
        return

    if not args.patch:
        print("\n（仅检查，未写入；加 --patch 执行）")
        return

    if os.geteuid() != 0 and os.path.abspath(args.target) == TARGET:
        die("写入需要 root：sudo python3 a2dp_fix.py --patch")
    if not todo:
        print("\n[+] 已是目标状态，无需写入")
        return

    os.makedirs(BACKUP_DIR, exist_ok=True)
    backup = os.path.join(BACKUP_DIR, "bluetoothd-" + time.strftime("%Y%m%d-%H%M%S"))
    shutil.copy2(args.target, backup)
    print("\n[+] 备份 -> %s" % backup)

    for r in todo:
        for site in r["sites"]:
            pos = off + site
            if bytes(data[pos:pos + len(r["orig"])]) != r["orig"]:
                die("写入前校验失败: %s @0x%x" % (r["name"], pos))
            data[pos:pos + len(r["new"])] = r["new"]
            print("[+] %s -> 文件偏移 0x%x" % (r["name"].split(" (")[0], pos))

    tmp = args.target + ".a2dptmp"
    with open(tmp, "wb") as f:
        f.write(data)
    os.chmod(tmp, 0o755)
    shutil.move(tmp, args.target)
    print("\n[+] 写入完成。备份在 %s" % BACKUP_DIR)
    print("    重启（或 killall bluetoothd）后生效；签名本就失效，amfi=0x80 下可正常运行。")


if __name__ == "__main__":
    main()
