#!/bin/bash
# apply.sh — 以 root 身份：挂载系统卷 -> 打补丁 -> 建快照
set -uo pipefail

DIR="$(cd "$(dirname "$0")" && pwd)"
PY="$DIR/a2dp_fix.py"
MP="/System/Volumes/Update/mnt1"
# 用干净环境调用系统 python，避免继承宿主的 sitecustomize 注入
PYBIN="/usr/bin/python3"
run_py() { env -i PATH=/usr/bin:/bin:/usr/sbin:/sbin HOME=/var/root "$PYBIN" "$PY" "$@"; }

say() { printf '\n== %s ==\n' "$*"; }
die() { printf '\n[!] %s\n' "$*"; exit 1; }

[ "$(id -u)" = "0" ] || die "需要 root 权限"

say "0. 识别系统卷"
ROOTDEV="$(df / | tail -1 | awk '{print $1}')"
echo "根设备: $ROOTDEV"
SYSDEV="${ROOTDEV%s1}"
[ "$SYSDEV" != "$ROOTDEV" ] || die "根设备不是快照设备，脚本不适用"
echo "系统卷: $SYSDEV"
diskutil info "$SYSDEV" 2>/dev/null | grep -E "Volume Name|Sealed"
diskutil apfs list 2>/dev/null | grep -q "$(basename "$SYSDEV") (System)" || die "$SYSDEV 不是 System 卷，中止"

say "1. 挂载系统卷到 $MP"
mkdir -p "$MP"
rm -f "$MP/usr/sbin/bluetoothd.a2dptmp" 2>/dev/null
if mount | grep -q " on $MP "; then
    echo "已挂载，跳过"
else
    mount -o nobrowse -t apfs "$SYSDEV" "$MP" || die "挂载失败"
fi
TARGET_FILE="$MP/usr/sbin/bluetoothd"
[ -f "$TARGET_FILE" ] || die "找不到 $TARGET_FILE"

say "2. 打补丁前检查"
run_py --check --target "$TARGET_FILE" || die "检查失败"

say "3. 写入补丁"
run_py --patch --target "$TARGET_FILE" || die "写入失败"

say "4. 写入后复核"
run_py --check --target "$TARGET_FILE"

say "4.5 重新 ad-hoc 签名（必须，否则 AMFI 会 kill 进程）"
ENT="/tmp/a2dp-ent.$$.plist"
SRC=""
for f in "$DIR"/backup/bluetoothd-*; do
    [ -f "$f" ] || continue
    if codesign --verify "$f" >/dev/null 2>&1; then SRC="$f"; break; fi
done
[ -n "$SRC" ] || die "找不到未修改的原版备份，无法取 entitlements"
echo "entitlements 来源: $(basename "$SRC")"
codesign -d --entitlements :- "$SRC" > "$ENT" 2>/dev/null
[ -s "$ENT" ] || die "导出 entitlements 失败"
codesign -f -s - --timestamp=none --entitlements "$ENT" "$TARGET_FILE" 2>&1 | tail -2
rm -f "$ENT"
codesign --verify --verbose=2 "$TARGET_FILE" 2>&1 | tail -3
codesign --verify "$TARGET_FILE" >/dev/null 2>&1 || die "重签后校验失败"
echo "[+] 签名已修复"
run_py --check --target "$TARGET_FILE" | tail -3

say "5. 重建系统快照（让修改进入下次启动）"
bless --mount "$MP" --bootefi --create-snapshot
BLESS_RC=$?
echo "bless 返回: $BLESS_RC"

say "6. 卸载"
umount "$MP" && echo "已卸载"

if [ "$BLESS_RC" = "0" ]; then
    echo
    echo "== 完成，可以重启了 =="
else
    echo
    echo "[!] 快照创建返回 $BLESS_RC，修改可能未进入启动快照，先别急着重启，把上面的输出发我"
fi
