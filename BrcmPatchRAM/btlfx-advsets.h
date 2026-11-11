/* btlfx-advsets.h —— 运行期 advsets 补丁引擎（BlueToolFixup 用）
 *
 * 与作者原实现的差别：
 *
 *   1) 全部 disp32 / rel32 通配。原实现把 26.4.1 的 vtable 槽位（+0x9c0/+0x9a8）、
 *      栈帧偏移（-0xa2）、结构体偏移（+0x334）、rip 位移全部写死，换个小版本就 0 命中，
 *      最坏情况（advsets-cap 那条）会命中到另一个能力 getter 上，静默改错地方。
 *
 *   2) 能力 getter 不再靠"序位"或"写死的槽位"，而是结构配对：同一页内所有
 *      `mov rcx,[rax]; mov rdi,rax; call [rcx+disp32]; mov r14d,eax; mov [rip+rel32],al`
 *      形态的命中按地址排序，取"标志位地址相差 0x10 且代码相距 < 0x400"的第一对，
 *      即 supportsExtendedScanning / supportsAdvertisingSets 这一对相邻能力。
 *      这条规则同时用 26.4.1（0x9a8/0x9c0）与 26.7.2（0x9a8/0x918）验证过。
 *
 *   3) 页级事务：XNU 的 cs_validate_page 是逐页回调，跨页做不了原子提交，
 *      所以每个页内"先全部定位、再写入、再回读"，任一站点不符就整页放弃。
 *      绝不出现"改了一半"的页。
 *
 *   4) 幂等：页若已是补丁后形态（重复 page-in），直接返回已打，不重复改写。
 *
 *   5) 失败可诊断：返回具体站点名，SYSLOG 里能直接看到是哪一条没匹配上。
 *
 * 所有站点都落在单个 4KB 页内（已在 26.7.2 上逐条验证页内余量 >= 模式长度）。
 *
 * 2.7.6：并入 PR #1 (pr/btlfx-advsets-26.7.2) 的 5 个 RPA / Filter Accept List
 * 代码注入站点。这些 pattern 是 25G332 专用的手写 x86 代码（含硬编码 E8 rel32 与
 * RIP 相对全局缓存地址），无法做通配符化；因此改为按「组」管理：
 *   RPA 组（同页 2 站）：rpa-resolve-hook + rpa-resolve-save，hook 的 call 跳进 save
 *   FAL 组（同页 3 站）：fal-add + fal-lookup-helper + fal-remove，前后两处 call 都跳进 helper
 * 组内必须「全部唯一命中原始形态」才写入；缺一站、多解、或新旧形态混杂都整页放弃，
 * 绝不出现 trampoline 跳进未改写代码的情况。写入前先保存原字节，回读不符则整组回滚。
 * 站点间相对偏移做结构校验（0xDB / 0x84 / 0x320），换 build 时宁可不生效也不乱打。
 * 可用 -btlfxrpaoff 单独关掉这 5 站做 A/B 对照。
 */
#pragma once

#include <stdint.h>
#include <stddef.h>

#define BTLFX_ADVSETS_CORE_SITES  7
#define BTLFX_ADVSETS_RPA_SITES   5
#define BTLFX_ADVSETS_SITES       12
#define BTLFX_MAX_CAND            64

/* 单页最多容纳的候选/站点数，够用且不占内核栈太多 */
struct btlfx_cap_hit {
    uint8_t *addr;      /* 模式起点 */
    int32_t  vtable;    /* call [rcx+vtable] 的 disp32 */
    intptr_t flag;      /* mov [rip+rel32],al 的目标（同段内相对比较，不必是真实地址） */
};

/* 站点表：name / 模式 / 掩码 / 改写位置与内容 */
struct btlfx_site {
    const char    *name;
    const uint8_t *pat;
    const uint8_t *msk;
    uint32_t       len;
    uint32_t       patch_off;
    const uint8_t *repl;
    uint32_t       repl_len;
};

/* 结果码 */
enum {
    BTLFX_ADV_OK        = 0,   /* 本页至少改了一处，且全部校验通过 */
    BTLFX_ADV_SKIP      = 1,   /* 本页与 advsets 无关（绝大多数页） */
    BTLFX_ADV_DONE      = 2,   /* 本页已是补丁后形态 */
    BTLFX_ADV_NOTFOUND  = 3,   /* 该页应有的站点没找到 */
    BTLFX_ADV_AMBIG     = 4,   /* 唯一站点出现多解 */
    BTLFX_ADV_SHAPE     = 5,   /* 能力 getter 配对失败（版本结构变了） */
    BTLFX_ADV_VERIFY    = 6,   /* 写入后回读不一致 */
};

static inline bool btlfx_match_at(const uint8_t *p, const uint8_t *pat, const uint8_t *msk, uint32_t len) {
    for (uint32_t i = 0; i < len; i++)
        if (msk[i] && p[i] != pat[i])
            return false;
    return true;
}

/* 在 [base,base+size) 内收集全部命中，返回实际数量（>max 时截断存入） */
static uint32_t btlfx_collect(uint8_t *base, size_t size,
                              const uint8_t *pat, const uint8_t *msk, uint32_t len,
                              uint8_t **out, uint32_t max) {
    uint32_t n = 0;
    if (size < len) return 0;
    for (size_t i = 0; i + len <= size; i++) {
        if (msk[0] && base[i] != pat[0]) continue;
        if (!btlfx_match_at(base + i, pat, msk, len)) continue;
        if (n < max) out[n] = base + i;
        n++;
        if (n > max * 4) break;         /* 离谱数量，早点退出，调用方会判 AMBIG */
    }
    return n;
}

static inline int32_t btlfx_rd32(const uint8_t *p) {
    return (int32_t)((uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24));
}

/* ---- 六个站点的掩码模式（disp32/rel32 全部为 0x00 通配） ---- */

/* supportsExtendedScanning / supportsAdvertisingSets 共用的 getter 骨架：
 *   48 8B 08                mov  rcx, [rax]
 *   48 89 C7                mov  rdi, rax
 *   FF 91 ?? ?? ?? ??       call qword [rcx + disp32]
 *   41 89 C6                mov  r14d, eax
 *   88 05 ?? ?? ?? ??       mov  [rip + rel32], al
 */
static const uint8_t kCapSkel[] =
{
    0x48, 0x8B, 0x08,
    0x48, 0x89, 0xC7,
    0xFF, 0x91, 0x00, 0x00, 0x00, 0x00,
    0x41, 0x89, 0xC6,
    0x88, 0x05, 0x00, 0x00, 0x00, 0x00
};
static const uint8_t kCapMask[] =
{
    0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00,
    0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00
};
static constexpr uint32_t kCapLen = sizeof(kCapSkel);

/* 能力 getter 尾部的 mov [rip+rel32], al 位于骨架偏移 17，命令结束于 21 */
static constexpr uint32_t kCapRelOff = 17;
static constexpr uint32_t kCapSkelLen = 21;

/* call 返回后写 mov al,1（不依赖 eax 高位的脏值） */
static const uint8_t kCapRepl[] = { 0xB8, 0x01, 0x00, 0x00, 0x00, 0x90 };

static const uint8_t kLeEventMaskPat[] =
{
    0x48, 0x8D, 0x05, 0x00, 0x00, 0x00, 0x00,   /* lea rax, [rip+mask1f]  */
    0x48, 0x8D, 0x15, 0x00, 0x00, 0x00, 0x00,   /* lea rdx, [rip+maskFull] */
    0x48, 0x0F, 0x44, 0xD0,                     /* cmove rdx, rax          */
    0x48, 0x8D, 0x35, 0x00, 0x00, 0x00, 0x00,   /* lea rsi, [rip+...]      */
    0xBF, 0xA2, 0x00, 0x00, 0x00                /* mov edi, 0xa2 (协议常量) */
};
static const uint8_t kLeEventMaskMsk[] =
{
    0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00,
    0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00,
    0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF
};
/* cmove -> 4 字节 nop，等价于无条件用全量掩码 */
static const uint8_t kLeEventMaskRepl[] = { 0x0F, 0x1F, 0x40, 0x00 };

static const uint8_t kAdvSetAddrSwitchPat[] =
{
    0x83, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x03,   /* cmp dword [rax+disp32], 3 */
    0x77, 0x00,                                 /* ja  short                 */
    0x31, 0xFF,                                 /* xor edi, edi              */
    0xE8                                        /* call                      */
};
static const uint8_t kAdvSetAddrSwitchMsk[] =
{
    0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF,
    0xFF, 0x00,
    0xFF, 0xFF,
    0xFF
};
/* ja +0x2a -> jmp +7：跳过 LE Set Advertising Set Random Address 那一次调用 */
static const uint8_t kAdvSetAddrSwitchRepl[] = { 0xEB, 0x07 };

static const uint8_t kLeExtConnPat[] =
{
    0x0F, 0xB6, 0xBD, 0x00, 0x00, 0x00, 0x00,   /* movzx edi, byte [rbp+disp32] */
    0xE8, 0x00, 0x00, 0x00, 0x00,               /* call                        */
    0x44, 0x0F, 0xB6, 0xBD, 0x00, 0x00, 0x00, 0x00, /* movzx r15d, byte [...]  */
    0x44, 0x89                                  /* mov ...                     */
};
static const uint8_t kLeExtConnMsk[] =
{
    0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00,
    0xFF, 0x00, 0x00, 0x00, 0x00,
    0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00,
    0xFF, 0xFF
};
/* mov edi, 1; nop; nop —— 让 extended create connection 走扩展路径 */
static const uint8_t kLeExtConnRepl[] = { 0xBF, 0x01, 0x00, 0x00, 0x00, 0x90, 0x90 };

static const uint8_t kAdvSetAddrResendPat[] =
{
    0x44, 0x09, 0xC2,                           /* or  edx, r8d        */
    0x0F, 0x84, 0x00, 0x00, 0x00, 0x00,         /* je  near            */
    0x80, 0x3D, 0x00, 0x00, 0x00, 0x00, 0x00,   /* cmp byte [rip+..],0 */
    0x74                                        /* je  short           */
};
static const uint8_t kAdvSetAddrResendMsk[] =
{
    0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00,
    0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF,
    0xFF
};
/* je -> 6 字节 nop：无条件重发广播集随机地址 */
static const uint8_t kAdvSetAddrResendRepl[] = { 0x66, 0x0F, 0x1F, 0x44, 0x00, 0x00 };

/* ---- PR #1 / 25G332：5 个 RPA / Filter Accept List 代码注入站点 ----
 * 原始字节与替换字节等长；替换字节内含手写 x86 代码（16 槽 ×0x18 的 RPA 缓存、
 * FAL 命令里把 Identity Address 换成最新 RPA）。来源于 PR #1 提交 929c7f6，
 * 由脚本从 BlueToolFixup.cpp 原样提取，未手改一个字节。
 */
static const uint8_t kRpaHookOrig[] = {
    0x42, 0x8A, 0x44, 0x20, 0xFF, 0x41, 0x88, 0x46, 0x06, 0x66, 0x41, 0x89,
    0x56, 0x04, 0x41, 0x89, 0x0E, 0xC6, 0x03, 0x01
};

static const uint8_t kRpaHookDone[] = {
    0x42, 0x8A, 0x44, 0x20, 0xFF, 0x41, 0x88, 0x46, 0x06, 0x66, 0x41, 0x89,
    0x56, 0x04, 0xE8, 0xCA, 0x00, 0x00, 0x00, 0x90
};

static const uint8_t kRpaSaveOrig[] = {
    0xBF, 0x01, 0x00, 0x00, 0x00, 0xBE, 0x43, 0x00, 0x00, 0x00, 0xE8, 0x36,
    0x0A, 0xEC, 0xFF, 0x84, 0xC0, 0x74, 0x65, 0x48, 0x8D, 0x3D, 0x72, 0xD4,
    0x71, 0x00, 0x31, 0xDB, 0x31, 0xC0, 0xE8, 0x85, 0x83, 0x02, 0x00, 0xBF,
    0x43, 0x00, 0x00, 0x00, 0xE8, 0xEE, 0xE1, 0xE9, 0xFF, 0x49, 0x89, 0xC6,
    0x48, 0x89, 0xC7, 0xBE
};

static const uint8_t kRpaSaveDone[] = {
    0xEB, 0x76, 0x41, 0x89, 0x0E, 0xC6, 0x03, 0x01, 0x44, 0x89, 0xE8, 0x83,
    0xE0, 0x0F, 0x48, 0x8D, 0x04, 0x40, 0x48, 0x8D, 0x15, 0x71, 0xB6, 0x92,
    0x00, 0x48, 0x8D, 0x04, 0xC2, 0x89, 0x08, 0x41, 0x8B, 0x4E, 0x03, 0x89,
    0x48, 0x03, 0x41, 0x8B, 0x0F, 0x89, 0x48, 0x08, 0x41, 0x8B, 0x4F, 0x03,
    0x89, 0x48, 0x0B, 0xC3
};

static const uint8_t kFalAddOrig[] = {
    0x49, 0x89, 0xC6, 0x41, 0x0F, 0xB6, 0x17, 0x49, 0x8D, 0x4F, 0x01, 0x48,
    0x8D, 0x35, 0x88, 0x01, 0x00, 0x00
};

static const uint8_t kFalAddDone[] = {
    0x49, 0x89, 0xC6, 0x31, 0xD2, 0xE8, 0x84, 0x00, 0x00, 0x00, 0x90, 0x48,
    0x8D, 0x35, 0x88, 0x01, 0x00, 0x00
};

static const uint8_t kFalHelperOrig[] = {
    0xBF, 0x02, 0x00, 0x00, 0x00, 0xBE, 0x42, 0x00, 0x00, 0x00, 0xE8, 0x2F,
    0x2B, 0xEB, 0xFF, 0xBB, 0x68, 0x00, 0x00, 0x00, 0x84, 0xC0, 0x0F, 0x84,
    0x9C, 0x00, 0x00, 0x00, 0x0F, 0xB6, 0x35, 0x52, 0x30, 0x90, 0x00, 0x0F,
    0xB7, 0x15, 0x49, 0x30, 0x90, 0x00, 0x48, 0x8D, 0x3D, 0x37, 0x1C, 0x71,
    0x00, 0x31, 0xC0, 0xE8, 0x69, 0xA4, 0x01, 0x00, 0xBF, 0x42, 0x00, 0x00,
    0x00, 0xE8, 0xD2, 0x02, 0xE9, 0xFF, 0x49, 0x89, 0xC6, 0x48, 0x89, 0xC7,
    0xBE, 0x10, 0x00, 0x00, 0x00, 0xE8, 0x85, 0x96, 0x64, 0x00, 0x84, 0xC0,
    0x74, 0x62, 0x4C, 0x89, 0xF7, 0xE8, 0xEE
};

static const uint8_t kFalHelperDone[] = {
    0xBB, 0x68, 0x00, 0x00, 0x00, 0xE9, 0xAE, 0x00, 0x00, 0x00, 0x48, 0x8D,
    0x05, 0x72, 0xD7, 0x91, 0x00, 0xB9, 0x10, 0x00, 0x00, 0x00, 0x41, 0x8B,
    0x37, 0x41, 0x8B, 0x7F, 0x03, 0x80, 0x7C, 0xD0, 0x08, 0x01, 0x75, 0x24,
    0x44, 0x8B, 0x00, 0x41, 0x31, 0xF0, 0x44, 0x8B, 0x48, 0x03, 0x41, 0x31,
    0xF9, 0x45, 0x09, 0xC1, 0x75, 0x12, 0x84, 0xD2, 0x75, 0x08, 0x48, 0x8B,
    0x70, 0x08, 0x48, 0x89, 0x70, 0x10, 0x48, 0x8D, 0x40, 0x10, 0xEB, 0x0B,
    0x48, 0x83, 0xC0, 0x18, 0xFF, 0xC9, 0x75, 0xCD, 0x4C, 0x89, 0xF8, 0x0F,
    0xB6, 0x10, 0x48, 0x8D, 0x48, 0x01, 0xC3
};

static const uint8_t kFalRemoveOrig[] = {
    0x48, 0x89, 0xC3, 0x41, 0x0F, 0xB6, 0x17, 0x49, 0x8D, 0x4F, 0x01, 0x48,
    0x8D, 0x35, 0xD9, 0x00, 0x00, 0x00
};

static const uint8_t kFalRemoveDone[] = {
    0x48, 0x89, 0xC3, 0x6A, 0x01, 0x5A, 0xE8, 0x63, 0xFD, 0xFF, 0xFF, 0x48,
    0x8D, 0x35, 0xD9, 0x00, 0x00, 0x00
};

#define BTLFX_MAX_CODE_SITES   3
#define BTLFX_MAX_CODE_BYTES   256

enum {
    BTLFX_GRP_ABSENT = 0,   /* 本页没有本组站点 */
    BTLFX_GRP_READY  = 1,   /* 全部原始形态唯一命中，结构校验通过，可提交 */
    BTLFX_GRP_DONE   = 2,   /* 本页已是补丁后形态 */
    BTLFX_GRP_ERROR  = 3    /* 缺站 / 多解 / 新旧混杂 / 结构不符 —— 整页放弃 */
};

struct btlfx_code_site {
    const char    *name;
    const uint8_t *orig;
    const uint8_t *done;
    uint32_t       len;
    ptrdiff_t      rel;      /* 相对组内第 0 站的期望偏移 */
};

struct btlfx_group_plan {
    int         status;
    int         rc;
    const char *failed;
    uint8_t    *addr[BTLFX_MAX_CODE_SITES];
};

/* 精确匹配（首个命中地址写入 out，返回总命中数，>4 提前退出） */
static uint32_t btlfx_find_exact(uint8_t *base, size_t size, const uint8_t *pat, uint32_t len, uint8_t **out) {
    uint32_t n = 0;
    *out = nullptr;
    if (size < len) return 0;
    for (size_t i = 0; i + len <= size; i++) {
        if (base[i] != pat[0]) continue;
        bool ok = true;
        for (uint32_t j = 1; j < len; j++)
            if (base[i + j] != pat[j]) { ok = false; break; }
        if (!ok) continue;
        if (n == 0) *out = base + i;
        n++;
        if (n > 4) break;
    }
    return n;
}

/* 探测一页内某组的状态。不做任何写入。 */
static void btlfx_probe_group(uint8_t *base, size_t size,
                              const btlfx_code_site *sites, uint32_t n,
                              btlfx_group_plan *plan) {
    plan->status = BTLFX_GRP_ABSENT;
    plan->rc = BTLFX_ADV_SKIP;
    plan->failed = nullptr;
    for (uint32_t i = 0; i < BTLFX_MAX_CODE_SITES; i++) plan->addr[i] = nullptr;

    uint32_t seenOrig = 0, seenDone = 0;
    for (uint32_t i = 0; i < n; i++) {
        uint8_t *o = nullptr, *d = nullptr;
        uint32_t no = btlfx_find_exact(base, size, sites[i].orig, sites[i].len, &o);
        uint32_t nd = btlfx_find_exact(base, size, sites[i].done, sites[i].len, &d);
        if (no > 1 || nd > 1 || (no && nd)) {
            plan->status = BTLFX_GRP_ERROR;
            plan->rc = BTLFX_ADV_AMBIG;
            plan->failed = sites[i].name;
            return;
        }
        if (no == 1) { plan->addr[i] = o; seenOrig++; }
        if (nd == 1) seenDone++;
    }

    /* 只有「至少一个原始站点」或「整组都已打过」才算本组相关页，
     * 避免别的页里偶然出现一段替换字节就被误判成半打状态。 */
    if (seenOrig == 0 && seenDone < n) return;
    if (seenDone == n && seenOrig == 0) { plan->status = BTLFX_GRP_DONE; return; }
    if (seenOrig == n && seenDone == 0) {
        for (uint32_t i = 0; i < n; i++) {
            if (!plan->addr[i] || plan->addr[i] - plan->addr[0] != sites[i].rel) {
                plan->status = BTLFX_GRP_ERROR;
                plan->rc = BTLFX_ADV_SHAPE;
                plan->failed = sites[i].name;
                return;
            }
        }
        plan->status = BTLFX_GRP_READY;
        return;
    }
    plan->status = BTLFX_GRP_ERROR;
    plan->rc = BTLFX_ADV_SHAPE;
    plan->failed = sites[0].name;
}

/* 提交一组：先全量保存原字节，再全量写入，回读不符则整组回滚。
 * 两个组分别落在 0x227000 / 0x235000 两页，不会在同一页同时 READY。 */
static int btlfx_commit_group(const btlfx_code_site *sites, uint32_t n,
                              const btlfx_group_plan *plan,
                              int *applied, const char **failed) {
    if (plan->status == BTLFX_GRP_ABSENT || plan->status == BTLFX_GRP_DONE)
        return BTLFX_ADV_DONE;
    if (plan->status != BTLFX_GRP_READY) {
        *failed = plan->failed;
        return plan->rc;
    }

    uint8_t saved[BTLFX_MAX_CODE_BYTES];
    uint32_t total = 0;
    for (uint32_t i = 0; i < n; i++) {
        if (total + sites[i].len > sizeof(saved)) {
            *failed = sites[i].name;
            return BTLFX_ADV_VERIFY;
        }
        for (uint32_t j = 0; j < sites[i].len; j++) saved[total + j] = plan->addr[i][j];
        total += sites[i].len;
    }
    for (uint32_t i = 0; i < n; i++)
        for (uint32_t j = 0; j < sites[i].len; j++) plan->addr[i][j] = sites[i].done[j];

    bool ok = true;
    for (uint32_t i = 0; i < n && ok; i++)
        for (uint32_t j = 0; j < sites[i].len; j++)
            if (plan->addr[i][j] != sites[i].done[j]) { ok = false; break; }
    if (!ok) {
        uint32_t off = 0;
        for (uint32_t i = 0; i < n; i++) {
            for (uint32_t j = 0; j < sites[i].len; j++) plan->addr[i][j] = saved[off + j];
            off += sites[i].len;
        }
        *failed = sites[0].name;
        return BTLFX_ADV_VERIFY;
    }
    *applied = (int)n;
    return BTLFX_ADV_OK;
}

static const btlfx_code_site kRpaGroup[] = {
    { "rpa-resolve-hook",  kRpaHookOrig,    kRpaHookDone,    (uint32_t)sizeof(kRpaHookOrig),    0 },
    { "rpa-resolve-save",  kRpaSaveOrig,    kRpaSaveDone,    (uint32_t)sizeof(kRpaSaveOrig),    0xDB },
};

static const btlfx_code_site kFalGroup[] = {
    { "fal-add-rpa",       kFalAddOrig,     kFalAddDone,     (uint32_t)sizeof(kFalAddOrig),     0 },
    { "fal-lookup-helper", kFalHelperOrig,  kFalHelperDone,  (uint32_t)sizeof(kFalHelperOrig),  0x84 },
    { "fal-remove-rpa",    kFalRemoveOrig,  kFalRemoveDone,  (uint32_t)sizeof(kFalRemoveOrig),  0x320 },
};

static const btlfx_site kAdvSetsSites[] =
{
    /* extscan / advsets 两个站点由结构配对填充，这里只占位（name 供日志） */
    { "advsets-cap",        nullptr, nullptr, 0, 0, nullptr, 0 },
    { "extscan-cap",        nullptr, nullptr, 0, 0, nullptr, 0 },
    { "le-event-mask",      kLeEventMaskPat,      kLeEventMaskMsk,      sizeof(kLeEventMaskPat),      14, kLeEventMaskRepl,      sizeof(kLeEventMaskRepl) },
    { "advset-addr-switch", kAdvSetAddrSwitchPat, kAdvSetAddrSwitchMsk, sizeof(kAdvSetAddrSwitchPat),  7, kAdvSetAddrSwitchRepl, sizeof(kAdvSetAddrSwitchRepl) },
    { "le-ext-conn",        kLeExtConnPat,        kLeExtConnMsk,        sizeof(kLeExtConnPat),         0, kLeExtConnRepl,        sizeof(kLeExtConnRepl) },
    { "advset-addr-resend", kAdvSetAddrResendPat, kAdvSetAddrResendMsk, sizeof(kAdvSetAddrResendPat),  3, kAdvSetAddrResendRepl, sizeof(kAdvSetAddrResendRepl) },
};
static constexpr uint32_t kAdvSetsSiteCount = sizeof(kAdvSetsSites) / sizeof(kAdvSetsSites[0]);

/* 写一处并回读校验 */
static inline bool btlfx_write_verify(uint8_t *dst, uint32_t len, uint32_t off, const uint8_t *repl, uint32_t replLen) {
    if (off + replLen > len) return false;
    for (uint32_t i = 0; i < replLen; i++)
        dst[off + i] = repl[i];
    for (uint32_t i = 0; i < replLen; i++)
        if (dst[off + i] != repl[i]) return false;
    return true;
}

/* 判断某页是否已是补丁后形态：能力 getter 的 call 槽位已被 mov eax,1 覆盖 */
static bool btlfx_page_is_patched(uint8_t *base, size_t size) {
    /* 补丁后骨架：48 8B 08 48 89 C7 B8 01 00 00 00 90 41 89 C6 88 05 */
    static const uint8_t kPatchedSkel[] =
    {
        0x48, 0x8B, 0x08, 0x48, 0x89, 0xC7,
        0xB8, 0x01, 0x00, 0x00, 0x00, 0x90,
        0x41, 0x89, 0xC6,
        0x88, 0x05
    };
    static const uint8_t kPatchedMsk[] =
    {
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF,
        0xFF, 0xFF
    };
    uint8_t *cand[BTLFX_MAX_CAND];
    return btlfx_collect(base, size, kPatchedSkel, kPatchedMsk, sizeof(kPatchedSkel), cand, BTLFX_MAX_CAND) > 0;
}

/* 能力 getter 结构配对。
 *
 * 教训：一开始只用"同页内 flag 差 0x10 + 代码相邻 < 0x400"做配对，在 26.7.2 上
 * 把 33 个能力 getter 的**每一个相邻对**都配上了 —— 0x40d000/0x40f000/0x410000/
 * 0x411000/0x413000 五页各被误改 2 处，一共 10 处误伤。
 * 所以现在必须先精确定位 supportsExtendedScanning，再用它推旁边那个。
 *
 * 判据：extended-scanning 的 vtable 槽位在 26.4.1 (25E253) 与 26.7.2 (25G332)
 * 实测都是 +0x9a8，是这类里最稳的一个常量；supportsAdvertisingSets 的槽位
 * 却是 0x9c0 -> 0x918，变了。因此用固定槽位锚定 extscan，再取"flag 恰为其 +0x10
 * 且代码在它之后 < 0x400"的那个候选作为 advsets。
 *
 * 页内没有 vtable==0x9a8 的候选 -> 这一页与 advsets 无关，直接跳过（绝不猜）。
 * 若将来 Apple 又动了这个槽位，后果是补丁不生效（AirDrop 不可用），
 * 而不是改错能力 —— 后者会破坏系统蓝牙，代价高得多。
 */
#define BTLFX_EXTSCAN_VTABLE 0x9a8

/* supportsBT5AdvertisingSets（日志里叫 "BT Spec advertisingsets"）的 vtable 槽位。
 *
 * 26.4.1 (25E253) 上 0x9c0 是 supportsExtendedAdvertisingSets，作者原 pattern 因此
 * 在 26.7.2 上"歪打正着"命中这里；但 26.7.2 把 extended advsets 挪到 0x918，
 * 0x9c0 留给 BT 5.0 advertising sets。
 *
 * 这一位关掉时 bluetoothd 只发一个 legacy advertising set，解析不了 iPhone 用
 * 扩展广播集发出来的 AirDrop 载荷 —— 表现是单向可见（iPhone 看得到 Mac，
 * Mac 看不到 iPhone）。实测 0x9c0 在 26.7.2 全文件唯一。
 */
#define BTLFX_BTSPEC_VTABLE  0x9c0

static bool btlfx_pair_caps(uint8_t *base, size_t size,
                            uint8_t **extscanAddr, uint8_t **advsetsAddr,
                            int32_t *extscanVt, int32_t *advsetsVt) {
    uint8_t *cand[BTLFX_MAX_CAND];
    uint32_t n = btlfx_collect(base, size, kCapSkel, kCapMask, kCapLen, cand, BTLFX_MAX_CAND);
    if (n < 2 || n > BTLFX_MAX_CAND) return false;

    btlfx_cap_hit hits[BTLFX_MAX_CAND];
    for (uint32_t i = 0; i < n; i++) {
        hits[i].addr   = cand[i];
        hits[i].vtable = btlfx_rd32(cand[i] + 8);
        hits[i].flag   = (intptr_t)cand[i] + kCapSkelLen + btlfx_rd32(cand[i] + kCapRelOff);
    }
    /* 按代码地址升序（btlfx_collect 已顺序收集，这里保险再插排一次） */
    for (uint32_t i = 1; i < n; i++) {
        btlfx_cap_hit k = hits[i];
        int32_t j = (int32_t)i - 1;
        while (j >= 0 && hits[j].addr > k.addr) { hits[j + 1] = hits[j]; j--; }
        hits[j + 1] = k;
    }

    /* 1) 锚定 extended scanning：vtable 槽位精确等于 0x9a8，且页内唯一 */
    int32_t anchor = -1;
    for (uint32_t i = 0; i < n; i++) {
        if (hits[i].vtable != BTLFX_EXTSCAN_VTABLE) continue;
        if (anchor >= 0) return false;          /* 出现两个，说明锚点不可信 */
        anchor = (int32_t)i;
    }
    if (anchor < 0) return false;

    /* 2) 找它后面那个相邻能力：flag 恰好多 0x10，代码相距 < 0x400 */
    for (uint32_t i = 0; i < n; i++) {
        if ((int32_t)i == anchor) continue;
        ptrdiff_t dcode = (uint8_t *)hits[i].addr - (uint8_t *)hits[anchor].addr;
        intptr_t dflag  = hits[i].flag - hits[anchor].flag;
        if (dflag != 0x10 || dcode <= 0 || dcode >= 0x400) continue;
        if (hits[i].vtable <= 0 || (hits[i].vtable & 7) || hits[i].vtable >= 0x1000) continue;
        if (hits[i].vtable == hits[anchor].vtable) continue;

        *extscanAddr = hits[anchor].addr;
        *advsetsAddr = hits[i].addr;
        *extscanVt   = hits[anchor].vtable;
        *advsetsVt   = hits[i].vtable;
        return true;
    }
    return false;
}

/* 对单页应用补丁。返回上述结果码，*applied 为本页实际生效的站点数。
 * enableRpa=false 时只跑原来 7 个核心站点（-btlfxrpaoff，用于 A/B 对照）。 */
static int btlfx_advsets_patch_page(uint8_t *base, size_t size, int *applied, const char **failed, bool enableRpa) {
    *applied = 0;
    *failed = nullptr;

    bool anySiteHere = false;
    bool anyApplied  = false;

    /* 先探测两个代码注入组；任何一组状态异常就整页放弃，一字节都不写。
     * 这一步必须排在核心站点写入之前，否则「hook 已写、helper 没写」就收不回来了。 */
    btlfx_group_plan rpaPlan {}, falPlan {};
    if (enableRpa) {
        btlfx_probe_group(base, size, kRpaGroup, 2, &rpaPlan);
        btlfx_probe_group(base, size, kFalGroup, 3, &falPlan);
        if (rpaPlan.status == BTLFX_GRP_ERROR) { *failed = rpaPlan.failed; return rpaPlan.rc; }
        if (falPlan.status == BTLFX_GRP_ERROR) { *failed = falPlan.failed; return falPlan.rc; }
    }

    /* 1) 代码注入组先提交：排在核心站点之前，这样即使本页同时有别的站点，
     * 组提交失败时也不会留下任何半写入。两个组分别落在 0x227000 / 0x235000 两页。 */
    if (enableRpa) {
        const btlfx_code_site *groups[2] = { kRpaGroup, kFalGroup };
        const btlfx_group_plan *plans[2] = { &rpaPlan, &falPlan };
        const uint32_t counts[2] = { 2, 3 };
        for (uint32_t g = 0; g < 2; g++) {
            if (plans[g]->status == BTLFX_GRP_DONE) anySiteHere = true;
            int n = 0;
            const char *gf = nullptr;
            int grc = btlfx_commit_group(groups[g], counts[g], plans[g], &n, &gf);
            if (grc == BTLFX_ADV_OK) {
                anySiteHere = true;
                anyApplied = true;
                (*applied) += n;
            } else if (grc != BTLFX_ADV_DONE) {
                *failed = gf;
                return grc;
            }
        }
    }

    /* 2) 能力 getter 配对（extscan + advsets，同页） */
    uint8_t *extAddr = nullptr, *advAddr = nullptr;
    int32_t extVt = 0, advVt = 0;
    if (btlfx_pair_caps(base, size, &extAddr, &advAddr, &extVt, &advVt)) {
        anySiteHere = true;
        if (!btlfx_write_verify(extAddr, kCapLen, 6, kCapRepl, sizeof(kCapRepl))) {
            *failed = "extscan-cap";
            return BTLFX_ADV_VERIFY;
        }
        if (!btlfx_write_verify(advAddr, kCapLen, 6, kCapRepl, sizeof(kCapRepl))) {
            *failed = "advsets-cap";
            return BTLFX_ADV_VERIFY;
        }
        (*applied) += 2;
        anyApplied = true;
    } else if (btlfx_page_is_patched(base, size)) {
        /* 本页两个能力 getter 已是补丁后形态：applied 只统计本次真实写入 */
        anySiteHere = true;
    }

    /* 3) BT 5.0 advertising sets 能力（日志串 "BT chip support for BT Spec advertisingsets"）。
     *
     * 它和上面那对相邻能力不在同一页，所以单独做一轮。判据是 vtable 槽位 == 0x9c0
     * 且本页恰好一个候选；多于一个说明 Apple 重排了虚表，宁可放弃也不猜。
     * 这一轮在 pair 写完之后扫描，0x40c000 页的骨架此时已变成 mov eax,1，
     * 不会被再认成候选，因此不会重复计入。
     */
    {
        uint8_t *cand[BTLFX_MAX_CAND];
        uint32_t n = btlfx_collect(base, size, kCapSkel, kCapMask, kCapLen, cand, BTLFX_MAX_CAND);
        int32_t only = -1;
        uint32_t cnt = 0;
        for (uint32_t i = 0; i < n; i++) {
            if (btlfx_rd32(cand[i] + 8) != BTLFX_BTSPEC_VTABLE) continue;
            only = (int32_t)i;
            cnt++;
        }
        if (cnt == 1) {
            anySiteHere = true;
            if (!btlfx_write_verify(cand[only], kCapLen, 6, kCapRepl, sizeof(kCapRepl))) {
                *failed = "btspec-advsets-cap";
                return BTLFX_ADV_VERIFY;
            }
            (*applied)++;
            anyApplied = true;
        } else if (cnt > 1) {
            anySiteHere = true;
            *failed = "btspec-advsets-cap";
            return BTLFX_ADV_AMBIG;
        }
    }

    /* 4) 四个唯一站点：页内必须恰好一处命中，否则整页放弃 */
    for (uint32_t s = 2; s < kAdvSetsSiteCount; s++) {
        const btlfx_site &site = kAdvSetsSites[s];
        uint8_t *cand[BTLFX_MAX_CAND];
        uint32_t n = btlfx_collect(base, size, site.pat, site.msk, site.len, cand, BTLFX_MAX_CAND);
        if (n == 0) continue;               /* 该站点不在此页 */

        anySiteHere = true;
        if (n > 1) {
            *failed = site.name;
            return BTLFX_ADV_AMBIG;
        }
        if (!btlfx_write_verify(cand[0], site.len, site.patch_off, site.repl, site.repl_len)) {
            *failed = site.name;
            return BTLFX_ADV_VERIFY;
        }
        (*applied)++;
        anyApplied = true;
    }

    if (!anySiteHere) return BTLFX_ADV_SKIP;
    return anyApplied ? BTLFX_ADV_OK : BTLFX_ADV_DONE;
}

static inline const char *btlfx_advsets_errname(int rc) {
    switch (rc) {
        case BTLFX_ADV_OK:       return "ok";
        case BTLFX_ADV_SKIP:     return "skip";
        case BTLFX_ADV_DONE:     return "already";
        case BTLFX_ADV_NOTFOUND: return "not found";
        case BTLFX_ADV_AMBIG:    return "ambiguous";
        case BTLFX_ADV_SHAPE:    return "shape mismatch";
        case BTLFX_ADV_VERIFY:   return "verify failed";
        default:                 return "unknown";
    }
}
