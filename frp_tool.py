#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
frp_tool.py — FNE 通用提权包（.frp）构建 / 校验 / 查看 / 解包工具

.frp 是一个 ZIP 容器（格式详见 docs/包格式规范.md），目录结构：

    <包名>.frp
    ├── manifest.json          包元数据 + 文件清单 + 执行契约（必需）
    ├── payload/               全部运行时物料（10 项，必需）
    │   ├── e                  exploit 二进制（aarch64 ELF）
    │   ├── fne_local.sh       主流程脚本
    │   ├── chain_hook.sh      KernelSU late-load 链钩子
    │   ├── fne_syms.txt       kallsyms 符号表（明文）
    │   ├── kernelsu.ko        KernelSU 模块（vermagic 必须匹配）
    │   ├── ksud / magiskpolicy / load_ko / kmsg_dumper / ksu_rules
    ├── offsets/
    │   └── offsets.json       5.4 系偏移需求表（必需）
    └── README.md              包内自述（可选）

命令：
    python3 frp_tool.py build   <素材目录> <输出.frp> [--id ID] [--name NAME]
    python3 frp_tool.py verify  <包.frp> [--json]
    python3 frp_tool.py inspect <包.frp>
    python3 frp_tool.py extract <包.frp> <目标目录>

设计原则：**只能整包导入**。校验器与 App 内的 Frp.verify 是同一份规则，
任一项失败即整体拒绝，不落盘、不提供「单换 e / 单换 sh」的入口。

威胁模型：包未做数字签名，manifest 可被改写。校验的目的是**防误配 / 防损坏 /
防散件导入**（例如只换 e 不换 sh），不防「攻击者同时改 manifest 与 payload 并让
二者自洽」。若要防篡改，需在包外对 .frp 做签名校验，见 docs/包格式规范.md §9。
"""

import argparse
import copy
import hashlib
import json
import os
import re
import shutil
import struct
import subprocess
import sys
import tempfile
import zipfile

FORMAT = "fne-rootpkg"
FORMAT_VERSION = 1
KERNEL_SERIES = "5.4"
WORKDIR = "/data/local/tmp/ksu_fne"   # e 二进制硬编码，不可改
E_PATH = WORKDIR + "/e"

# ---- 内置规则（第三轮：不再从包内 manifest/offsets.json 读取校验基准）----
# 早期版本把「必备字段清单」「符号表行数期望」「offsets_ref」「entry_script」
# 都从包内自述读取，攻击者只要同时改包内规则与物料，就能让校验器
# 「自己出题自己判卷」全部放行。这些基准属于格式规范，必须内置在代码里。
OFFSETS_REF = "offsets/offsets.json"       # 固定路径，不认包内指定
ENTRY_SCRIPT = "fne_local.sh"              # 释放/搬运/执行命令都写死这个名字
MIN_KALLSYMS_LINES = 200000                # 5.4 系 kallsyms 规模硬下限
# 5.4 系偏移需求表的 75 个必备字段（权威来源 offsets_5.4.json 的 field_dictionary）
OFFSET_FIELDS = (
    "kernel_phys_load", "kimage_text_base", "off_init_task", "off_init_cred",
    "off_init_uts_ns", "off_empty_zero_page", "off_root_task_group",
    "off_selinux_enforcing", "off_sig_enforce", "off_kptr_restrict",
    "off_selinux_blob_sizes", "off_security_hook_heads", "off_kmalloc_caches",
    "off_anon_pipe_buf_ops", "off_ashmem_misc_fops", "off_ashmem_fops",
    "off_ashmem_ioctl", "off_ashmem_compat_ioctl", "off_ashmem_mmap",
    "off_ashmem_open", "off_ashmem_release", "off_ashmem_show_fdinfo",
    "off_configfs_read_iter", "off_configfs_bin_write_iter",
    "off_copy_splice_read", "off_noop_llseek", "off_cap_capable_active",
    "off_slide_nfulnl_logger", "off_slide_loggers_0_1", "off_slide_boot_id",
    "off_system_unbound_wq", "off_call_usermodehelper_exec_work",
    "task_prio", "task_normal_prio", "task_sched_task_group", "task_pi_lock",
    "task_pi_waiters", "task_pi_top_task", "task_pi_blocked_on", "task_pid",
    "task_tgid", "task_real_parent", "task_atomic_flags", "task_real_cred",
    "task_cred", "task_comm", "task_tasks", "task_seccomp", "mm_owner",
    "task_usage", "waiter_compact", "fops_llseek", "fops_read", "fops_write",
    "fops_read_iter", "fops_write_iter", "fops_ioctl", "fops_compat_ioctl",
    "fops_mmap", "fops_open", "fops_release", "fops_splice_read",
    "fops_show_fdinfo", "cfg_page_off", "cfg_needs_read_fill_off",
    "cfg_bin_buffer_off", "cfg_bin_buffer_size_off", "cfg_cb_max_size_off",
    "cred_uid_off", "cred_securebits_off", "cred_caps_off", "cred_security_off",
    "fops_no_iter", "mcast_route", "dm_va_absolute",
)
assert len(OFFSET_FIELDS) == 75 and len(set(OFFSET_FIELDS)) == 75

# ---- 资源上限（第四轮）：两端逐字一致，防 zip bomb / 超大条目把 App 打 OOM ----
# 官方示范包实测：13 条目、最大单条目 11,095,147 B、总解压 25,024,800 B、
# 压缩后 8.8 MB、manifest 4716 B；下列阈值均留有充分余量。
MAX_PKG_SIZE = 64 * 1024 * 1024
MAX_ENTRIES = 64
MAX_ENTRY_SIZE = 16 * 1024 * 1024
MAX_TOTAL_SIZE = 48 * 1024 * 1024
MAX_MANIFEST_SIZE = 64 * 1024
# 第五轮：offsets/offsets.json 是包内第二份独立 JSON，必须与 manifest 一样过词法预检
# （官方 11 内核表 52,213 B，给 4 MB 余量；同时受 MAX_ENTRY_SIZE 16 MB 兜底）
MAX_OFFSETS_SIZE = 4 * 1024 * 1024
MAX_JSON_DEPTH = 64
MAX_SCRIPT_SIZE = 2 * 1024 * 1024
# JSON 整数偏移值的上界：与 org.json 一致（Integer/Long，最大 Long.MAX）。
# 第五轮 G6：旧值 0xFFFFFFFFFFFFFFFF 让 PC 放行 2^64-1，而 App 端 org.json 把
# > Long.MAX 的字面量解析成 Double、parseNumOk 拒绝 —— 同一个包 PC ACCEPT / App REJECT。
INT_MAX = 0x7FFFFFFFFFFFFFFF

# 必需物料：role -> (payload 内默认文件名, 释放到 workdir 的目标名, 权限, 说明)
REQUIRED = {
    "exploit":       ("e",             "e",             "0755", "提权利用二进制，aarch64 ELF；内部硬编码 /data/local/tmp/ksu_fne"),
    "entry_script":  ("fne_local.sh",  "fne_local.sh",  "0755", "主流程脚本，W1/W2 与门控"),
    "chain_hook":    ("chain_hook.sh", "chain_hook.sh", "0755", "root child 拉起的 KernelSU late-load 链"),
    "kallsyms":      ("fne_syms.txt",  "fne_syms.txt",  "0644", "内核符号表明文，207919 行量级"),
    "kernelsu_ko":   ("kernelsu.ko",   "kernelsu.ko",   "0644", "KernelSU 模块，vermagic 必须与内核逐字一致"),
    "ksud":          ("ksud",          "ksud",          "0755", "KernelSU userspace daemon"),
    "magiskpolicy":  ("magiskpolicy",  "magiskpolicy",  "0755", "SELinux 策略修补"),
    "load_ko":       ("load_ko",       "load_ko",       "0755", "ko 装载辅助"),
    "kmsg_dumper":   ("kmsg_dumper",   "kmsg_dumper",   "0755", "内核日志抓取"),
    "ksu_rules":     ("ksu_rules",     "ksu_rules",     "0644", "KSU 规则文件"),
}


def sha256(b):
    return hashlib.sha256(b).hexdigest()


def read_zip(zf, name):
    if not isinstance(name, str):
        return None
    try:
        info = zf.getinfo(name)
        # 解压前先挡尺寸：zf.read() 会把整个条目读进内存，伪造 size 的 zip bomb
        # 同样会在 read() 里被下方 manifest_guard 之外的限制拦住（见 verify 条目检查）
        if info.file_size < 0 or info.file_size > MAX_ENTRY_SIZE:
            return None
        return zf.read(name)
    except (KeyError, ValueError, TypeError, RuntimeError,
            zipfile.BadZipFile, OSError):
        # CRC 不一致时 Python 抛 BadZipFile；必须收敛成「读不到 -> REJECT」，
        # 不能让工具直接崩（第四轮 E1）
        return None


def real_entry_len(zf, info):
    """按 deflate 流读【真实】解压字节数，不受 ZIP 头声明的 file_size 截断。

    第五轮 H6：ZipEntry.getSize() / getinfo().file_size 都是「声明值」，可被伪造。
    Python zipfile 的 ZipExtFile 会按 _left(=声明 file_size) 提前停止读取，
    所以必须复制一份 ZipInfo 并把 file_size 放大，才能读到 deflate 流末尾拿到
    真实字节数。与 App 端 Frp.verifyContainer 的流式读 + CRC 逐条比对对齐。
    返回 (真实字节数, crc_ok)。
    """
    zi = copy.copy(info)
    zi.file_size = MAX_TOTAL_SIZE + 1     # 放大，解除 _left 截断
    real = 0
    crc_ok = True
    try:
        with zf.open(zi) as f:
            while True:
                c = f.read(65536)
                if not c:
                    break
                real += len(c)
                if real > MAX_ENTRY_SIZE:
                    break
    except (zipfile.BadZipFile, OSError, RuntimeError, EOFError, ValueError):
        # CRC 不符 / deflate 损坏：Python zipfile 会在读取末尾抛 BadZipFile
        crc_ok = False
    return real, crc_ok


def vprint(ok, msg, errors):
    print(("  [OK]   " if ok else "  [FAIL] ") + msg)
    if not ok:
        errors.append(msg)
    return ok


def safe_name(name):
    """zip-slip 防护：拒绝非字符串、绝对路径、..、盘符、反斜杠。"""
    if not isinstance(name, str) or not name:
        return False
    if name.startswith(("/", "\\")) or ".." in name.split("/"):
        return False
    if re.match(r"^[A-Za-z]:", name):
        return False
    if "\\" in name:
        return False
    return True


def parse_num(v):
    """与 App 端 Frp.parseNumOk 逐字对齐的偏移值判定。

    旧实现用 Python 的 int(s, 0)，会放行 0b101 / 0o17 / 1_000 / +0x10 /
    -0x10 以及 400 位巨数，而 Java 端 BigInteger 全部拒绝 —— 同一个包
    PC ACCEPT / App REJECT（第四轮 E5）。现统一为**只接受非负、无前导 +、
    无下划线、长度受限**的十进制或 0x 十六进制；bool/null/对象一律拒绝。
    """
    if isinstance(v, bool) or v is None:
        return None
    if isinstance(v, int):
        # 第五轮：上界收到 Long.MAX，与 App 端 org.json 的 Integer/Long 逐字对齐。
        # 官方 825 个偏移值全是 0x 十六进制字符串，字符串分支不受此限。
        return v if 0 <= v <= INT_MAX else None
    if isinstance(v, str):
        s = v.strip()
        while s and s[-1] in "UuLl":
            s = s[:-1]
        if re.fullmatch(r"0[xX][0-9a-fA-F]{1,16}", s):
            return int(s[2:], 16)
        if re.fullmatch(r"[0-9]{1,20}", s):
            return int(s, 10)
        return None
    return None


def json_guard(raw, max_size):
    """通用 JSON 词法预检，与 App 端 Frp.jsonGuard 逐条对齐。

    第五轮：manifest.json 与 offsets/offsets.json 共用。前四轮只把它用在
    manifest.json 上，offsets.json 直接 json.loads(off_raw.decode())，于是
    「BOM / 重复键 / 非法 UTF-8」在两端出现 PC 拒 / App 放行（G1/G2/G3）。
    在把字节交给各自 JSON 解析器之前，先用**确定性词法扫描**统一处理：
    BOM / 非法 UTF-8 / 体积 / 括号嵌套深度 / 同一对象内重复键 /
    非标准裸字面量 NaN/Infinity（Python json 允许、org.json 不允许）。
    第六轮：升级为严格 RFC 8259 状态机，字符串内管转义与控制字符、
    字符串外管数字/裸标识符/结构位置，杜绝 App 端 org.json 方言。
    返回 (ok, reason)。
    """
    if raw[:3] == b"\xef\xbb\xbf":
        return False, "含 UTF-8 BOM"
    if len(raw) > max_size:
        return False, "超过 %d B" % max_size
    try:
        s = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        return False, "不是合法 UTF-8"
    # 第六轮：严格 RFC 8259 词法裁决（与 App 端 Frp.jsonGuard 逐条对齐）。
    # 此前只查 BOM / UTF-8 / 体积 / 深度 / 重复键 / 大写 NaN+Infinity，把
    # 「什么算合法 JSON」的最终裁决权交给了两个方言差异极大的解析器：
    #   PC  json.loads 严格；App org.json 宽松（+1/01/0x1 -> 数值，
    #   nan/inf/None -> 字符串，True -> Boolean，非法转义被吞掉反斜杠）。
    # 现在在把字节交给解析器之前用确定性状态机统一裁决：
    #   字符串内：转义白名单、u 转义严格 4 位 hex、拒绝裸控制字符；
    #   字符串外：数字必须匹配 RFC 8259、裸标识符只允许小写 true/false/null、
    #             结构字符位置由状态机判定、其它字符一律拒绝。
    WS = " " + chr(9) + chr(10) + chr(13)
    HEX = "0123456789abcdefABCDEF"
    ESC = {"b": chr(8), "f": chr(12), "n": chr(10), "r": chr(13),
           "t": chr(9), "/": "/", '"': '"', chr(92): chr(92)}
    NUM_RE = re.compile(r"-?(?:0|[1-9][0-9]*)(?:[.][0-9]+)?(?:[eE][+-]?[0-9]+)?")
    # 期待状态：VAL=值或容器可结束 / VAL_REQ=必须有值 / KEY=键或 } /
    #           KEY_REQ=必须有键 / COLON / DELIM=逗号或容器结束
    VAL, VAL_REQ, KEY, KEY_REQ, COLON, DELIM = range(6)
    stack = []            # 对象用 set()，数组用 None
    expect = VAL_REQ      # 根节点必须有一个值
    depth = 0
    i, n = 0, len(s)

    def skip_ws(j):
        while j < n and s[j] in WS:
            j += 1
        return j

    while i < n:
        c = s[i]
        if c in WS:
            i += 1
            continue

        # ---- 字符串（键或值）----
        if c == '"':
            if expect not in (VAL, VAL_REQ, KEY, KEY_REQ):
                return False, "字符串位置非法 @%d" % i
            is_key = expect in (KEY, KEY_REQ)
            i += 1
            buf = []
            closed = False
            while i < n:
                ch = s[i]
                if ch == '"':
                    i += 1
                    closed = True
                    break
                if ord(ch) < 0x20:
                    return False, "字符串内裸控制字符 0x%02X @%d" % (ord(ch), i)
                if ch == chr(92):
                    i += 1
                    if i >= n:
                        return False, "转义不完整"
                    e = s[i]
                    if e == "u":
                        h = s[i + 1:i + 5]
                        if len(h) != 4 or any(x not in HEX for x in h):
                            return False, "u 转义必须是 4 位十六进制"
                        buf.append(chr(int(h, 16)))
                        i += 5
                        continue
                    if e not in ESC:
                        return False, "非法转义 (反斜杠 + %s)" % e
                    buf.append(ESC[e])
                    i += 1
                    continue
                buf.append(ch)
                i += 1
            if not closed:
                return False, "字符串未闭合"
            if is_key:
                j = skip_ws(i)
                if j >= n or s[j] != ":":
                    return False, "对象键后缺少冒号"
                if not stack or stack[-1] is None:
                    return False, "键出现在数组上下文"
                key = "".join(buf)
                if key in stack[-1]:
                    return False, "JSON 重复键 %r" % key
                stack[-1].add(key)
                expect = COLON
            else:
                expect = DELIM
            continue

        # ---- 容器与分隔符 ----
        if c == "{":
            if expect not in (VAL, VAL_REQ):
                return False, "对象位置非法 @%d" % i
            stack.append(set())
            depth += 1
            if depth > MAX_JSON_DEPTH:
                return False, "嵌套深度 > %d" % MAX_JSON_DEPTH
            expect = KEY
            i += 1
            continue
        if c == "[":
            if expect not in (VAL, VAL_REQ):
                return False, "数组位置非法 @%d" % i
            stack.append(None)
            depth += 1
            if depth > MAX_JSON_DEPTH:
                return False, "嵌套深度 > %d" % MAX_JSON_DEPTH
            expect = VAL
            i += 1
            continue
        if c == "}":
            if expect not in (KEY, DELIM) or not stack or stack[-1] is None:
                return False, "对象结束位置非法 @%d" % i
            depth -= 1
            stack.pop()
            expect = DELIM
            i += 1
            continue
        if c == "]":
            if expect not in (VAL, DELIM) or not stack or stack[-1] is not None:
                return False, "数组结束位置非法 @%d" % i
            depth -= 1
            stack.pop()
            expect = DELIM
            i += 1
            continue
        if c == ":":
            if expect != COLON:
                return False, "冒号位置非法 @%d" % i
            expect = VAL_REQ
            i += 1
            continue
        if c == ",":
            if expect != DELIM or not stack:
                return False, "逗号位置非法 @%d" % i
            expect = KEY_REQ if stack[-1] is not None else VAL_REQ
            i += 1
            continue

        # ---- 数字：严格 RFC 8259 ----
        if c == "-" or c in "0123456789":
            if expect not in (VAL, VAL_REQ):
                return False, "数字位置非法 @%d" % i
            m = NUM_RE.match(s, i)
            if not m:
                return False, "非法数字字面量 @%d" % i
            end = m.end()
            if end < n and s[end] not in WS + ",}]":
                return False, "非法数字字面量（尾部粘连）@%d" % i
            i = end
            expect = DELIM
            continue

        # ---- 裸标识符：只允许精确小写 true / false / null ----
        if c in "tfn":
            if expect not in (VAL, VAL_REQ):
                return False, "字面量位置非法 @%d" % i
            lit = None
            for cand in ("true", "false", "null"):
                if s.startswith(cand, i):
                    lit = cand
                    break
            if lit is None:
                return False, "非标准裸字面量 @%d: %r" % (i, s[i:i + 12])
            end = i + len(lit)
            if end < n and s[end] not in WS + ",}]":
                return False, "非标准裸字面量（尾部粘连）@%d" % i
            i = end
            expect = DELIM
            continue

        return False, "字符串外非法字符 0x%02X @%d" % (ord(c), i)

    if depth != 0 or stack or expect != DELIM:
        return False, "JSON 结构不完整 / 括号不配对"
    return True, "词法预检通过"


def safe_text(v):
    """自由文本字段：非空、<=256 字符、无控制字符（防日志注入 / UI 伪造，P06）。"""
    if not isinstance(v, str) or not v or len(v) > 256:
        return False
    return all(ord(c) >= 0x20 and ord(c) != 0x7f for c in v)


# --------------------------------------------------------------------------
# verify
# --------------------------------------------------------------------------

def verify(pkg, as_json=False):
    errors = []
    report = {"package": os.path.basename(pkg) if isinstance(pkg, str) else "",
              "checks": [], "ok": False}

    def chk(cond, msg):
        cond = bool(cond)
        report["checks"].append({"ok": cond, "msg": msg})
        if as_json:
            if not cond:
                errors.append(msg)
        else:
            vprint(cond, msg, errors)
        return cond

    def finish():
        ok = not errors
        report["ok"] = ok
        report["error_count"] = len(errors)
        if as_json:
            print(json.dumps(report, ensure_ascii=False, indent=2))
        else:
            print("\n结论: %s（%d 项不通过）" %
                  ("完整包校验通过 ✔" if ok else "拒绝导入 ✘", len(errors)))
        return ok

    if not isinstance(pkg, str) or not os.path.isfile(pkg):
        chk(False, "包文件不存在: %s" % pkg)
        return finish()
    report["size"] = os.path.getsize(pkg)
    chk(report["size"] <= MAX_PKG_SIZE,
        "包文件 <= %d B（实际 %d B）" % (MAX_PKG_SIZE, report["size"]))

    try:
        zf = zipfile.ZipFile(pkg)
    except Exception as e:
        chk(False, "不是合法 ZIP: %s" % e)
        return finish()

    all_names = zf.namelist()
    # 第四轮 E6：目录条目（以 / 结尾）也必须参与「无未声明条目」检查。
    # 旧实现把 / 结尾条目从 names 里剔除，导致「名字是目录但带内容」的条目
    # 可以夹带任意数据而两端都不报。
    names = list(all_names)
    chk(all(safe_name(n) for n in all_names),
        "ZIP 条目路径安全（无 zip-slip / 绝对路径）")
    chk(len(all_names) == len(set(all_names)),
        "ZIP 内无重复条目名（%d 条 / %d 唯一）" % (len(all_names), len(set(all_names))))
    chk(len(all_names) <= MAX_ENTRIES,
        "ZIP 条目数 <= %d（实际 %d）" % (MAX_ENTRIES, len(all_names)))
    sizes = []
    for n in all_names:
        try:
            sizes.append(max(zf.getinfo(n).file_size, 0))
        except Exception:
            sizes.append(MAX_ENTRY_SIZE + 1)
    chk(all(s <= MAX_ENTRY_SIZE for s in sizes),
        "每个条目解压尺寸 <= %d B（最大 %d B）" % (MAX_ENTRY_SIZE, max(sizes) if sizes else 0))
    chk(sum(sizes) <= MAX_TOTAL_SIZE,
        "总解压尺寸 <= %d B（实际 %d B）" % (MAX_TOTAL_SIZE, sum(sizes)))
    try:
        crc_ok = zf.testzip() is None
    except Exception:
        crc_ok = False
    chk(crc_ok, "ZIP CRC 完整")

    # 第五轮 · 容器层：所有条目的【真实】解压字节数必须 == ZIP 头声明 size。
    # testzip() 只按声明 size 读并校验 CRC；若攻击者把声明 size 伪造成小值、
    # 同时把 CRC 重算成「声明的那点字节」的 CRC，testzip 会自洽通过，而 App 端
    # install 会按 deflate 流落盘全部真实数据（H6：声明 100、真实 6MB）。
    # 这里逐条读真实字节数与声明比对，与 App 端 Frp.verifyContainer 逐字对齐。
    real_ok = True
    real_total = 0
    for n in all_names:
        try:
            info = zf.getinfo(n)
            real, c_ok = real_entry_len(zf, info)
            real_total += real
            if not c_ok or real != max(info.file_size, 0) or real > MAX_ENTRY_SIZE:
                real_ok = False
        except Exception:
            real_ok = False
    chk(real_ok, "容器层：真实解压字节数 == ZIP 头声明 size（防声明伪造 zip bomb）")
    chk(real_total <= MAX_TOTAL_SIZE,
        "容器层：真实解压总量 <= %d B（实际 %d B）" % (MAX_TOTAL_SIZE, real_total))

    raw = read_zip(zf, "manifest.json")
    if not chk(raw is not None, "manifest.json 存在"):
        return finish()
    g_ok, g_why = json_guard(raw, MAX_MANIFEST_SIZE)
    if not chk(g_ok, "manifest 词法预检：%s" % g_why):
        return finish()
    try:
        m = json.loads(raw.decode("utf-8"))
        if not isinstance(m, dict):
            raise ValueError("根节点不是对象")
    except Exception as e:
        chk(False, "manifest.json 合法 JSON (%s)" % e)
        return finish()
    chk(True, "manifest.json 合法 JSON")

    chk(m.get("format") == FORMAT, "format == %s" % FORMAT)
    fv = m.get("format_version")
    chk(isinstance(fv, int) and not isinstance(fv, bool) and fv == FORMAT_VERSION,
        "format_version == %d（必须是 JSON 整数）" % FORMAT_VERSION)
    chk(m.get("kernel_series") == KERNEL_SERIES,
        "kernel_series == %s（当前 %r）" % (KERNEL_SERIES, m.get("kernel_series")))

    pk = m.get("package")
    pk = pk if isinstance(pk, dict) else {}
    # 第六轮：id / name / ko_vermagic 必须是单行纯文本 JSON 字符串。
    # 旧实现 bool(pk.get("id")) 对数字 123 / 对象 {} 都返回 True（L01/L02），
    # 含换行 + 伪造 [OK] 行的 id 还能注入界面日志（P06）。
    chk(safe_text(pk.get("id")),
        "package.id 是单行纯文本且 <= 256 字符（JSON 字符串）")
    chk(safe_text(pk.get("name")),
        "package.name 是单行纯文本且 <= 256 字符（JSON 字符串）")
    releases = pk.get("kernel_releases")
    releases = releases if isinstance(releases, list) else []
    chk(bool(releases) and all(isinstance(r, str) and r.startswith("5.4.")
                               for r in releases),
        "package.kernel_releases 非空且全为 5.4 系（%d 条）" % len(releases))
    chk(safe_text(pk.get("ko_vermagic")),
        "package.ko_vermagic 是单行纯文本且 <= 256 字符（JSON 字符串）")

    ex = m.get("execution")
    ex = ex if isinstance(ex, dict) else {}
    chk(ex.get("workdir") == WORKDIR,
        "execution.workdir == %s（e 硬编码路径）" % WORKDIR)
    chk(ex.get("e_path") == E_PATH, "execution.e_path == %s" % E_PATH)
    chk(ex.get("entry_script") == ENTRY_SCRIPT,
        "execution.entry_script == %s（释放/搬运/执行命令写死此名）" % ENTRY_SCRIPT)
    env = ex.get("env")
    env = env if isinstance(env, dict) else {}
    chk("DM_PAGE_OFFSET" in env,
        "execution.env 含 DM_PAGE_OFFSET（5.4 系 __va 绝对映射）")
    chk(str(env.get("DM_PAGE_OFFSET", "")).startswith("0xffffff8"),
        "DM_PAGE_OFFSET 形如 0xffffff8000000000")

    # offsets 表（第三轮：路径固定、字段清单内置、值必须可解析、releases 全覆盖）
    off_ref = m.get("offsets_ref")
    chk(off_ref == OFFSETS_REF,
        "offsets_ref == %s（固定路径，当前 %r）" % (OFFSETS_REF, off_ref))
    off_raw = read_zip(zf, OFFSETS_REF)
    # 第五轮：offsets.json 是包内第二份独立 JSON，必须与 manifest 一样过词法预检，
    # 否则 BOM / 重复键 / 非法 UTF-8 会在两端出现 PC 拒 / App 放行（G1/G2/G3）
    og_ok, og_why = json_guard(off_raw, MAX_OFFSETS_SIZE) if off_raw is not None \
        else (False, "offsets.json 不存在 / CRC 错误")
    chk(og_ok, "offsets.json 词法预检：%s" % og_why)
    if chk(off_raw is not None and og_ok, "offsets/%s 存在且预检通过" % OFFSETS_REF.split("/")[-1]):
        try:
            off = json.loads(off_raw.decode("utf-8"))
            kernels = off.get("kernels") or []
            chk(bool(kernels), "offsets.json 含内核条目（%d 条）" % len(kernels))
            chk(all(isinstance(k, dict) and str(k.get("uname_r", "")).startswith("5.4.")
                    for k in kernels),
                "offsets.json 所有条目均为 5.4 系")
            # 5.4 系偏移「需求表」允许覆盖多个内核（官方表就有 11 条），
            # 但 package.kernel_releases 声明的每个内核都必须在表里有条目
            #（全覆盖，而非旧版的「至少一个」），且表内 uname_r 不得重复。
            unames = [k.get("uname_r") for k in kernels if isinstance(k, dict)]
            chk(len(unames) == len(set(unames)),
                "offsets.json uname_r 无重复（%d 条）" % len(unames))
            chk(all(r in unames for r in releases),
                "offsets.json 全覆盖 kernel_releases（%d 个内核）" % len(releases))
            # 字段清单内置（OFFSET_FIELDS），不认包内 field_dictionary 的 required 开关；
            # 且每个字段值必须是可解析的数字，不能是 null / 非数字字符串
            miss = sum(1 for k in kernels for f in OFFSET_FIELDS
                       if not isinstance(k, dict)
                       or parse_num((k.get("offsets") or {}).get(f)) is None)
            chk(miss == 0, "每条内核覆盖内置 %d 字段且值可解析（缺/非法 %d 项）"
                % (len(OFFSET_FIELDS), miss))
        except Exception as e:
            chk(False, "offsets.json 合法 JSON (%s)" % e)

    # 文件清单（严格类型检查 + 每个 role 恰好 1 项 + 无夹带条目）
    files = m.get("files")
    if not isinstance(files, list):
        chk(False, "files[] 是数组")
        return finish()
    chk(len(files) == len(REQUIRED),
        "files[] 恰好 %d 项（实际 %d）" % (len(REQUIRED), len(files)))
    by_role = {}
    declared = set()
    dests = set()
    paths = set()
    for idx, f in enumerate(files):
        if not isinstance(f, dict):
            chk(False, "  files[%d] 是对象" % idx)
            continue
        role = f.get("role")
        if isinstance(role, str) and role:
            by_role.setdefault(role, []).append(f)
        p = f.get("path", "")
        if not isinstance(p, str):
            p = ""
        declared.add(p)
        dest = f.get("dest") if isinstance(f.get("dest"), str) else ""

        # 角色 ↔ 目标名 ↔ 权限 ↔ path 全绑定，杜绝物料错位 / 相互覆盖 / 夹带
        spec = REQUIRED.get(role) if isinstance(role, str) else None
        chk(spec is not None, "  files[%d].role 在 10 项白名单内 (%r)" % (idx, role))
        if spec:
            chk(dest == spec[1], "  role=%s 的 dest 必须为 %s" % (role, spec[1]))
            chk(f.get("mode") == spec[2], "  role=%s 的 mode 必须为 %s" % (role, spec[2]))
            chk(p == "payload/" + spec[1],
                "  role=%s 的 path 必须为 payload/%s" % (role, spec[1]))
        chk(bool(dest) and safe_name(dest), "  %-34s dest 合法" % p)
        dup_dest, dup_path = dest in dests, p in paths
        dests.add(dest); paths.add(p)
        chk(not dup_dest, "  files[%d].dest 唯一 (%r)" % (idx, dest))
        chk(not dup_path, "  files[%d].path 唯一 (%r)" % (idx, p))

        if not chk(safe_name(p), "  files[%d].path 安全 (%r)" % (idx, p)):
            continue
        b = read_zip(zf, p)
        if not chk(b is not None, "  %-34s 条目存在" % p):
            continue
        sv = f.get("size")
        chk(isinstance(sv, int) and not isinstance(sv, bool) and sv == len(b),
            "  %-34s size 一致 / 为 JSON 整数 (%d)" % (p, len(b)))
        chk(sha256(b) == f.get("sha256"), "  %-34s sha256 一致" % p)
        chk(re.fullmatch(r"0[0-7]{3}", str(f.get("mode", ""))) is not None,
            "  %-34s mode 格式合法 (%s)" % (p, f.get("mode")))

    for role in REQUIRED:
        n = len(by_role.get(role, []))
        chk(n == 1, "必需物料 role=%-13s 有且仅有 1 项（实际 %d）" % (role, n))

    # 未声明条目：包内不得夹带清单外的文件（完整包语义）
    # 白名单固定为内置路径，不再把包内自述的 offsets_ref 加进来
    allowed = {"manifest.json", "README.md", OFFSETS_REF}
    undeclared = sorted(n for n in names if n not in declared and n not in allowed)
    chk(not undeclared, "无未声明条目（%d 项）%s" %
        (len(undeclared), (" -> " + ", ".join(undeclared[:3])) if undeclared else ""))

    # 交叉校验（物料之间的配套关系：这才是「必须整包」的核心）
    def blob(role):
        fs = by_role.get(role) or []
        return read_zip(zf, fs[0].get("path", "")) if fs and isinstance(fs[0], dict) else None

    e = blob("exploit")
    if e:
        ok = len(e) > 64 and e[:4] == b"\x7fELF" and \
             struct.unpack_from("<H", e, 18)[0] == 0xB7
        chk(ok, "e 为 aarch64 ELF（EM_AARCH64=0xB7）")
        declared_size = ex.get("e_size")
        chk(isinstance(declared_size, int) and not isinstance(declared_size, bool)
            and declared_size == len(e),
            "execution.e_size 与 e 实际尺寸一致 (%d B，必须是 JSON 整数)" % len(e))
    else:
        chk(False, "e 可读")

    ko = blob("kernelsu_ko") or b""
    mv = re.search(rb"vermagic=([^\s\x00]+)", ko)
    got = mv.group(1).decode("ascii", "ignore") if mv else ""
    chk(got == str(pk.get("ko_vermagic", "")),
        "kernelsu.ko vermagic 与 package.ko_vermagic 一致 (%s)" % (got or "未找到"))

    assertions = ex.get("assertions")
    assertions = assertions if isinstance(assertions, dict) else {}
    syms = blob("kallsyms") or b""
    lines = syms.count(b"\n")
    # 内置硬下限恒成立：包内 assertions.kallsyms_lines 只能用于「一致性」，
    # 不能把期望值自述成 1 行就放行（第三轮 A4）
    chk(lines >= MIN_KALLSYMS_LINES,
        "fne_syms.txt 行数 >= 内置下限 %d（实际 %d）" % (MIN_KALLSYMS_LINES, lines))
    dl = assertions.get("kallsyms_lines")
    if "kallsyms_lines" in assertions:
        chk(isinstance(dl, int) and not isinstance(dl, bool) and dl == lines,
            "assertions.kallsyms_lines 与实际行数一致 (%r / %d)" % (dl, lines))

    sh = blob("entry_script") or b""
    chk(sh.startswith(b"#!"), "fne_local.sh 有 shebang")
    chain = blob("chain_hook") or b""
    chk(chain.startswith(b"#!"), "chain_hook.sh 有 shebang")

    # 物料互相绑定：只换物料再让 build 重算 size/sha256（manifest 自洽）不算配套，
    # 设备端会被 sh 里的尺寸 / workdir / 内核门控断言挡下
    e_len = len(e or b"")
    chk(e_len > 0 and str(e_len).encode() in sh,
        "fne_local.sh 含 e 尺寸断言 %d B（换 e 不改 sh 应拒绝）" % e_len)
    if "e_size_in_entry_script" in assertions:
        v = assertions["e_size_in_entry_script"]
        chk(isinstance(v, int) and not isinstance(v, bool) and v == e_len,
            "assertions.e_size_in_entry_script 与 e 尺寸一致")
    chk(WORKDIR.encode() in sh and WORKDIR.encode() in chain,
        "两个 sh 的 workdir 与 execution.workdir 一致")
    vm = str(pk.get("ko_vermagic", ""))
    chk(bool(vm) and vm.encode() in sh and vm.encode() in chain,
        "两个 sh 的内核门控与 ko vermagic 一致 (%s)" % vm)
    for key, label in (("ko_vermagic_in_entry_script", "入口脚本"),
                       ("kernel_release_gate_in_chain_hook", "chain 门控")):
        if key in assertions:
            chk(assertions[key] == vm, "assertions.%s 与 ko vermagic 一致（%s）" % (key, label))

    # sh 语法检查：两端都用真正的 sh -n，脚本从 stdin 喂入（零临时文件、零执行）。
    # 与 App 端 Frp.shSyntaxOk 用同一个系统 sh 判定；不用静态括号/关键字配平，
    # 因为官方 sh 里 case 模式 / 注释 / 跨行引号本就不配平，启发式会误伤合法脚本。
    # 没有可用 sh 时 fail-closed（拒绝），不静默放行。
    for role, label in (("entry_script", "fne_local.sh"), ("chain_hook", "chain_hook.sh")):
        b = blob(role)
        if not b:
            chk(False, "%s 通过 sh -n 语法检查（物料缺失）" % label)
            continue
        if len(b) > MAX_SCRIPT_SIZE:
            chk(False, "%s 通过 sh -n 语法检查（超过 %d B 上限）"
                % (label, MAX_SCRIPT_SIZE))
            continue
        try:
            r = subprocess.run(["sh", "-n"], input=b, capture_output=True,
                               timeout=10)
            chk(r.returncode == 0, "%s 通过 sh -n 语法检查" % label)
        except subprocess.TimeoutExpired:
            chk(False, "%s 通过 sh -n 语法检查（超时，fail-closed）" % label)
        except (FileNotFoundError, OSError) as e:
            chk(False, "%s 通过 sh -n 语法检查（sh 不可用: %s）" % (label, e))

    return finish()


# --------------------------------------------------------------------------
# build
# --------------------------------------------------------------------------

def build(src, out, pkg_id=None, pkg_name=None):
    src = os.path.abspath(src)
    payload = os.path.join(src, "payload")
    offdir = os.path.join(src, "offsets")
    if not os.path.isdir(payload):
        sys.exit("素材目录缺少 payload/: " + src)

    meta_path = os.path.join(src, "manifest.template.json")
    meta = json.load(open(meta_path, encoding="utf-8")) if os.path.isfile(meta_path) else {}
    if not isinstance(meta, dict):
        meta = {}
    pkg_meta = meta.get("package")
    pkg_meta = dict(pkg_meta) if isinstance(pkg_meta, dict) else {}
    exec_meta = meta.get("execution")
    exec_meta = dict(exec_meta) if isinstance(exec_meta, dict) else {}

    files = []
    for role, (fname, dest, mode, desc) in REQUIRED.items():
        p = os.path.join(payload, fname)
        if not os.path.isfile(p):
            sys.exit("缺少必需物料 payload/%s (role=%s)" % (fname, role))
        b = open(p, "rb").read()
        files.append({
            "path": "payload/" + fname,
            "dest": dest,
            "role": role,
            "size": len(b),
            "sha256": sha256(b),
            "mode": mode,
            "desc": desc,
        })

    ko = open(os.path.join(payload, "kernelsu.ko"), "rb").read()
    mv = re.search(rb"vermagic=([^\s\x00]+)", ko)
    ko_vermagic = mv.group(1).decode("ascii", "ignore") if mv else ""
    e_size = os.path.getsize(os.path.join(payload, "e"))
    syms_lines = open(os.path.join(payload, "fne_syms.txt"), "rb").read().count(b"\n")

    m = {
        "format": FORMAT,
        "format_version": FORMAT_VERSION,
        "kernel_series": KERNEL_SERIES,
        "package": pkg_meta,
        "execution": exec_meta,
        "files": files,
        "offsets_ref": "offsets/offsets.json",
    }
    # CLI 显式传值必须覆盖模板，不能用 setdefault（否则 --id/--name 永远无效）
    if pkg_id:
        m["package"]["id"] = pkg_id
    else:
        m["package"].setdefault("id", "fne-5.4-custom")
    if pkg_name:
        m["package"]["name"] = pkg_name
    else:
        m["package"].setdefault("name", "FNE 5.4 系通用提权包")
    # 这几项由物料实际内容 / 硬编码路径决定，必须覆盖模板，避免模板写错还自洽通过
    m["package"]["ko_vermagic"] = ko_vermagic
    m["package"].setdefault("kernel_releases", [ko_vermagic] if ko_vermagic else [])
    m["package"].setdefault("built", "")
    m["execution"]["workdir"] = WORKDIR
    m["execution"]["e_path"] = E_PATH
    m["execution"]["entry_script"] = ENTRY_SCRIPT
    m["execution"]["e_size"] = e_size
    # assertions 必须从「实际物料」重算并覆盖模板，不能 setdefault 沿用旧模板值。
    # 否则把符号表换成 1 行 + 模板里 kallsyms_lines=1，就能产出自洽但设备端必挂的包（C4）。
    m["execution"]["assertions"] = {
        "kallsyms_lines": syms_lines,
        "e_size_in_entry_script": e_size,
        "ko_vermagic_in_entry_script": ko_vermagic,
        "kernel_release_gate_in_chain_hook": ko_vermagic,
    }
    m["execution"].setdefault("hardcoded_paths", [
        "e 二进制硬编码 /data/local/tmp/ksu_fne",
        "chain_hook.sh 的 D=/data/local/tmp/ksu_fne",
        "fne_local.sh 的 E/D/LOG 均指向该目录",
    ])
    m["execution"].setdefault("env", {
        "GL_AIM_DM": "1",
        "DM_PAGE_OFFSET": "0xffffff8000000000",
        "GL_W1_ATTEMPTS": "2",
        "GL_ROUTE_ATTEMPTS": "1",
        "GL_HOLD_CHAIN": "1",
        "GL_HOLD_WAITER": "1",
        "GL_PUNCH_IN_WINDOW": "1",
        "GL_MCAST_ROUTE": "1",
        "GL_W2_ROUNDS": "1",
    })

    if not os.path.isfile(os.path.join(offdir, "offsets.json")):
        sys.exit("素材目录缺少 offsets/offsets.json")

    tmp = tempfile.mkdtemp(prefix="frpbuild-")
    try:
        with open(os.path.join(tmp, "manifest.json"), "w", encoding="utf-8") as f:
            json.dump(m, f, ensure_ascii=False, indent=2)
        os.makedirs(os.path.join(tmp, "payload"))
        os.makedirs(os.path.join(tmp, "offsets"))
        # 只打包清单声明的物料，杜绝素材目录里的临时/备份文件被夹带进包
        for f in files:
            shutil.copy2(os.path.join(payload, os.path.basename(f["path"])),
                         os.path.join(tmp, f["path"]))
        shutil.copy2(os.path.join(offdir, "offsets.json"),
                     os.path.join(tmp, "offsets", "offsets.json"))
        if os.path.isfile(os.path.join(src, "README.md")):
            shutil.copy2(os.path.join(src, "README.md"), os.path.join(tmp, "README.md"))

        os.makedirs(os.path.dirname(os.path.abspath(out)) or ".", exist_ok=True)
        with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED, compresslevel=6) as z:
            for root, _, fns in os.walk(tmp):
                for fn in sorted(fns):
                    full = os.path.join(root, fn)
                    z.write(full, os.path.relpath(full, tmp).replace(os.sep, "/"))
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    print("已生成: %s (%d B)" % (out, os.path.getsize(out)))
    print("自动校验：")
    return 0 if verify(out) else 1


# --------------------------------------------------------------------------
# inspect / extract
# --------------------------------------------------------------------------

def inspect(pkg):
    """查看包摘要；畸形/缺字段的包给出友好错误，不抛 traceback（第三轮 C1）。"""
    try:
        zf = zipfile.ZipFile(pkg)
        m = json.loads(zf.read("manifest.json").decode("utf-8"))
        if not isinstance(m, dict):
            raise ValueError("manifest 根节点不是对象")
        pk = m.get("package") if isinstance(m.get("package"), dict) else {}
        ex = m.get("execution") if isinstance(m.get("execution"), dict) else {}
        files = m.get("files") if isinstance(m.get("files"), list) else []
        print("包文件   : %s (%d B)" % (os.path.basename(pkg), os.path.getsize(pkg)))
        print("格式     : %s v%s / %s 系" % (m.get("format", "?"),
              m.get("format_version", "?"), m.get("kernel_series", "?")))
        print("ID       : %s" % pk.get("id", "-"))
        print("名称     : %s" % pk.get("name", "-"))
        rels = pk.get("kernel_releases") or []
        print("内核     : %s" % ", ".join(str(r) for r in rels))
        print("vermagic : %s" % pk.get("ko_vermagic", "-"))
        print("工作目录 : %s" % ex.get("workdir", "-"))
        print("e 尺寸   : %s B" % ex.get("e_size", "-"))
        try:
            off = json.loads(zf.read(m["offsets_ref"]).decode("utf-8"))
            print("偏移条目 : %d 条 5.4 内核" % len(off.get("kernels", [])))
        except Exception:
            pass
        print("\n物料清单 (%d 项):" % len(files))
        for f in files:
            if not isinstance(f, dict):
                print("  <非法条目>")
                continue
            print("  %-13s %-24s %9s B  %s  -> %s" %
                  (f.get("role", "?"), f.get("path", "?"), f.get("size", "?"),
                   f.get("mode", "?"), f.get("dest", "?")))
        print("\n备注: 只能整包导入；e 与 sh 内的尺寸/vermagic/路径断言互相绑定。")
        print("提示: inspect 只做摘要展示，包是否可导入以 verify 为准。")
    except SystemExit:
        raise
    except Exception as e:
        print("无法查看包摘要: %s: %s" % (type(e).__name__, e), file=sys.stderr)
        print("请用 verify 获取完整校验结果；畸形 manifest 不会导致工具崩溃。")
        sys.exit(1)


def extract(pkg, dest):
    if not verify(pkg):
        sys.exit("校验未通过，拒绝解包")
    dest = os.path.abspath(dest)
    # 第三轮 C2：目标目录里若预置了符号链接（如 payload -> /tmp/xxx），
    # 直接 open(target,'wb') 会跟随链接把物料写出 dest 之外。
    # 解包前先拒绝 dest 子树内任何符号链接，并要求每个解析后的目标仍在 dest 内。
    for root, dirs, fns in os.walk(dest):
        for d in dirs:
            p = os.path.join(root, d)
            if os.path.islink(p):
                sys.exit("拒绝解包：目标目录含符号链接 %s（防 zip-slip 逃逸）" % p)
        for fn in fns:
            p = os.path.join(root, fn)
            if os.path.islink(p):
                sys.exit("拒绝解包：目标目录含符号链接 %s（防 zip-slip 逃逸）" % p)
    os.makedirs(dest, exist_ok=True)
    with zipfile.ZipFile(pkg) as z:
        for n in z.namelist():
            if not safe_name(n):
                continue
            target = os.path.join(dest, n)
            # realpath 必须仍在 dest 之内（覆盖「目录不存在但父级是链接」等情形）
            real = os.path.realpath(target)
            if os.path.commonpath([os.path.realpath(dest), real]) != os.path.realpath(dest):
                sys.exit("拒绝解包：条目 %s 解析后越出目标目录" % n)
            par = os.path.dirname(target)
            if par:
                os.makedirs(par, exist_ok=True)
                if os.path.islink(par):
                    sys.exit("拒绝解包：父目录 %s 是符号链接" % par)
            if not n.endswith("/"):
                with open(target, "wb") as f:
                    f.write(z.read(n))
    print("已解包到: " + dest)


def main():
    ap = argparse.ArgumentParser(description="FNE 通用提权包(.frp)工具")
    sub = ap.add_subparsers(dest="cmd", required=True)
    b = sub.add_parser("build", help="从素材目录构建 .frp")
    b.add_argument("src"); b.add_argument("out")
    b.add_argument("--id"); b.add_argument("--name")
    v = sub.add_parser("verify", help="整包校验")
    v.add_argument("pkg"); v.add_argument("--json", action="store_true")
    i = sub.add_parser("inspect", help="查看包摘要")
    i.add_argument("pkg")
    e = sub.add_parser("extract", help="校验通过后解包")
    e.add_argument("pkg"); e.add_argument("dest")
    a = ap.parse_args()
    if a.cmd == "build":
        sys.exit(build(a.src, a.out, a.id, a.name))
    elif a.cmd == "verify":
        sys.exit(0 if verify(a.pkg, a.json) else 1)
    elif a.cmd == "inspect":
        inspect(a.pkg)
    else:
        extract(a.pkg, a.dest)


if __name__ == "__main__":
    main()
