#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
parse_offsets.py — 从 GhostLock main 库的官方 C 头文件生成 5.4 系偏移需求表 JSON。

来源（只读，不修改）：
  main/root/exploit/src/devices/fne/offsets.h     289 + 9 个 295 CDN + 实机精确条目
  main/root/exploit/src/devices/offsets.h         STRUCT_OFFSETS_5_4 宏与字段语义

输出 offsets_5.4.json，供 .frp 包的 offsets/ 目录使用。
所有数值都是「预重定位 VA - kimage_text_base」，必须在目标内核上逐条复核；
错一个数据偏移会静默破坏无关内核内存（见 offsets.h 原始注释）。
"""

import json
import os
import re
import sys

BASE_DEFAULT = ("/root/.codebuddy/artifact/2f8a7d30-9c21-4f0b-1d67-b55eb80b4000/"
                "ghostlock/GhostLock-HonorFne-main/root/exploit/src")

# 字段字典：字段 -> (分类, 含义, 采集方式, 是否必需)
DICT = [
    ("kernel_phys_load", "平台常量", "内核镜像物理装载地址，bootloader 决定；从 /proc/iomem 的 Kernel code 减去 (_stext-_text)", "root 同型号机读取", True),
    ("kimage_text_base", "平台常量", "内核 _text 虚拟基址，本 FNE 5.4 系固定 0xffffffc010080000", "kallsyms _text", True),
    ("off_init_task", "内核符号", "init_task 相对 _text 偏移，用于定位 task_struct 链", "kallsyms VA - _text", True),
    ("off_init_cred", "内核符号", "init_cred，提权时复制的 root cred 模板", "kallsyms VA - _text", True),
    ("off_init_uts_ns", "内核符号", "init_uts_ns", "kallsyms VA - _text", True),
    ("off_empty_zero_page", "内核符号", "empty_zero_page", "kallsyms VA - _text", True),
    ("off_root_task_group", "内核符号", "root_task_group", "kallsyms VA - _text", True),
    ("off_selinux_enforcing", "内核符号", "selinux_state.enforcing（= selinux_state + 1），W1 写入目标", "selinux_state +1", True),
    ("off_sig_enforce", "内核符号", "module.c 的 static bool sig_enforce，W1b 清零目标；占 8 字节对齐槽", "kallsyms VA - _text", True),
    ("off_kptr_restrict", "内核符号", "kptr_restrict", "kallsyms VA - _text", True),
    ("off_selinux_blob_sizes", "内核符号", "selinux_blob_sizes（LSM blob 尺寸）", "kallsyms VA - _text", True),
    ("off_security_hook_heads", "内核符号", "security_hook_heads", "kallsyms VA - _text", True),
    ("off_kmalloc_caches", "内核符号", "kmalloc_caches，堆喷布局依赖", "kallsyms VA - _text", True),
    ("off_anon_pipe_buf_ops", "内核符号", "anon_pipe_buf_ops", "kallsyms VA - _text", True),
    ("off_ashmem_misc_fops", "内核符号", "ashmem_misc.fops", "kallsyms VA - _text", True),
    ("off_ashmem_fops", "内核符号", "ashmem_fops（被重定向的函数表）", "kallsyms VA - _text", True),
    ("off_ashmem_ioctl", "内核符号", "ashmem_ioctl 函数地址", "kallsyms VA - _text", True),
    ("off_ashmem_compat_ioctl", "内核符号", "ashmem_compat_ioctl（5.4 上同 ioctl）", "取 off_ashmem_ioctl", True),
    ("off_ashmem_mmap", "内核符号", "ashmem_mmap", "kallsyms VA - _text", True),
    ("off_ashmem_open", "内核符号", "ashmem_open", "kallsyms VA - _text", True),
    ("off_ashmem_release", "内核符号", "ashmem_release", "kallsyms VA - _text", True),
    ("off_ashmem_show_fdinfo", "内核符号", "ashmem_show_fdinfo", "kallsyms VA - _text", True),
    ("off_configfs_read_iter", "内核符号", "configfs_read_file / read_iter 槽", "kallsyms VA - _text", True),
    ("off_configfs_bin_write_iter", "内核符号", "configfs_write_bin_file 槽", "kallsyms VA - _text", True),
    ("off_copy_splice_read", "内核符号", "5.4 无 copy_splice_read，取 default_file_splice_read", "kallsyms VA - _text", True),
    ("off_noop_llseek", "内核符号", "noop_llseek", "kallsyms VA - _text", True),
    ("off_cap_capable_active", "内核符号", "cap_capable 门控；FNE 5.4 为 0（无门）", "反汇编确认", True),
    ("off_slide_nfulnl_logger", "内核符号", "slide 探针：nfulnl_logger", "kallsyms VA - _text", True),
    ("off_slide_loggers_0_1", "内核符号", "slide 探针：loggers + 0x10", "kallsyms + 0x10", True),
    ("off_slide_boot_id", "内核符号", "sysctl boot_id 数据缓冲，位于 .bss（Image 之外）", "sysctl 表项 +0x18 指针", True),
    ("off_system_unbound_wq", "内核符号", "system_unbound_wq，UMH root 路径", "kallsyms VA - _text", True),
    ("off_call_usermodehelper_exec_work", "内核符号", "call_usermodehelper_exec_work，UMH root 路径", "kallsyms VA - _text", True),
    ("task_prio", "结构体 5.4", "task_struct.prio 偏移（STRUCT_OFFSETS_5_4）", "结构体反汇编", True),
    ("task_normal_prio", "结构体 5.4", "task_struct.normal_prio", "结构体反汇编", True),
    ("task_sched_task_group", "结构体 5.4", "task_struct.sched_task_group", "结构体反汇编", True),
    ("task_pi_lock", "结构体 5.4", "task_struct.pi_lock（futex PI UAF 关键）", "结构体反汇编", True),
    ("task_pi_waiters", "结构体 5.4", "task_struct.pi_waiters", "结构体反汇编", True),
    ("task_pi_top_task", "结构体 5.4", "task_struct.pi_top_task", "结构体反汇编", True),
    ("task_pi_blocked_on", "结构体 5.4", "task_struct.pi_blocked_on", "结构体反汇编", True),
    ("task_pid", "结构体 5.4", "task_struct.pid", "结构体反汇编", True),
    ("task_tgid", "结构体 5.4", "task_struct.tgid", "结构体反汇编", True),
    ("task_real_parent", "结构体 5.4", "task_struct.real_parent", "结构体反汇编", True),
    ("task_atomic_flags", "结构体 5.4", "task_struct.atomic_flags", "结构体反汇编", True),
    ("task_real_cred", "结构体 5.4", "task_struct.real_cred（cred 写入目标）", "结构体反汇编", True),
    ("task_cred", "结构体 5.4", "task_struct.cred（cred_off=0x880 在 W2 日志里出现）", "结构体反汇编", True),
    ("task_comm", "结构体 5.4", "task_struct.comm", "结构体反汇编", True),
    ("task_tasks", "结构体 5.4", "task_struct.tasks 链表", "结构体反汇编", True),
    ("task_seccomp", "结构体 5.4", "task_struct.seccomp", "结构体反汇编", True),
    ("mm_owner", "结构体 5.4", "mm_struct.owner", "结构体反汇编", True),
    ("task_usage", "结构体 5.4", "task_struct.usage 引用计数", "结构体反汇编", True),
    ("waiter_compact", "结构体 5.4", "rt_mutex_waiter 紧凑布局标志", "反汇编确认", True),
    ("fops_llseek", "file_operations 5.4", "file_operations.llseek", "结构体反汇编", True),
    ("fops_read", "file_operations 5.4", "file_operations.read", "结构体反汇编", True),
    ("fops_write", "file_operations 5.4", "file_operations.write", "结构体反汇编", True),
    ("fops_read_iter", "file_operations 5.4", "file_operations.read_iter", "结构体反汇编", True),
    ("fops_write_iter", "file_operations 5.4", "file_operations.write_iter", "结构体反汇编", True),
    ("fops_ioctl", "file_operations 5.4", "file_operations.unlocked_ioctl", "结构体反汇编", True),
    ("fops_compat_ioctl", "file_operations 5.4", "file_operations.compat_ioctl", "结构体反汇编", True),
    ("fops_mmap", "file_operations 5.4", "file_operations.mmap", "结构体反汇编", True),
    ("fops_open", "file_operations 5.4", "file_operations.open", "结构体反汇编", True),
    ("fops_release", "file_operations 5.4", "file_operations.release", "结构体反汇编", True),
    ("fops_splice_read", "file_operations 5.4", "file_operations.splice_read", "结构体反汇编", True),
    ("fops_show_fdinfo", "file_operations 5.4", "file_operations.show_fdinfo", "结构体反汇编", True),
    ("cfg_page_off", "configfs_buffer 5.4", "configfs_buffer.page", "configfs 反汇编", True),
    ("cfg_needs_read_fill_off", "configfs_buffer 5.4", "configfs_buffer.needs_read_fill", "configfs 反汇编", True),
    ("cfg_bin_buffer_off", "configfs_buffer 5.4", "configfs_bin_attribute 私有缓冲", "configfs 反汇编", True),
    ("cfg_bin_buffer_size_off", "configfs_buffer 5.4", "缓冲长度字段", "configfs 反汇编", True),
    ("cfg_cb_max_size_off", "configfs_buffer 5.4", "cb_max_size", "configfs 反汇编", True),
    ("cred_uid_off", "struct cred 5.4", "cred.uid（W2 改写目标）", "结构体反汇编", True),
    ("cred_securebits_off", "struct cred 5.4", "cred.securebits", "结构体反汇编", True),
    ("cred_caps_off", "struct cred 5.4", "cred.cap_* 能力集", "结构体反汇编", True),
    ("cred_security_off", "struct cred 5.4", "cred.security", "结构体反汇编", True),
    ("fops_no_iter", "布局开关", "1 = 5.4 的 configfs 消费者用普通 read/write 槽而非 iter 槽", "内核版本判定", True),
    ("mcast_route", "布局开关", "1 = 用 MCAST_JOIN_SOURCE_GROUP 作为 waiter 栈载体（5.4 不能走 select）", "内核版本判定", True),
    ("dm_va_absolute", "布局开关", "1 = __va() 绝对映射（HONOR 5.4 家族），dm VA = PAGE_OFFSET + phys", "page_frag_free 反汇编", True),
]

# 运行时注入量（不在 offsets.h 内，但 5.4 系包必须提供）
RUNTIME = {
    "P0_PAGE_OFFSET": {"value": "0xffffff8000000000", "meaning": "线性映射区基址，脚本以 DM_PAGE_OFFSET 注入", "source": "target.h L9 / docs 实测"},
    "P0_PHYS_OFFSET": {"value": "0x80000000", "meaning": "物理地址基准（HONOR 家族 L=0xa8000000 时加此值）", "source": "target.h L10"},
    "P0_KERNEL_PHYS_LOAD": {"value": "0xa8000000", "meaning": "默认内核物理装载，FNE 实取 0x128000000", "source": "target.h L11"},
    "GL_MEMSTART": {"value": "运行时探测", "meaning": "memstart probe 结果，决定 slide；不可硬编码", "source": "e 的 memstart probe"},
    "GL_W2_ROUNDS": {"value": "1", "meaning": "W2 只跑 1 轮；root 到手后再次 PI 操作会踢到 ghost waiter 引发 panic", "source": "fne_local.sh"},
    "GL_SILENT_SEC": {"value": "5（可 15/60）", "meaning": "post-boot 纯静默，让内存回收、堆喷页布局稳定；不做采样", "source": "fne_local.sh settle()"},
}


def strip_comments(t):
    t = re.sub(r"/\*.*?\*/", " ", t, flags=re.S)
    t = re.sub(r"//[^\n]*", " ", t)
    return t


def load_macros(text):
    """返回 {宏名: 展开后的字段字符串}，处理反斜杠续行与嵌套宏引用。"""
    merged = re.sub(r"\\\s*\n", " ", text)
    raw = {}
    for m in re.finditer(r"^\s*#define\s+(\w+)\s+(.+?)\s*$", merged, re.M):
        raw[m.group(1)] = m.group(2).strip()

    def expand(name, seen=None):
        seen = seen or set()
        if name in seen or name not in raw:
            return ""
        seen = set(seen) | {name}
        s = raw[name]
        # 裸宏引用（STRUCT_OFFSETS_5_4 / FNE295_COMMON / FNE295_CLUSTER_x）
        def rep(mo):
            ref = mo.group(0)
            return expand(ref, seen) if ref in raw else ref
        s = re.sub(r"\b(?:STRUCT_OFFSETS_5_4|FNE295_COMMON|FNE295_CLUSTER_[A-D])\b", rep, s)
        return s

    return {k: expand(k) for k in raw}


def parse_fields(s):
    out = {}
    for m in re.finditer(r"\.([A-Za-z_]\w*)\s*=\s*([^,]+?)\s*(?=,|$)", s):
        name, val = m.group(1), m.group(2).strip()
        val = re.sub(r"ULL?$", "", val, flags=re.I).strip()
        try:
            n = int(val, 16) if val.lower().startswith("0x") else int(val, 0)
            out[name] = "0x%X" % n
        except ValueError:
            out[name] = val
    return out


def main():
    base = sys.argv[1] if len(sys.argv) > 1 else BASE_DEFAULT
    fne_h = os.path.join(base, "devices/fne/offsets.h")
    dev_h = os.path.join(base, "devices/offsets.h")
    fne_txt = strip_comments(open(fne_h, encoding="utf-8").read())
    dev_txt = strip_comments(open(dev_h, encoding="utf-8").read())
    macros = load_macros(fne_txt + "\n" + dev_txt)

    entries = []
    for m in re.finditer(r'OFFSETS_ENTRY\(\s*"([^"]+)"\s*,\s*(.*?)\)\s*,', fne_txt, re.S):
        uname, body = m.group(1), m.group(2)
        # 展开条目里出现的裸宏
        def rep(mo):
            ref = mo.group(0)
            return macros.get(ref, "")
        body = re.sub(r"\b(?:STRUCT_OFFSETS_5_4|FNE295_COMMON|FNE295_CLUSTER_[A-D])\b", rep, body)
        f = parse_fields(body)
        if not f:
            continue
        entries.append({"uname_r": uname, "offsets": f})

    # 附加可信度标注与布局簇（依据 offsets.h 原始注释）
    clusters = {
        "A": ["g6aea83b404da", "gc4635e0ca684", "ge32871827345"],
        "B": ["g0fe5dd3dbc93", "gc26f40498717", "g165910d83a3a"],
        "C": ["g58bd9508770a", "g5e68e68ac2e2"],
        "D": ["g351930777161"],
    }

    def cluster_of(u):
        for c, pats in clusters.items():
            if any(p in u for p in pats):
                return c
        return "independent"

    for e in entries:
        u = e["uname_r"]
        if u == "5.4.295-qgki-g0fb2656b2b50":
            e["status"] = "exact-live-unit"
            e["note"] = ("8.0.224 实机内核，从 v880302 full + v915183 增量重建，"
                         "独立于 4 个 CDN cluster；注释早期曾把它当作 cluster B 的推测值，"
                         "文件末尾已补精确条目，仍建议真机验证")
        elif u.startswith("5.4.289"):
            e["status"] = "extracted-from-kernel_880302.elf"
            e["note"] = "289 基线，结构体布局已对 configfs/pipe_write/__sched_setscheduler 反汇编校验"
        else:
            e["status"] = "cdn-full-derived"
            e["note"] = "9 个 CDN 完整 OTA 内核之一，按布局聚为 A/B/C/D 四簇；仅文本符号全簇相同"
        e["cluster"] = cluster_of(u)

    doc = {
        "series": "5.4",
        "scope": "仅 Linux 5.4 GKI（HONOR FNE 家族）。不覆盖 5.10 / 5.15 / 6.x："
                 "file_operations 布局（fop_flags / iterate_shared）、configfs_buffer、"
                 "task_struct PI 字段与 __va 语义均不同，套用会静默写坏内核内存。",
        "source": "GhostLock-HonorFne-main/root/exploit/src/devices/fne/offsets.h",
        "addressing": "所有 off_* 为 kallsyms 预重定位 VA 减去 kimage_text_base (0xffffffc010080000)；"
                      "e 在运行时加 kaslr_base 得到实际地址。",
        "struct_macro_5_4": parse_fields(macros.get("STRUCT_OFFSETS_5_4", "")),
        "field_dictionary": [
            {"name": n, "category": c, "meaning": m, "how_to_get": h, "required": r}
            for (n, c, m, h, r) in DICT
        ],
        "runtime_contract": RUNTIME,
        "kernels": entries,
        "warning": "偏移错误不会崩溃而是静默写到无关内核内存，极难定位。"
                   "换内核必须重跑 tools/kernel-offsets/extract_offsets.py 并在设备上验证。",
    }

    out = sys.argv[2] if len(sys.argv) > 2 else "/workspace/FNERoot_通用提权包/offsets_5.4.json"
    with open(out, "w", encoding="utf-8") as f:
        json.dump(doc, f, ensure_ascii=False, indent=2)
    print("生成 %s" % out)
    print("  内核条目: %d 条" % len(entries))
    for e in entries:
        print("    %-42s %-28s %d 字段" % (e["uname_r"], e["status"], len(e["offsets"])))
    if entries:
        missing = set(n for n, *_ in DICT) - set(entries[0]["offsets"])
        print("  字段字典 %d 项；首条未覆盖字段: %s" % (len(DICT), sorted(missing) or "无"))


if __name__ == "__main__":
    main()
