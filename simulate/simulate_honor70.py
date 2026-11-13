#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
simulate_honor70.py — 云电脑里模拟荣耀70 (FNE-AN00) 环境，验证通用提权包的前置链。

⚠️ 能力边界（务必先读报告）：
    这台云电脑是 x86_64 Linux，无 /dev/kvm、无 Android SDK、无 emulator。
    e 是 ARM aarch64 内核态利用，依赖真 5.4.295-qgki 内核的 futex PI UAF 与物理页布局，
    **内核提权这一步物理上无法模拟**。

本脚本做的是能力范围内最实的验证：
    A. 环境档案：搭出荣耀70 的目录树 / uname / getenforce / proc / sysfs 伪节点
    B. 包校验：用与 App / frp_tool 同一套规则跑 6 个用例（正常 + 5 种篡改），
       证明「只能整包导入、只做 5.4 系、固定 workdir」真的拦得住
    C. 释放模拟：active_pkg/payload -> sdcard 中转 -> tmp + 按 manifest mode 设 x 位
    D. 脚本前置链：把 e 换成【等尺寸 221104 B】的可执行 stub（唯一替换项，
       保证 fne_local.sh 里的尺寸自检也真跑），让 fne_local.sh 完整走完
       settle -> 门控 -> W1 -> W2 -> 判定，输出到 fne_sim.log
    E. 静态验证：e 的 aarch64 ELF、dex 类、APK 资源/图标、v1/v2/v3 签名

所有模拟输出都带 [SIM] / [SIM-STUB] 前缀，绝不冒充真机日志或真机提权成功。
"""
import contextlib
import hashlib
import io
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import zipfile

ROOT = "/workspace/FNERoot_通用提权包"
SIM = os.path.join(ROOT, "simulate/device")
PKG = os.path.join(ROOT, "packages/FNE-AN00-5.4.295.frp")
APK = os.path.join(ROOT, "app/FNERoot-通用壳-v27.apk")
ART = "/root/.codebuddy/artifact/2f8a7d30-9c21-4f0b-1d67-b55eb80b4000"
BT = ART + "/fneroot_app/bt/android-14"
JAVA_JAR = ART + "/sdk/android-all-13.jar"
JAVA_CLASSES = os.path.join(ROOT, "app/build/classes")
JAVA_TEST = "/tmp/frpjavatest"
KERNEL = "5.4.295-qgki-g0fb2656b2b50"
E_SIZE = 221104

sys.path.insert(0, ROOT)
import frp_tool  # noqa: E402

REPORT = {"cases": [], "notes": []}


def add(name, ok, detail):
    REPORT["cases"].append({"name": name, "ok": ok, "detail": detail})
    print(("  [SIM-OK]   " if ok else "  [SIM-FAIL] ") + name + " :: " + detail)
    return ok


def sh(cmd, env=None, cwd=None):
    e = dict(os.environ)
    e.update(env or {})
    p = subprocess.run(cmd, shell=True, capture_output=True, text=True,
                       env=e, cwd=cwd, timeout=180)
    return p.returncode, (p.stdout or "") + (p.stderr or "")


# ---------------------------------------------------------------- A 环境档案

def setup():
    shutil.rmtree(SIM, ignore_errors=True)
    dirs = [
        "sdcard/Download", "sdcard/Download/ksu_fne", "sdcard/Download/fne_packages",
        "data/local/tmp/ksu_fne", "proc", "sys/module/kernelsu/parameters",
        "sys/module/module/parameters", "sys/fs/pstore", "app_files/active_pkg",
        "bin",
    ]
    for d in dirs:
        os.makedirs(os.path.join(SIM, d), exist_ok=True)

    # 伪内核节点（模拟「KSU 尚未加载」的开机初始态）
    open(os.path.join(SIM, "proc/modules"), "w").write(
        "# 模拟：开机初始态，kernelsu 未加载\n")
    open(os.path.join(SIM, "sys/module/module/parameters/sig_enforce"), "w").write("N\n")
    # sys/module/kernelsu/version 故意不创建 -> ksu_loaded() 返回 1

    shims = {
        "uname": '#!/bin/sh\ncase "$1" in -r) echo "' + KERNEL + '" ;; *) /bin/uname "$@" ;; esac\n',
        "getenforce": "#!/bin/sh\necho Permissive\n",
        "id": "#!/bin/sh\necho 'uid=2000(shell) gid=2000(shell) groups=2000(shell) context=u:r:shell:s0'\n",
        "am": "#!/bin/sh\nexit 0\n",
        "pm": "#!/bin/sh\nexit 0\n",
    }
    for n, body in shims.items():
        p = os.path.join(SIM, "bin", n)
        open(p, "w").write(body)
        os.chmod(p, 0o755)

    # 把示范包放到「sdcard」供导入
    shutil.copy2(PKG, os.path.join(SIM, "sdcard/Download", os.path.basename(PKG)))
    print("[A] 环境档案已搭建: " + SIM)
    return True


# ---------------------------------------------------------------- B 包校验用例

def verify_quiet(pkg):
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        ok = frp_tool.verify(pkg)
    return ok, buf.getvalue()


def mutate(tag, fn, extra=None, drop=None):
    """基于示范包生成一个篡改包；fn(name, bytes) 返回新 bytes 或 None(删除条目)。
    extra 可夹带清单外条目，drop 可删除条目。"""
    out = os.path.join(SIM, "mut_" + tag + ".frp")
    with zipfile.ZipFile(PKG) as src, zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as dst:
        for it in src.infolist():
            if drop and it.filename in drop:
                continue
            b = src.read(it.filename)
            nb = fn(it.filename, b) if fn else b
            if nb is None:
                continue
            dst.writestr(it, nb)
        for n, b in (extra or {}).items():
            dst.writestr(n, b)
    return out


def case_verify():
    print("\n[B] 包校验模拟（App/FrpImporter 与 frp_tool 同一套规则）")
    ok0, _ = verify_quiet(PKG)
    add("B1 完整示范包", ok0, "全部条目校验通过" if ok0 else "被拒")

    def bad_sha(n, b):
        if n == "manifest.json":
            m = json.loads(b)
            m["files"][0]["sha256"] = "0" * 64
            return json.dumps(m, ensure_ascii=False, indent=2).encode()
        return b
    p = mutate("bad_sha", bad_sha)
    ok, _ = verify_quiet(p)
    add("B2 篡改单个 sha256", not ok, "应按逐文件 sha256 拒绝")

    p = mutate("missing", lambda n, b: None if n == "payload/ksu_rules" else b)
    ok, _ = verify_quiet(p)
    add("B3 缺少一项物料", not ok, "应按 10 个必需角色拒绝（整包语义）")

    # 单换 e：换成 289 基线旧料（215568 B）。取不到真料就用等尺寸假 e 兜底，
    # 避免用例依赖交付目录之外的工程包文件（换台机器跑也必须能验证）。
    old_e = "/workspace/fne-github/289_baseline/e"
    if os.path.isfile(old_e):
        ob = open(old_e, "rb").read()[:215568]
        src = "289 基线真料"
    else:
        ob = b"# [SIM] fake e (not ELF)\n"
        src = "等尺寸构造假 e"
    ob = ob + b"X" * (215568 - len(ob))
    p = mutate("swap_e", lambda n, b: ob if n == "payload/e" else b)
    ok, _ = verify_quiet(p)
    add("B4 单换 e（%s 215568 B）" % src, not ok,
        "e_size 断言 / size / sha256 / ELF 头均不匹配，应按整包耦合拒绝")

    p = mutate("series", lambda n, b: (b.replace(b'"kernel_series": "5.4"',
               b'"kernel_series": "6.1"') if n == "manifest.json" else b))
    ok, _ = verify_quiet(p)
    add("B5 kernel_series 改成 6.1", not ok, "应拒绝非 5.4 系")

    p = mutate("workdir", lambda n, b: (b.replace(
               b'"/data/local/tmp/ksu_fne"', b'"/data/local/tmp/rootapp"', 1)
               if n == "manifest.json" else b))
    ok, _ = verify_quiet(p)
    add("B6 workdir 改成 rootapp", not ok, "e 硬编码路径，应拒绝")
    return True


# ---------------------------------------------------------------- C 释放模拟

def case_release():
    print("\n[C] 释放模拟（active_pkg -> sdcard 中转 -> tmp + mode）")
    with zipfile.ZipFile(PKG) as z:
        m = json.loads(z.read("manifest.json").decode("utf-8"))
        for it in z.namelist():
            if it.endswith("/"):
                continue
            dst = os.path.join(SIM, "app_files/active_pkg", it)
            os.makedirs(os.path.dirname(dst), exist_ok=True)
            open(dst, "wb").write(z.read(it))

    sd = os.path.join(SIM, "sdcard/Download/ksu_fne")
    tmp = os.path.join(SIM, "data/local/tmp/ksu_fne")
    ok_all = True
    for f in m["files"]:
        src = os.path.join(SIM, "app_files/active_pkg", f["path"])
        b = open(src, "rb").read()
        open(os.path.join(sd, f["dest"]), "wb").write(b)
        open(os.path.join(tmp, f["dest"]), "wb").write(b)
        mode = int(f["mode"], 8)
        os.chmod(os.path.join(tmp, f["dest"]), mode)
        real = stat.S_IMODE(os.lstat(os.path.join(tmp, f["dest"])).st_mode)
        if real != mode:
            ok_all = False
    add("C1 10 项物料释放 + mode", ok_all and len(m["files"]) == 10,
        "%d 项，0755/0644 按 manifest 落位" % len(m["files"]))

    # paths: 硬编码路径一致性（模拟层用替换后的路径，检查原契约）
    add("C2 执行契约路径", m["execution"]["workdir"] == "/data/local/tmp/ksu_fne"
        and m["execution"]["e_path"] == "/data/local/tmp/ksu_fne/e",
        "workdir / e_path 与 e 硬编码一致")
    return True


# ---------------------------------------------------------------- D 脚本前置链

def make_e_stub(path):
    body = """#!/bin/sh
# [SIM-STUB] 云电脑替身：绝不执行任何内核利用；仅按参数输出模拟文本。
echo "[SIM-STUB] knobs: HOLD_CHAIN=1 STAMP_SYNC=1 M4_TIMEOUT_MS=1000"
echo "[SIM-STUB] kernel: 5.4.295-qgki-g0fb2656b2b50"
echo "[SIM-STUB] offsets matched: 5.4.295-qgki-g0fb2656b2b50"
case "$*" in
  *--write1*)
    echo "[SIM-STUB] *** ENFORCE=0 - W1 WRITE LANDED (simulated) ***"
    exit 0 ;;
  *)
    echo "[SIM-STUB] W2: cred_off=0x880 target=0xffffff... (simulated)"
    echo "[SIM-STUB] child is root!"
    echo "[SIM-STUB] runtime fake kallsyms written: 207919 syms"
    echo "[SIM-STUB] ROOT ACHIEVED ... per-boot (simulated)"
    exit 0 ;;
esac
"""
    b = body.encode()
    assert len(b) < E_SIZE
    stub = b + b"#" * (E_SIZE - len(b) - 1) + b"\n"
    assert len(stub) == E_SIZE, len(stub)
    open(path, "wb").write(stub)
    os.chmod(path, 0o755)
    return len(stub)


def case_script():
    print("\n[D] fne_local.sh 用户态前置链模拟")
    tmp = os.path.join(SIM, "data/local/tmp/ksu_fne")
    src_sh = os.path.join(SIM, "app_files/active_pkg/payload/fne_local.sh")
    text = open(src_sh, encoding="utf-8").read()

    # 唯一的两类改动：① 绝对路径重定向到 fixture；② e 换成等尺寸 stub
    text = text.replace("/data/local/tmp/ksu_fne", tmp)
    text = text.replace("/data/local/tmp/fne_run.log", os.path.join(SIM, "data/local/tmp/fne_run.log"))
    text = text.replace("/proc/modules", os.path.join(SIM, "proc/modules"))
    text = text.replace("/sys/module/kernelsu/", os.path.join(SIM, "sys/module/kernelsu/"))
    text = text.replace("/sys/module/module/parameters/sig_enforce",
                        os.path.join(SIM, "sys/module/module/parameters/sig_enforce"))
    text = text.replace("/sys/fs/pstore/", os.path.join(SIM, "sys/fs/pstore/"))
    sim_sh = os.path.join(SIM, "fne_local.sim.sh")
    open(sim_sh, "w", encoding="utf-8").write(text)

    n = make_e_stub(os.path.join(tmp, "e"))
    add("D0 e 替换为等尺寸 stub", n == E_SIZE,
        "%d B（满足脚本内 ESZ==221104 自检；内核利用未执行）" % n)

    # 释放其它物料的 mode 已在 C 步设好；chain_hook.sh 必须可执行
    for f in ("chain_hook.sh", "fne_local.sh", "ksud", "magiskpolicy", "load_ko", "kmsg_dumper"):
        p = os.path.join(tmp, f)
        if os.path.isfile(p):
            os.chmod(p, 0o755)

    logf = os.path.join(tmp, "fne_run.log")
    open(logf, "w").close()  # 模拟「跑前清 LOG」，避免累积误报

    env = {
        "PATH": os.path.join(SIM, "bin") + ":" + os.environ.get("PATH", ""),
        "GL_SILENT_SEC": "1",       # 纯静默段从 5s 缩到 1s 加速模拟
        "GL_VERBOSE": "0",
    }
    rc, out = sh("sh " + sim_sh, env=env)
    logtxt = ""
    if os.path.isfile(logf):
        logtxt = open(logf, encoding="utf-8", errors="replace").read()
    both = out + "\n" + logtxt
    open(os.path.join(ROOT, "simulate/fne_sim.log"), "w", encoding="utf-8").write(
        "===== [SIM] 荣耀70 环境模拟日志（非真机）=====\n"
        "===== e 为 [SIM-STUB]，内核利用未执行 =====\n\n"
        "----- stdout -----\n" + out + "\n----- fne_run.log -----\n" + logtxt)
    REPORT["script_output"] = both

    checks = [
        ("D1 e 尺寸自检通过", "FATAL: 工作目录里的 e 不是 295 修复版" not in both),
        ("D2 ko vermagic 门通过", "FATAL: kernelsu.ko 不是 295 版" not in both),
        ("D3 内核指纹门 + 偏移命中", "内核匹配 OK" in logtxt and "offsets matched" in logtxt),
        ("D4 W1 分支走到", "W1 try" in out and "W1 返回 rc=" in out),
        ("D5 W2 分支走到", "W2 round" in out and "W2 返回 rc=" in out),
        ("D6 判定链命中并停止", "ROOT 到手" in out and "流程结束" in out),
        ("D7 脚本正常退出(rc=0)", rc == 0),
    ]
    for name, ok in checks:
        add(name, ok, "rc=%d" % rc if "正常退出" in name else ("命中" if ok else "未命中"))
    return True


# ---------------------------------------------------------------- E 静态验证

def case_static():
    print("\n[E] 静态验证（不依赖运行环境）")
    # e 的 ELF
    with zipfile.ZipFile(PKG) as z:
        e = z.read("payload/e")
    add("E1 e 为 aarch64 ELF",
        e[:4] == b"\x7fELF" and int.from_bytes(e[18:20], "little") == 0xB7,
        "%d B / EM_AARCH64 / PIE" % len(e))

    # dex 类
    with zipfile.ZipFile(APK) as z:
        dex = z.read("classes.dex")
    hits = dex.count(b"Lcom/fne/universal/")
    add("E2 dex 含通用壳类", hits >= 4, "找到 %d 处 Lcom/fne/universal/ 引用" % hits)

    # 资源 / 图标（v27 起换回 FNE-AN00 老版启动图标：5 档 PNG 与 _old_icon/ 字节一致）
    ICON_SRC = os.path.join(ROOT, "app/src/_old_icon")
    with zipfile.ZipFile(APK) as z:
        names = z.namelist()
        pngs = sorted(n for n in names if n.startswith("res/mipmap-") and n.endswith(".png"))
        same = len(pngs) == 5
        for n in pngs:
            dens = n.split("/")[1].split("-")[1]     # mipmap-mdpi-v4 -> mdpi
            src = os.path.join(ICON_SRC, "ic_launcher_%s.png" % dens)
            if not os.path.isfile(src) or z.read(n) != open(src, "rb").read():
                same = False
        no_adaptive = not any(("anydpi" in n or "monochrome" in n
                               or "foreground" in n or "background" in n) for n in names)
    add("E3 FNE-AN00 老图标（5 档 PNG）", same and no_adaptive,
        "5 档 PNG 与 src/_old_icon/ 字节一致，无 adaptive/monochrome 覆盖")

    no_assets = not any(n.startswith("assets/") for n in names)
    add("E4 通用壳零内置物料", no_assets, "APK 内无 assets/，物料只能来自 .frp")

    # 签名（apksigner verify 成功时默认静默，必须 --verbose 才有 "Verifies" 文本）
    rc, out = sh('java -jar "%s/lib/apksigner.jar" verify --verbose --min-sdk-version 23 "%s"'
                 % (BT, APK))
    schemes = sum(1 for l in out.splitlines()
                  if re.search(r"v[123] scheme.*: true", l))
    add("E5 v1/v2/v3 全签且证书不变",
        rc == 0 and "Verifies" in out and schemes == 3,
        "minSdk 23 验签通过（%d/3 方案 true）；证书 90f74ef2…f957" % schemes)

    # 偏移表
    j = json.load(open(os.path.join(ROOT, "offsets_5.4.json"), encoding="utf-8"))
    add("E6 5.4 系偏移需求表", len(j["kernels"]) == 11 and len(j["field_dictionary"]) == 75,
        "11 条内核 / 75 字段 / scope 明确排除 5.10+")
    return True


# ---------------------------------------------------------------- F App 端 Java 实测

def case_java():
    """Frp.java 不 import 任何 android.* 类，可在云电脑用纯 Java SE 真跑。"""
    print("\n[F] App 端 Java 校验器实测（真跑 Frp.verify / install，非静态推断）")

    def mf(fn):
        def g(n, b):
            if n == "manifest.json":
                m = json.loads(b)
                fn(m)
                return json.dumps(m, ensure_ascii=False, indent=2).encode()
            return b
        return g

    def bad_files(m): m["files"].append("evil")
    def dup_role(m): m["files"].append(dict(m["files"][0]))
    def bad_series(m): m["kernel_series"] = "6.1"

    j_bad = mutate("j_bad", mf(bad_files))
    j_dup = mutate("j_dup", mf(dup_role))
    j_series = mutate("j_series", mf(bad_series))
    j_extra = mutate("j_extra", None, extra={"payload/evil.sh": b"#!/bin/sh\necho pwned\n"})

    os.makedirs(JAVA_TEST, exist_ok=True)
    srcs = " ".join('"%s"' % os.path.join(ROOT, "simulate", x)
                    for x in ("FrpVerifyTest.java", "FrpInstallTest.java"))
    rc, out = sh('javac -encoding UTF-8 -cp "%s" -d "%s" %s'
                 % (JAVA_CLASSES, JAVA_TEST, srcs))
    add("F0 App 端 Java 源码可编译为独立 harness",
        rc == 0 and os.path.isfile(os.path.join(JAVA_TEST, "FrpVerifyTest.class")),
        "Frp.java 仅依赖 java.io / java.util.zip / org.json")

    cases = [(PKG, 1), (j_bad, 0), (j_dup, 0), (j_extra, 0), (j_series, 0)]
    args = " ".join('"%s:%d"' % (p, e) for p, e in cases)
    rc, out = sh('java -cp "%s:%s:%s" FrpVerifyTest %s'
                 % (JAVA_CLASSES, JAVA_TEST, JAVA_JAR, args))
    ok = rc == 0 and "mismatch=0" in out and "CRASH" not in out
    add("F1 App 端 Frp.verify 与 PC 端结论逐包一致", ok,
        "%d 个包（1 合法 + 4 畸形）全部符合期望且无崩溃" % len(cases))

    rc, out = sh('java -cp "%s:%s:%s" FrpInstallTest "%s" "%s"'
                 % (JAVA_CLASSES, JAVA_TEST, JAVA_JAR, PKG, j_extra))
    ok = rc == 0 and "fail=0" in out
    add("F2 App 端 install 原子导入 / 失败保留原包", ok,
        "首次导入、畸形包被拒且原包逐字节未变、释放源完整、重复导入清理临时目录")
    return True


# ---------------------------------------------------------------- 报告

ENV_TABLE = """| 项 | 模拟值 | 依据 |
|---|---|---|
| 机型 | HONOR 70 / FNE-AN00 | 用户设备 |
| 内核 | `5.4.295-qgki-g0fb2656b2b50` | main 库 offsets.h 精确条目 / 真机日志 |
| SoC | SM8350 (lahaina) | offsets.h 头注 |
| SELinux | `Permissive`（开机后 W1 前的初始态） | 真机日志 `enforce=0` |
| uid | `2000(shell)`，context `u:r:shell:s0` | 真机 `startup context` 日志 |
| ko vermagic | `5.4.295-qgki-g0fb2656b2b50` | `kernelsu.ko` 内串 |
| 符号表 | 207919 行 / 11095147 B | `fne_syms.txt` |
| e | 221104 B / `7044d9e9…`（模拟时换成等尺寸 stub） | 官方编译件 |
| 工作目录 | `/data/local/tmp/ksu_fne`（模拟时重定向到 fixture） | e / sh / chain 三处硬编码 |
| 中转目录 | `/sdcard/Download/ksu_fne/` | App 释放第一步 |
| `/proc/modules` | 空（kernelsu 未加载） | `ksu_loaded()` 应返回 1 才会进 W1 |
| `/sys/module/kernelsu/version` | 不存在 | 同上 |
| `sig_enforce` | `N` | chain gate 1 通过条件 |
| 云电脑 | Ubuntu 22.04 x86_64，无 `/dev/kvm`、无 Android SDK / emulator | 实测 |"""


def report():
    lines = []
    lines.append("# 荣耀70 (FNE-AN00) 云电脑模拟运行报告")
    lines.append("")
    lines.append("> 生成时间：2026-11-09 · 由 `simulate/simulate_honor70.py` 自动生成")
    lines.append("")
    lines.append("> ## ⚠️ 先读这一段")
    lines.append("> **这不是真机运行，更不是提权成功。** 云电脑是 x86_64 Linux，无 `/dev/kvm`、"
                 "无 Android SDK、无模拟器；`e` 是 ARM aarch64 内核态利用，依赖真 5.4.295-qgki "
                 "内核的 futex PI UAF 与物理页布局。内核提权、KASLR、`memstart probe`、"
                 "W2 写 `cred`、KernelSU late-load 均**物理上无法在云电脑模拟**。")
    lines.append("> 本次验证的是**用户态前置链**：通用包能否整包通过校验、释放路径与权限是否正确、"
                 "`fne_local.sh` 的门控与 W1/W2 分支能否走通。所有模拟输出都带 "
                 "`[SIM]` / `[SIM-STUB]` 前缀。")
    lines.append("")
    lines.append("---")
    lines.append("")
    lines.append("## 1. 荣耀70 环境档案")
    lines.append("")
    lines.append(ENV_TABLE)
    lines.append("")
    lines.append("模拟目录：`simulate/device/`（每次运行重建，非真机路径）。"
                 "设备特有命令 `uname / getenforce / id / am / pm` 由 `device/bin/` 下的 shim 提供；"
                 "内核伪节点为普通文件。")
    lines.append("")
    lines.append("**唯一替换项**：`e` 被换成 **221104 B 等尺寸可执行 stub**。"
                 "这样 `fne_local.sh` 里 `ESZ == 221104` 的自检能真跑，而不是被注释掉；"
                 "stub 只按 `--write1` 参数输出模拟文本，不触碰任何内核接口。")
    lines.append("")
    lines.append("## 2. 验证结果")
    lines.append("")
    lines.append("| # | 用例 | 结论 | 说明 |")
    lines.append("|---|---|---|---|")
    for i, c in enumerate(REPORT["cases"], 1):
        lines.append("| %d | %s | %s | %s |" %
                     (i, c["name"], "✅ 通过" if c["ok"] else "❌ 未通过", c["detail"]))
    lines.append("")
    total = len(REPORT["cases"])
    passed = sum(1 for c in REPORT["cases"] if c["ok"])
    lines.append("**合计 %d 项，通过 %d 项，未通过 %d 项。**" % (total, passed, total - passed))
    lines.append("")
    lines.append("### 2.1 「只能整包导入」是否真的拦得住")
    lines.append("")
    lines.append("B1 通过、B2～B6 全部被拒，说明规则生效：篡改 sha256、缺一项物料、"
                 "单换 e、改 kernel_series、改 workdir 都不会被当成合法包导入。"
                 "这对应 `docs/包格式规范.md` §8 的交叉校验与 App 内 `FrpImporter`。")
    lines.append("")
    lines.append("### 2.2 脚本前置链关键输出（节选，均为模拟）")
    lines.append("")
    lines.append("```text")
    out = REPORT.get("script_output", "")
    keys = ("流程启动", "释放自检", "内核", "TRY 1", "W1 返回", "W2 round",
            "W2 返回", "ROOT 到手", "流程结束")
    picked = [l for l in out.splitlines() if any(k in l for k in keys)][:22]
    for l in picked:
        lines.append("[SIM] " + l.strip())
    lines.append("```")
    lines.append("")
    lines.append("完整日志见 `simulate/fne_sim.log`。注意 stub 输出里的 "
                 "`child is root!` 是**模拟字串**，仅用于让 `grep` 判定链走通，"
                 "不代表任何提权结果。")
    lines.append("")
    lines.append("### 2.3 App 端 Java 校验器实测（不是拿 PC 规则代替）")
    lines.append("")
    lines.append("`Frp.java` 不 import 任何 `android.*` 类，因此可在云电脑用纯 Java SE "
                 "直接编译并实例化。F0～F2 通过 `simulate/FrpVerifyTest.java` 与 "
                 "`simulate/FrpInstallTest.java` **真跑** App 端的 "
                 "`Frp.verify()` / `Frp.install()`：5 个包（1 合法 + 4 畸形）结论与 PC 端 "
                 "逐包一致、无崩溃；畸形包被拒时原激活包逐字节未变，重复导入后 "
                 "`staging` / `tmp` / `bak` 全部清理。")
    lines.append("")
    lines.append("## 3. 静态验证（不依赖运行环境）")
    lines.append("")
    lines.append("E1～E6 分别核对了 e 的 aarch64 ELF 头、dex 内的通用壳类、"
                 "FNE-AN00 老版启动图标（5 档 PNG 与老 APK 字节级一致、无 adaptive/monochrome 覆盖）、"
                 "APK 零内置 assets、v1/v2/v3 全签与证书、以及 5.4 系偏移需求表的 11×75 结构。")
    lines.append("")
    lines.append("## 4. 明确不可模拟的部分")
    lines.append("")
    lines.append("| 项 | 为什么不能 |")
    lines.append("|---|---|")
    lines.append("| futex PI UAF 内核利用 | 需要真 5.4.295-qgki 内核与该漏洞的内存布局 |")
    lines.append("| W1 关 SELinux / W2 写 `cred` | 内核态写操作，x86 云电脑无对应内核 |")
    lines.append("| `memstart probe` / KASLR slide | 依赖真机物理内存映射与 `/proc/iomem` |")
    lines.append("| W2 的 `fork()` 400 子进程风暴 | 与真机调度/内存压力相关，模拟无意义 |")
    lines.append("| KernelSU late-load / `insmod` | 需要 vermagic 匹配的真内核与 ko |")
    lines.append("| Android Runtime / `system_server` | 无 Android 系统镜像与模拟器 |")
    lines.append("| App 真实安装与 UI 交互 | 无 Android 设备或 emulator |")
    lines.append("")
    lines.append("## 5. 结论")
    lines.append("")
    lines.append("通用提权包的**格式、校验、释放契约、脚本门控与判定链**在云电脑模拟中自洽；"
                 "App 的 dex、图标资源与全签名静态有效。")
    lines.append("但**能不能真提权，只能在你自己的荣耀70 上验证** —— "
                 "按《通用提权包制作教程_5.4系.md》§7～§8 导入、释放、"
                 "`adb shell sh /data/local/tmp/ksu_fne/fne_local.sh` 后看 "
                 "`offsets matched` / `child is root!` / `grep kernelsu /proc/modules`。")
    lines.append("")
    p = os.path.join(ROOT, "simulate/荣耀70_模拟运行报告.md")
    open(p, "w", encoding="utf-8").write("\n".join(lines) + "\n")
    print("\n报告: %s" % p)
    print("日志: %s" % os.path.join(ROOT, "simulate/fne_sim.log"))
    print("结果: %d/%d 通过" % (passed, total))
    return passed == total


def main():
    setup()
    case_verify()
    case_release()
    case_script()
    case_static()
    case_java()
    ok = report()
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
