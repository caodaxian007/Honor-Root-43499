#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
第二轮 Bug 实证：不再只测「畸形 manifest 会不会崩」，而是测规则本身有没有漏洞。

交叉跑三条链路：
  1. PC 端   frp_tool.verify()
  2. App 端  Frp.verify()      —— 纯 Java SE 真跑，org.json 来自 android-all-13.jar
  3. App 端  Frp.install()/release() + copyCommand() —— 释放与搬运链路

用例放在 /tmp，不污染交付目录。输出一张「PC / App / 期望」对照表。
用法：python3 simulate/bugcheck_v2.py
"""
import contextlib
import hashlib
import io
import json
import os
import shutil
import subprocess
import sys
import zipfile

ROOT = "/workspace/FNERoot_通用提权包"
PKG = os.path.join(ROOT, "packages/FNE-AN00-5.4.295.frp")
ART = "/root/.codebuddy/artifact/2f8a7d30-9c21-4f0b-1d67-b55eb80b4000"
JAR = ART + "/sdk/android-all-13.jar"
SRC_CLASSES = os.path.join(ROOT, "app/build/classes")
TMP = "/tmp/frp_bugcheck_v2"
JCLASSES = os.path.join(TMP, "classes")      # 只放 Frp*.class，org.json 一律用 jar 真实现
JTEST = os.path.join(TMP, "test")

sys.path.insert(0, ROOT)
import frp_tool  # noqa: E402


# ---------------------------------------------------------------- 用例构造

def mutate(tag, fn, extra=None, drop=None):
    """基于示范包生成篡改包：fn(name, bytes) -> 新 bytes / None(删除条目)。"""
    out = os.path.join(TMP, tag + ".frp")
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


def mutate_dup_rev(tag, dup_name, first_bytes, second_bytes):
    """同名条目出现两次，且最后一个才是合法内容 —— 最能暴露重复条目歧义。"""
    out = os.path.join(TMP, tag + ".frp")
    with zipfile.ZipFile(PKG) as src, zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as dst:
        for it in src.infolist():
            dst.writestr(it, first_bytes if it.filename == dup_name
                         else src.read(it.filename))
        dst.writestr(dup_name, second_bytes)
    return out


def edit_manifest(b, fn):
    m = json.loads(b)
    fn(m)
    return json.dumps(m, ensure_ascii=False, indent=2).encode()


def only_manifest(mutator):
    def g(n, b):
        if n == "manifest.json":
            return edit_manifest(b, mutator)
        return b
    return g


def by_role(m, role):
    return next(f for f in m["files"] if f.get("role") == role)


CASES = []


def case(tag, desc, builder, expect):
    """expect: 'REJECT' = 应当被两端都拒绝；'ACCEPT' = 应当放行；'DIFF' = 记录两端是否不一致。"""
    CASES.append((tag, desc, builder, expect))


# C1 角色与目标名解绑：交换 exploit / ksud 的 dest，物料本身完全没动
def c1(m):
    by_role(m, "exploit")["dest"] = "ksud"
    by_role(m, "ksud")["dest"] = "e"


case("C1_dest_swap", "交换 exploit/ksud 的 dest（e 会被释放成 ksud）",
     lambda: mutate("C1_dest_swap", only_manifest(c1)), "REJECT")


# C2 dest 重名：ksud 也释放成 e，后写覆盖前面的 e
def c2(m):
    by_role(m, "ksud")["dest"] = "e"


case("C2_dest_dup", "两个 role 的 dest 都写 e（释放时相互覆盖）",
     lambda: mutate("C2_dest_dup", only_manifest(c2)), "REJECT")


# C3 dest 含子目录：verify 是否允许？release 是否建父目录？
def c3(m):
    by_role(m, "entry_script")["dest"] = "sub/fne_local.sh"


case("C3_dest_subdir", "entry_script 的 dest 改成 sub/fne_local.sh",
     lambda: mutate("C3_dest_subdir", only_manifest(c3)), "REJECT")


# C4 清单内额外条目：声明一个未知 role，并在 ZIP 里放对应文件
EVIL = b"#!/bin/sh\necho pwned\n"


def c4(m):
    m["files"].append({
        "path": "payload/evil.sh", "dest": "evil.sh", "role": "misc",
        "size": len(EVIL), "sha256": __import__("hashlib").sha256(EVIL).hexdigest(),
        "mode": "0755", "desc": "清单内额外条目",
    })


case("C4_extra_declared", "files[] 里多声明一项未知 role（含对应 ZIP 条目）",
     lambda: mutate("C4_extra_declared", only_manifest(c4),
                    extra={"payload/evil.sh": EVIL}), "REJECT")


# C5 数字写成字符串：PC 严格判等、App 用 optInt 可能转换 -> 两端结论不一致
def c5(m):
    m["format_version"] = "1"
    m["files"][0]["size"] = "221104"
    m["execution"]["e_size"] = "221104"


case("C5_str_int", "format_version / size / e_size 写成字符串 \"1\"/\"221104\"",
     lambda: mutate("C5_str_int", only_manifest(c5)), "REJECT")


# C6 e_size 缺失：PC 有回退到 files[exploit].size，App 没有
def c6(m):
    m["execution"].pop("e_size", None)


case("C6_e_size_missing", "删掉 execution.e_size（旧版两端结论相反）",
     lambda: mutate("C6_e_size_missing", only_manifest(c6)), "REJECT")


# C7 mode 只校验格式、不校验值：exploit 写成 0644
def c7(m):
    by_role(m, "exploit")["mode"] = "0644"


case("C7_mode_value", "exploit 的 mode 改成 0644（格式合法但值不符契约）",
     lambda: mutate("C7_mode_value", only_manifest(c7)), "REJECT")


# C8 offsets 表只留一个字段，却宣称「75 字段完整」
def c8(n, b):
    if n != "offsets/offsets.json":
        return b
    o = json.loads(b)
    for k in o["kernels"]:
        k["offsets"] = {"off_init_cred": k["offsets"].get("off_init_cred")}
    return json.dumps(o, ensure_ascii=False).encode()


case("C8_offsets_thin", "offsets.json 每条只留 off_init_cred 一个字段",
     lambda: mutate("C8_offsets_thin", c8), "REJECT")


# C9 kernel_series 前缀过宽
def c9(m):
    m["kernel_series"] = "5.40"


case("C9_series_loose", "kernel_series 改成 5.40（startsWith(\"5.4\") 会放行）",
     lambda: mutate("C9_series_loose", only_manifest(c9)), "REJECT")


# C10 dest 绝对路径（对照：应已被 safeName 拦住）
def c10(m):
    by_role(m, "exploit")["dest"] = "/data/local/tmp/ksu_fne/e"


case("C10_abs_dest", "dest 用绝对路径（对照组，v21 已修）",
     lambda: mutate("C10_abs_dest", only_manifest(c10)), "REJECT")


# C11 两个 role 指向同一个 path（同一份内容被释放两次，物料缺失）
def c11(m):
    by_role(m, "ksud")["path"] = "payload/e"
    by_role(m, "ksud")["size"] = 221104
    by_role(m, "ksud")["sha256"] = by_role(m, "exploit")["sha256"]


case("C11_same_path", "ksud 与 exploit 指向同一个 payload/e",
     lambda: mutate("C11_same_path", only_manifest(c11), drop=["payload/ksud"]), "REJECT")


# ---------------------------------------------------------------- D 组：物料互相绑定 / 重复条目

def rebuild(tag, changes, mm=None):
    """替换若干条目并自动同步 manifest 的 size/sha256，制造一个「自洽」的误配包。"""
    def g(n, b):
        if n == "manifest.json":
            m = json.loads(b)
            for f in m["files"]:
                if f["path"] in changes:
                    nb = changes[f["path"]]
                    f["size"] = len(nb)
                    f["sha256"] = hashlib.sha256(nb).hexdigest()
            if mm:
                mm(m)
            return json.dumps(m, ensure_ascii=False, indent=2).encode()
        return changes.get(n, b)
    return mutate(tag, g)


def load(name):
    return zipfile.ZipFile(PKG).read(name)


# D1 换一个不同尺寸的 e（manifest 全套自洽），但 fne_local.sh 里仍断言 221104
case("D1_e_size_vs_sh", "e 换成 200000 B 且 manifest 自洽，sh 的 ESZ 断言仍为 221104",
     lambda: rebuild("D1_e_size_vs_sh",
                     {"payload/e": load("payload/e")[:200000]},
                     lambda m: m["execution"].__setitem__("e_size", 200000)), "REJECT")

# D2 脚本里的 workdir 被改掉，manifest 仍写死 /data/local/tmp/ksu_fne
case("D2_sh_workdir", "fne_local.sh 内 workdir 改成 /data/local/tmp/other（manifest 自洽）",
     lambda: rebuild("D2_sh_workdir",
                     {"payload/fne_local.sh": load("payload/fne_local.sh").replace(
                         b"/data/local/tmp/ksu_fne", b"/data/local/tmp/other")}), "REJECT")

# D3 chain_hook.sh 的内核指纹门被改成别的内核
case("D3_chain_gate", "chain_hook.sh 内核门改成 5.4.999-qgki-deadbeef（manifest 自洽）",
     lambda: rebuild("D3_chain_gate",
                     {"payload/chain_hook.sh": load("payload/chain_hook.sh").replace(
                         b"5.4.295-qgki-g0fb2656b2b50", b"5.4.999-qgki-deadbeef00")}), "REJECT")

# D4 符号表被截到 100001 行（旧规则 >100000 会放行），与 assertions.kallsyms_lines=207919 不符
def thin_syms():
    b = load("payload/fne_syms.txt")
    pos, cnt = 0, 0
    for i, c in enumerate(b):
        if c == 10:
            cnt += 1
            if cnt > 100001:
                pos = i
                break
    return b[:pos]

case("D4_syms_thin", "fne_syms.txt 截到 100001 行（manifest 自洽）",
     lambda: rebuild("D4_syms_thin", {"payload/fne_syms.txt": thin_syms()}), "REJECT")

# D5 ZIP 里放两个同名 manifest.json（第二个是坏的）
def bad_manifest():
    m = json.loads(load("manifest.json"))
    m["format"] = "evil-format"
    return json.dumps(m, ensure_ascii=False, indent=2).encode()

case("D5_dup_manifest", "两个同名 manifest.json（第一个 evil、第二个合法）",
     lambda: mutate_dup_rev("D5_dup_manifest", "manifest.json",
                            bad_manifest(), load("manifest.json")), "REJECT")

# D6 ZIP 里放两个同名 payload/e（第一个垃圾、第二个官方）
case("D6_dup_payload_e", "两个同名 payload/e（第一个垃圾、第二个官方）",
     lambda: mutate_dup_rev("D6_dup_payload_e", "payload/e",
                            b"GARBAGE" * 1000, load("payload/e")), "REJECT")


# ---------------------------------------------------------------- 跑校验器

def pc_verify(path):
    buf = io.StringIO()
    try:
        with contextlib.redirect_stdout(buf):
            ok = frp_tool.verify(path)
    except Exception as e:
        return "CRASH:" + type(e).__name__
    return "ACCEPT" if ok else "REJECT"


PROBE_JAVA = r'''
import com.fne.universal.Frp;
import java.io.File;
public class FrpProbe {
    public static void main(String[] a) {
        for (String p : a) {
            try {
                Frp.Result r = Frp.verify(new File(p));
                System.out.println((r.ok ? "ACCEPT" : "REJECT") + " " + new File(p).getName());
            } catch (Throwable t) {
                System.out.println("CRASH " + new File(p).getName() + " " + t);
            }
        }
    }
}
'''

RELEASE_JAVA = r'''
import com.fne.universal.Frp;
import java.io.File;
public class FrpReleaseProbe {
    public static void main(String[] a) throws Exception {
        File dir = new File(a[0]);
        Frp.Result ins = Frp.install(new File(a[1]), dir);
        System.out.println("INSTALL " + (ins.ok ? "OK" : "FAIL"));
        if (!ins.ok) { for (String l : ins.lines) System.out.println("  " + l); }
        Frp.Result rel = Frp.release(dir);
        System.out.println("RELEASE_OK " + rel.ok);
        for (String l : rel.lines) System.out.println("  " + l);
        System.out.println("--- copyCommand ---");
        System.out.println(Frp.copyCommand());
    }
}
'''


def javac(src, name, cp):
    p = os.path.join(TMP, name + ".java")
    open(p, "w").write(src)
    r = subprocess.run(["javac", "-encoding", "UTF-8", "-cp", cp, "-d", JTEST, p],
                       capture_output=True, text=True)
    if r.returncode:
        print("javac 失败:", r.stderr[:800])
        sys.exit(2)


def java_probe(paths):
    javac(PROBE_JAVA, "FrpProbe", JCLASSES + ":" + JAR)
    r = subprocess.run(["java", "-cp", JCLASSES + ":" + JTEST + ":" + JAR,
                        "FrpProbe"] + paths, capture_output=True, text=True)
    out = {}
    for line in (r.stdout or "").splitlines():
        parts = line.split(" ", 1)
        if len(parts) == 2 and parts[0] in ("ACCEPT", "REJECT", "CRASH"):
            out[parts[1]] = parts[0]
    if r.returncode:
        print("java 运行异常:", (r.stderr or "")[:500])
    return out


def setup_java_classes():
    os.makedirs(JCLASSES, exist_ok=True)
    os.makedirs(JTEST, exist_ok=True)
    dst = os.path.join(JCLASSES, "com/fne/universal")
    os.makedirs(dst, exist_ok=True)
    for f in os.listdir(SRC_CLASSES + "/com/fne/universal"):
        if f.startswith("Frp"):
            shutil.copy2(os.path.join(SRC_CLASSES, "com/fne/universal", f),
                         os.path.join(dst, f))


# ---------------------------------------------------------------- 释放链路实证

def release_probe(install_pkg, tag):
    javac(RELEASE_JAVA, "FrpReleaseProbe", JCLASSES + ":" + JAR)
    sd = "/sdcard/Download/ksu_fne"
    files_dir = os.path.join(TMP, "filesdir_" + tag)
    shutil.rmtree(files_dir, ignore_errors=True)
    os.makedirs(files_dir, exist_ok=True)
    # 预置「上一次释放留下的旧物料」，模拟用户换包
    os.makedirs(sd, exist_ok=True)
    leftover = os.path.join(sd, "OLD_STALE_e")
    open(leftover, "wb").write(b"OLD-STALE-ARTIFACT")
    r = subprocess.run(["java", "-cp", JCLASSES + ":" + JTEST + ":" + JAR,
                        "FrpReleaseProbe", files_dir, install_pkg],
                       capture_output=True, text=True)
    listing = sorted(os.listdir(sd)) if os.path.isdir(sd) else []
    return (r.stdout or "") + (r.stderr or ""), listing


# ---------------------------------------------------------------- main

def main():
    shutil.rmtree(TMP, ignore_errors=True)
    os.makedirs(TMP, exist_ok=True)
    setup_java_classes()

    built = []
    for tag, desc, builder, expect in CASES:
        built.append((tag, desc, builder(), expect))
    # 合法示范包作为基准
    all_pkgs = [PKG] + [p for _, _, p, _ in built]

    pc = {os.path.basename(p): pc_verify(p) for p in all_pkgs}
    ja = java_probe(all_pkgs)

    print("=" * 100)
    print("第二轮 Bug 实证 · PC 端 frp_tool.verify  vs  App 端 Frp.verify（Java SE 真跑）")
    print("=" * 100)
    print("%-24s %-10s %-10s %-8s %-8s  %s" %
          ("用例", "PC", "App", "一致", "期望", "说明"))
    print("-" * 100)

    npass = nfail = 0

    def row(tag, desc, path, expect):
        nonlocal npass, nfail
        k = os.path.basename(path)
        p, j = pc.get(k, "?"), ja.get(k, "?")
        same = "是" if p == j else "**否**"
        ok = (p == expect and j == expect)
        if ok:
            npass += 1
        else:
            nfail += 1
        verdict = "PASS" if ok else (
            "FAIL 放行=BUG" if "ACCEPT" in (p, j) else "FAIL 两端不一致/误拒")
        print("%-24s %-10s %-10s %-8s %-8s  %s" %
              (tag, p, j, same, expect, desc + " -> " + verdict))

    row("BASE_合法包", "未篡改示范包", PKG, "ACCEPT")
    for tag, desc, path, expect in built:
        row(tag, desc, path, expect)
    print("\n校验器回归: %d PASS / %d FAIL" % (npass, nfail))

    print("\n" + "=" * 100)
    print("释放 / 搬运链路实证（真跑 Frp.install + Frp.release + copyCommand）")
    print("=" * 100)

    rel_ok = True
    out, listing = release_probe(PKG, "good")
    for l in out.splitlines():
        if any(x in l for x in ("INSTALL", "RELEASE_OK", "[FAIL]", "释放完成",
                                "释放存在", "中转目录已写入", "提示] 中转目录")):
            print("  " + l.strip())
    cmd = out.split("--- copyCommand ---")[-1].strip()
    uses_star = "*" in cmd
    n_listed = cmd.count("/sdcard/Download/ksu_fne/")
    if uses_star:
        rel_ok = False
    if "OLD_STALE_e" in cmd:
        rel_ok = False
    print("  搬运命令: %s（显式列出 %d 项）" %
          ("仍用通配符 * -> BUG" if uses_star else "已显式列出文件名 ✔", n_listed))
    print("  残留 OLD_STALE_e: %s" %
          ("仍在（不删用户文件），但搬运命令不含它 ✔"
           if "OLD_STALE_e" in listing and "OLD_STALE_e" not in cmd else "已清理"))

    # dest 含子目录的包：修复后应在 verify 阶段就被拒绝，不会走到 release
    c3_path = next(p for t, _, p, _ in built if t == "C3_dest_subdir")
    out3, listing3 = release_probe(c3_path, "subdir")
    c3_rejected = "INSTALL FAIL" in out3
    if not c3_rejected:
        rel_ok = False
    print("\n  [C3 dest 含子目录] 是否在导入阶段被拒绝: " +
          ("是 ✔（不会再出现半截释放）" if c3_rejected else "否 -> BUG"))
    if not c3_rejected:
        for l in out3.splitlines():
            if any(x in l for x in ("RELEASE_OK", "[FAIL]", "释放异常")):
                print("    " + l.strip())

    # 只清理实证自己创建的中转目录，不动 /sdcard 其它内容
    shutil.rmtree("/sdcard/Download/ksu_fne", ignore_errors=True)
    for d in ("/sdcard/Download", "/sdcard"):
        try:
            os.rmdir(d)
        except OSError:
            pass
    print("\n总判定: " + ("全部通过 ✔" if nfail == 0 and rel_ok else "存在失败 ✘"))
    print("用例包保留在: " + TMP)
    return 0 if (nfail == 0 and rel_ok) else 1


if __name__ == "__main__":
    sys.exit(main())
