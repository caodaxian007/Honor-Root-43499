#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
第三轮 Bug 实证：不再测「畸形输入」，也不再测「格式合法但违反整包语义」，
而是测三层更隐蔽的问题：

  A. 规则自证 —— 校验器把「必备字段清单 / 断言值 / 偏移表路径 / 覆盖率」
                 都从包内 manifest、offsets.json 自己读，包改了规则就跟着改。
  B. 跨端差异 —— PC(frp_tool.py) 与 App(Frp.java) 的检查项并不一一对应，
                 同一个包可能 PC 拒 / App 放，或反之。
  C. 链路/工具 —— verify 与 install 两次独立打开 ZIP 的 TOCTOU、
                 inspect 畸形包崩溃、extract 符号链接逃逸、build 沿用旧断言。

交叉跑：PC frp_tool.verify  +  App Frp.verify（纯 Java SE 真跑，org.json 用
android-all-13.jar 真实现）+ 真跑 Frp.install 的 TOCTOU harness。

用法：python3 simulate/bugcheck_v3.py
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
FRP_SRC = os.path.join(ROOT, "app/src/com/fne/universal/Frp.java")
MAT = os.path.join(ROOT, "packages/_素材_FNE-AN00-5.4.295")
TMP = "/tmp/frp_bugcheck_v3"
JCLASSES = os.path.join(TMP, "classes")
JTEST = os.path.join(TMP, "test")

sys.path.insert(0, ROOT)
import frp_tool  # noqa: E402


# ---------------------------------------------------------------- 构造工具

def load(name, pkg=PKG):
    return zipfile.ZipFile(pkg).read(name)


def mutate(tag, changes=None, mm=None, drop=None, extra=None):
    """changes: {条目名: 新 bytes}；mm: manifest 变体函数；drop: 删除的条目名。"""
    out = os.path.join(TMP, tag + ".frp")
    changes = changes or {}
    with zipfile.ZipFile(PKG) as src, zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as dst:
        for it in src.infolist():
            if drop and it.filename in drop:
                continue
            b = src.read(it.filename)
            if it.filename == "manifest.json":
                m = json.loads(b)
                # 自动同步被替换物料的 size/sha256
                for f in m["files"]:
                    if f["path"] in changes:
                        nb = changes[f["path"]]
                        f["size"] = len(nb)
                        f["sha256"] = hashlib.sha256(nb).hexdigest()
                if mm:
                    mm(m)
                b = json.dumps(m, ensure_ascii=False, indent=2).encode()
            else:
                b = changes.get(it.filename, b)
            dst.writestr(it, b)
        for n, b in (extra or {}).items():
            dst.writestr(n, b)
    return out


def offsets_mutate(tag, fn, mm=None, extra=None, drop=None):
    """只改 offsets/offsets.json（它不在 files[] 里，没有 size/sha256 绑定）。"""
    o = json.loads(load("offsets/offsets.json"))
    fn(o)
    nb = json.dumps(o, ensure_ascii=False, indent=2).encode()
    return mutate(tag, {"offsets/offsets.json": nb}, mm=mm, extra=extra, drop=drop)


CASES = []


def case(tag, group, desc, builder, expect):
    # expect = 修复后应当得到的结论；修前实测若不符即为 BUG
    CASES.append((tag, group, desc, builder, expect))


# ---------------------------------------------------------------- A 组：规则自证

def a1(o):
    """把 field_dictionary 砍到只剩 1 项，每条内核的 offsets 也只留这 1 个字段。
    校验器的「75 必备字段」清单来自包内自述 —— 包说 1 个就只查 1 个。"""
    o["field_dictionary"] = [d for d in o["field_dictionary"]
                             if d.get("name") == "off_init_cred"]
    for k in o["kernels"]:
        k["offsets"] = {"off_init_cred": k["offsets"]["off_init_cred"]}


case("A1_dict_shrink", "A 规则自证",
     "field_dictionary 砍到 1 项 + 11 条内核 offsets 各只剩 1 字段（宣称的 75 字段形同虚设）",
     lambda: offsets_mutate("A1_dict_shrink", a1), "REJECT")


def a2(o):
    """74 个字段标 required:false，并把每条内核的 offsets 也只留 off_init_cred。
    修前：校验器按包内字典的 required 开关判卷，只查 1 个字段 -> 放行；
    修后：字段清单内置，无论包怎么自述都按 75 项全查 -> 拒绝。"""
    for d in o["field_dictionary"]:
        d["required"] = (d.get("name") == "off_init_cred")
    for k in o["kernels"]:
        k["offsets"] = {"off_init_cred": k["offsets"]["off_init_cred"]}


case("A2_required_off", "A 规则自证",
     "field_dictionary 74 项标 required:false 且内核 offsets 同步只剩 1 字段",
     lambda: offsets_mutate("A2_required_off", a2), "REJECT")


def a3(o):
    """同上但用字符串 "false"：PC 按 truthy 仍算必备，App optBoolean 会跳过 -> DIFF。"""
    for d in o["field_dictionary"]:
        if d.get("name") != "off_init_cred":
            d["required"] = "false"
    # 顺手删掉一条内核的 off_init_cred，放大两端差异
    del o["kernels"][0]["offsets"]["off_init_cred"]


case("A3_required_str", "A 规则自证",
     "required 写成字符串 \"false\" 且删掉 1 条内核的 off_init_cred（PC/App 解析不同）",
     lambda: offsets_mutate("A3_required_str", a3), "REJECT")


def a4_mm(m):
    m["execution"]["assertions"]["kallsyms_lines"] = 1


SYMS_1LINE = b"ffffffff00000000 A _stext\n"


case("A4_syms_assert", "A 规则自证",
     "assertions.kallsyms_lines 改成 1 + 符号表截成 1 行并重算 sha256（期望行数由包自述）",
     lambda: mutate("A4_syms_assert", {"payload/fne_syms.txt": SYMS_1LINE}, mm=a4_mm),
     "REJECT")


def a5_mm(m):
    m["package"]["kernel_releases"] = list(m["package"]["kernel_releases"]) + [
        "5.4.999-qgki-fake0001", "5.4.999-qgki-fake0002"]


case("A5_partial_cover", "A 规则自证",
     "kernel_releases 加 2 个假内核，偏移表只覆盖原来那 1 个（「至少覆盖一个」被利用）",
     lambda: mutate("A5_partial_cover", mm=a5_mm), "REJECT")


def a6(o):
    """偏移表整体搬到 payload/ 下，靠 offsets_ref 指向它 —— 这个文件不在 files[]，
    没有 size/sha256，且 allowed 集合会无条件把 offRef 加进白名单。"""
    o["field_dictionary"] = [d for d in o["field_dictionary"]
                             if d.get("name") == "off_init_cred"]


EVIL_OFF = None


def a6_build():
    global EVIL_OFF
    o = json.loads(load("offsets/offsets.json"))
    a6(o)
    EVIL_OFF = json.dumps(o, ensure_ascii=False, indent=2).encode()
    return mutate("A6_offsets_ref", mm=lambda m: m.__setitem__(
        "offsets_ref", "payload/offsets_evil.json"),
        drop=["offsets/offsets.json"],
        extra={"payload/offsets_evil.json": EVIL_OFF})


case("A6_offsets_ref", "A 规则自证",
     "offsets_ref 改成 payload/offsets_evil.json，并把原表删掉（规范写死路径却未校验）",
     a6_build, "REJECT")


def a7_mm(m):
    m["execution"]["entry_script"] = "other.sh"


case("A7_entry_script", "A 规则自证",
     "execution.entry_script 改成 other.sh（执行契约只查非空，未与 copyCommand/execCommand 绑定）",
     lambda: mutate("A7_entry_script", mm=a7_mm), "REJECT")


def a8(o):
    o["kernels"] = [o["kernels"][0]]
    o["kernels"][0]["uname_r"] = "5.4.999-qgki-notreal"


case("A8_bogus_uname", "A 规则自证",
     "kernels 只留 1 条且 uname_r=5.4.999-qgki-notreal（只查前缀 5.4.）",
     lambda: offsets_mutate("A8_bogus_uname", a8), "REJECT")


# ---------------------------------------------------------------- B 组：跨端差异

def b1(o):
    o["kernels"][0]["offsets"]["off_init_cred"] = "garbage"


case("B1_off_not_num", "B 跨端差异",
     "off_init_cred 值改成 \"garbage\"（PC 有 parse_num，App 只查键是否存在）",
     lambda: offsets_mutate("B1_off_not_num", b1), "REJECT")


def b2():
    e = bytearray(load("payload/e"))
    e[19] = 1                    # e_machine 高字节；PC 读 2 字节 = 0x1B7，App 只查低字节 0xB7
    return bytes(e)


case("B2_elf_em_hi", "B 跨端差异",
     "e 的 ELF e_machine 高字节改成 1（PC 读 2 字节 REJECT / App 只查低字节）",
     lambda: mutate("B2_elf_em_hi", {"payload/e": b2()}), "REJECT")


BAD_SH_TAIL = b"\nif [ 1 = 1 ; then echo broken\n"


def b3_sh():
    return load("payload/fne_local.sh") + BAD_SH_TAIL


case("B3_sh_syntax", "B 跨端差异",
     "fne_local.sh 追加一行语法错误（PC 有 sh -n，App 无任何语法检查）",
     lambda: mutate("B3_sh_syntax", {"payload/fne_local.sh": b3_sh()}), "REJECT")


def b4(o):
    # 删 field_dictionary（两端都只要求非空 -> 应拒），这里测另一个差异点：
    # offsets 值写成 JSON null：PC 用 `f in dict` 仍算存在，App 用 opt()==null 算缺失
    o["kernels"][0]["offsets"]["off_init_cred"] = None


case("B4_off_null", "B 跨端差异",
     "off_init_cred = null（PC 按键存在放行 / App 按 opt()==null 判缺失）",
     lambda: offsets_mutate("B4_off_null", b4), "REJECT")


# ---------------------------------------------------------------- C 组：链路 / 工具

# C1 inspect 畸形包
def c1_build():
    out = os.path.join(TMP, "C1_inspect_bad.frp")
    with zipfile.ZipFile(PKG) as s, zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as d:
        for it in s.infolist():
            d.writestr(it, b"{}" if it.filename == "manifest.json"
                       else s.read(it.filename))
    return out


# C2 extract 符号链接逃逸的目标目录（在实证函数里准备）

# C3 TOCTOU：B 包只改 package.id，仍是完全合法的包
def c3_build():
    out = os.path.join(TMP, "C3_toctou_evil.frp")
    m = json.loads(load("manifest.json"))
    m["package"]["id"] = "EVIL-TOCTOU"
    with zipfile.ZipFile(PKG) as s, zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as d:
        for it in s.infolist():
            d.writestr(it, json.dumps(m, ensure_ascii=False, indent=2).encode()
                       if it.filename == "manifest.json" else s.read(it.filename))
    return out


# C4 build 沿用模板 assertions
def c4_build():
    src = os.path.join(TMP, "mat_c4")
    shutil.rmtree(src, ignore_errors=True)
    shutil.copytree(MAT, src)
    open(os.path.join(src, "payload/fne_syms.txt"), "wb").write(SYMS_1LINE)
    tp = os.path.join(src, "manifest.template.json")
    meta = json.load(open(tp, encoding="utf-8")) if os.path.isfile(tp) else {}
    meta.setdefault("execution", {}).setdefault("assertions", {})["kallsyms_lines"] = 1
    json.dump(meta, open(tp, "w", encoding="utf-8"), ensure_ascii=False, indent=2)
    return src


# ---------------------------------------------------------------- 双端校验

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

TOC_JAVA = r'''
import com.fne.universal.Frp;
import java.io.*;
import java.nio.file.*;
public class TocProbe {
    static String diskId(File dir) throws Exception {
        String s = new String(Files.readAllBytes(
            new File(dir, "active_pkg/manifest.json").toPath()), "UTF-8");
        int p = s.indexOf("\"id\"");
        int c = s.indexOf(':', p);
        int q1 = s.indexOf('"', c + 1);
        int q2 = s.indexOf('"', q1 + 1);
        return s.substring(q1 + 1, q2);
    }
    public static void main(String[] a) throws Exception {
        byte[] good = Files.readAllBytes(Paths.get(a[0]));
        byte[] evil = Files.readAllBytes(Paths.get(a[1]));
        final String pkgPath = a[2];
        File pkg = new File(pkgPath);
        File dir = new File(a[3]);
        // 扫描不同延时，命中「verify 返回后、install 第二次 new ZipFile 前」的窄窗口
        long[] delays = {0, 1, 2, 3, 5, 8, 12, 20, 35, 60, 100};
        int bad = 0, ok = 0, tried = 0;
        for (long d : delays) {
            for (int rep = 0; rep < 2; rep++) {
                Files.write(pkg.toPath(), good);
                final long delay = d;
                Thread sw = new Thread(new Runnable() { public void run() {
                    try {
                        if (delay > 0) Thread.sleep(delay);
                        Path t = Paths.get(pkgPath + ".tmp");
                        Files.write(t, evil);
                        Files.move(t, Paths.get(pkgPath),
                                   StandardCopyOption.REPLACE_EXISTING);
                    } catch (Exception e) {}
                }});
                sw.setDaemon(true);
                sw.start();
                tried++;
                Frp.Result r = Frp.install(pkg, dir);
                sw.join();
                if (!r.ok) continue;
                ok++;
                String d2 = diskId(dir);
                if (!d2.equals(r.id)) bad++;
            }
        }
        // 对照组：不做中途替换
        Files.write(pkg.toPath(), good);
        Frp.Result rc = Frp.install(pkg, dir);
        boolean controlOk = rc.ok && diskId(dir).equals(rc.id);
        System.out.println("TOCTOU tried=" + tried + " ok=" + ok + " mismatch=" + bad
                           + " control=" + (controlOk ? "OK" : "BAD"));
    }
}
'''


def javac(src, name, cp, out):
    p = os.path.join(TMP, name + ".java")
    open(p, "w").write(src)
    r = subprocess.run(["javac", "-encoding", "UTF-8", "-cp", cp, "-d", out, p],
                       capture_output=True, text=True)
    if r.returncode:
        print("javac 失败:", r.stderr[:1200])
        sys.exit(2)


def setup_java():
    shutil.rmtree(JCLASSES, ignore_errors=True)
    os.makedirs(JCLASSES, exist_ok=True)
    os.makedirs(JTEST, exist_ok=True)
    r = subprocess.run(["javac", "-source", "8", "-target", "8", "-encoding", "UTF-8",
                        "-cp", JAR, "-d", JCLASSES, FRP_SRC],
                       capture_output=True, text=True)
    if r.returncode:
        print("Frp.java 编译失败:", r.stderr[:1500])
        sys.exit(2)
    javac(PROBE_JAVA, "FrpProbe", JCLASSES + ":" + JAR, JTEST)
    javac(TOC_JAVA, "TocProbe", JCLASSES + ":" + JAR, JTEST)


def java_probe(paths):
    r = subprocess.run(["java", "-cp", JCLASSES + ":" + JTEST + ":" + JAR,
                        "FrpProbe"] + paths, capture_output=True, text=True)
    out = {}
    for line in (r.stdout or "").splitlines():
        parts = line.split(" ", 1)
        if len(parts) == 2 and parts[0] in ("ACCEPT", "REJECT", "CRASH"):
            out[parts[1]] = parts[0]
    if r.returncode:
        print("java 运行异常:", (r.stderr or "")[:400])
    return out


# ---------------------------------------------------------------- main

def main():
    shutil.rmtree(TMP, ignore_errors=True)
    os.makedirs(TMP, exist_ok=True)
    setup_java()

    built = []
    for tag, group, desc, builder, expect in CASES:
        built.append((tag, group, desc, builder(), expect))
    all_pkgs = [PKG] + [p for _, _, _, p, _ in built]

    pc = {os.path.basename(p): pc_verify(p) for p in all_pkgs}
    ja = java_probe(all_pkgs)

    print("=" * 112)
    print("第三轮 Bug 实证 · PC frp_tool.verify  vs  App Frp.verify（Java SE 真跑）")
    print("expect = 修复后应得到的结论；修前与之不符即坐实 BUG")
    print("=" * 112)
    print("%-22s %-8s %-9s %-9s %-7s %-9s %s" %
          ("用例", "组", "PC", "App", "一致", "期望", "判定"))
    print("-" * 112)

    npass = nfail = 0
    group_stat = {}

    def row(tag, group, desc, path, expect):
        nonlocal npass, nfail
        k = os.path.basename(path)
        p, j = pc.get(k, "?"), ja.get(k, "?")
        same = "是" if p == j else "**否**"
        ok = (p == expect and j == expect)
        if ok:
            npass += 1
        else:
            nfail += 1
        st = group_stat.setdefault(group, [0, 0])
        st[0 if ok else 1] += 1
        verdict = "PASS" if ok else (
            "BUG 放行" if "ACCEPT" in (p, j) else "BUG 两端不一致/误拒")
        print("%-22s %-8s %-9s %-9s %-7s %-9s %s" %
              (tag, group, p, j, same, expect, verdict))

    row("BASE_合法包", "基准", "未篡改示范包", PKG, "ACCEPT")
    for tag, group, desc, path, expect in built:
        row(tag, group, desc, path, expect)
    print("\n校验器回归: %d PASS / %d FAIL" % (npass, nfail))
    for g in sorted(group_stat):
        a, b = group_stat[g]
        print("  %-12s %d PASS / %d FAIL" % (g, a, b))

    # ---------------- C 组工具链 / 链路实证 ----------------
    print("\n" + "=" * 112)
    print("C 组 · 工具链与链路实证")
    print("=" * 112)
    c_ok = True

    # C1 inspect 畸形 manifest
    bad = c1_build()
    r = subprocess.run([sys.executable, os.path.join(ROOT, "frp_tool.py"), "inspect", bad],
                       capture_output=True, text=True)
    crashed = r.returncode != 0 and "Traceback" in r.stderr
    print("  [C1] frp_tool.py inspect 畸形 manifest: %s" %
          ("未捕获异常崩溃 -> BUG" if crashed else "已友好报错 ✔"))
    if crashed:
        c_ok = False
        print("       " + r.stderr.strip().splitlines()[-1][:100])

    # C2 extract 符号链接逃逸
    dest = os.path.join(TMP, "extract_dest")
    escaped = os.path.join(TMP, "escaped")
    shutil.rmtree(dest, ignore_errors=True)
    shutil.rmtree(escaped, ignore_errors=True)
    os.makedirs(escaped)
    os.makedirs(dest)
    os.symlink(escaped, os.path.join(dest, "payload"))
    r = subprocess.run([sys.executable, os.path.join(ROOT, "frp_tool.py"),
                        "extract", PKG, dest], capture_output=True, text=True)
    leaked = os.path.isfile(os.path.join(escaped, "e"))
    print("  [C2] extract 目标目录内预置符号链接 payload -> %s: %s" %
          (escaped, "物料被写出 dest 之外 -> BUG" if leaked else "已阻断 ✔"))
    if leaked:
        c_ok = False
        print("       逃逸文件: " + ", ".join(sorted(os.listdir(escaped))[:5]))

    # C3 TOCTOU
    evil = c3_build()
    live = os.path.join(TMP, "live.frp")
    dir3 = os.path.join(TMP, "filesdir_toc")
    shutil.rmtree(dir3, ignore_errors=True)
    os.makedirs(dir3)
    r = subprocess.run(["java", "-cp", JCLASSES + ":" + JTEST + ":" + JAR,
                        "TocProbe", PKG, evil, live, dir3, "6"],
                       capture_output=True, text=True, timeout=300)
    line = (r.stdout or "").strip().splitlines()[-1] if (r.stdout or "").strip() else "(无输出)"
    mm = 0
    if "mismatch=" in line:
        mm = int(line.split("mismatch=")[1].split()[0])
    print("  [C3] install 两次独立打开 ZIP（中途原子替换包）: %s" %
          ("落盘内容与校验内容不一致 -> BUG" if mm > 0 else "未复现/已修复"))
    print("       " + line + ("  " + (r.stderr or "")[:200] if r.returncode else ""))
    if mm > 0:
        c_ok = False

    # C4 build 沿用旧 assertions
    src4 = c4_build()
    out4 = os.path.join(TMP, "C4_build_selfassert.frp")
    r = subprocess.run([sys.executable, os.path.join(ROOT, "frp_tool.py"),
                        "build", src4, out4], capture_output=True, text=True)
    built_ok = r.returncode == 0
    print("  [C4] build 换掉符号表但沿用模板 kallsyms_lines=1: %s" %
          ("产出「校验通过但设备端必挂」的包 -> BUG" if built_ok else "已被 build 拦截 ✔"))
    if built_ok:
        c_ok = False
        print("       " + (r.stdout or "").strip().splitlines()[-1][:100])

    print("\nC 组判定: " + ("全部通过 ✔" if c_ok else "存在失败 ✘"))
    print("\n总判定: " + ("全部通过 ✔" if nfail == 0 and c_ok else "存在失败 ✘"))
    print("用例包保留在: " + TMP)
    return 0 if (nfail == 0 and c_ok) else 1


if __name__ == "__main__":
    sys.exit(main())
