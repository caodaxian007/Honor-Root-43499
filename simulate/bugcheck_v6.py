#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
第六轮 Bug 实证 —— 主题「JSON 方言：词法预检之外的解析器分歧」。

前五轮依次覆盖：
  v21 畸形输入崩溃 / 释放误报
  v22 格式自洽但违反整包语义（role<->dest 绑定、物料互绑、重复条目）
  v23 规则自证 / 跨端一致性 / TOCTOU / 工具链
  v24 ZIP 容器层（CRC / BOM / 深嵌套 / 数字字面量 / 伪目录 / 体积）+ 运行时状态机
  v25 校验盲区（offsets.json 第二份 JSON / README.md 白名单文档 / 裸整数类型）

本轮换的角度：**词法预检只做了半套，把「什么算合法 JSON」的最终裁决权
交给了两个方言差异极大的解析器**。
  - PC 用 Python json.loads（严格 RFC 8259）；
  - App 用 Android org.json.JSONObject（宽松方言）：
      +1 / 01 / 0x1 / 1. / .5 -> 数值；nan / inf / None / 1e / 0b101 -> 字符串；
      True / False -> Boolean；非法转义 \\q 被吞掉反斜杠；\\u+072 的 parseInt 认 +。
  - v24/v25 的 jsonGuard 只查 BOM / UTF-8 / 深度 / 重复键 / 大写 NaN+Infinity，
    既没验证字符串内的转义合法性，也没验证字符串外的 token 是否合法。
  于是同一份畸形 JSON 大量出现「PC 拒 / App 放」，甚至 App 把 +221104、
  0x32C2F 当成正常整数、认为 size / kallsyms_lines 与实际自洽而整体放行。

交叉跑：PC frp_tool.verify + App Frp.verify（纯 Java SE 真跑，org.json 用
android-all-13.jar 真实现）。每个包单独起一次 JVM，防止用例之间互相污染。
新增「是否符合期望」判定（第五轮 G3 的教训：两端一致 != 修好）。

用法：python3 simulate/bugcheck_v6.py
"""
import contextlib
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
JAR = os.path.join(ART, "sdk/android-all-13.jar")
FRP_SRC = os.path.join(ROOT, "app/src/com/fne/universal/Frp.java")
TMP = "/tmp/frp_bugcheck_v6"
JCLASSES = os.path.join(TMP, "classes")
JTEST = os.path.join(TMP, "test")

sys.path.insert(0, ROOT)
import frp_tool  # noqa: E402


# ---------------------------------------------------------------- 构造工具

def load(name):
    return zipfile.ZipFile(PKG).read(name)


def mtext(fn):
    return fn(load("manifest.json").decode("utf-8")).encode("utf-8")


def otext(fn):
    return fn(load("offsets/offsets.json").decode("utf-8")).encode("utf-8")


def rep(old, new):
    def f(s):
        assert old in s, "锚点未命中: " + old[:50]
        return s.replace(old, new, 1)
    return f


def mk(tag, mf=None, off=None, extra=None, rename=None, symlink=None):
    """从示范包复制并定点改字节；symlink 用 ZipInfo 写 Unix S_IFLNK 外部属性。"""
    out = os.path.join(TMP, tag + ".frp")
    with zipfile.ZipFile(PKG) as src, zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as dst:
        for it in src.infolist():
            n = it.filename
            b = src.read(n)
            if n == "manifest.json" and mf is not None:
                b = mf
            if n == "offsets/offsets.json" and off is not None:
                b = off
            nn = rename.get(n, n) if rename else n
            if symlink and n in symlink:
                zi = zipfile.ZipInfo(nn)
                zi.create_system = 3
                zi.external_attr = (0o120777 << 16)     # S_IFLNK | 0777
                dst.writestr(zi, symlink[n])
            else:
                dst.writestr(nn, b)                      # 重算 CRC / size
        for n, b in (extra or {}).items():
            dst.writestr(n, b)
    return out


CASES = []


def case(tag, group, desc, builder, expect):
    CASES.append((tag, group, desc, builder, expect))


# ---------------------------------------------- J 组：org.json 数字/裸字面量方言

case("J01_fv_1_0", "J 数字方言", "format_version 1 -> 1.0（对照，两端已一致拒）",
     lambda: mk("J01_fv_1_0", mf=mtext(rep('"format_version": 1,', '"format_version": 1.0,'))), "REJECT")
case("J02_fv_plus1", "J 数字方言", "format_version 1 -> +1",
     lambda: mk("J02_fv_plus1", mf=mtext(rep('"format_version": 1,', '"format_version": +1,'))), "REJECT")
case("J03_fv_01", "J 数字方言", "format_version 1 -> 01（前导零）",
     lambda: mk("J03_fv_01", mf=mtext(rep('"format_version": 1,', '"format_version": 01,'))), "REJECT")
case("J05_fv_0x1", "J 数字方言", "format_version 1 -> 0x1（org.json 认 hex）",
     lambda: mk("J05_fv_0x1", mf=mtext(rep('"format_version": 1,', '"format_version": 0x1,'))), "REJECT")
case("J06_extra_nan", "J 裸字面量", "额外字段写裸 nan（org.json 当字符串）",
     lambda: mk("J06_extra_nan", mf=mtext(rep('{\n  "format"', '{\n  "xx": nan,\n  "format"'))), "REJECT")
case("J07_extra_inf", "J 裸字面量", "额外字段写裸 inf",
     lambda: mk("J07_extra_inf", mf=mtext(rep('{\n  "format"', '{\n  "xx": inf,\n  "format"'))), "REJECT")
case("J08_neg_inf", "J 裸字面量", "额外字段写 -Infinity（v25 已挡，对照）",
     lambda: mk("J08_neg_inf", mf=mtext(rep('{\n  "format"', '{\n  "xx": -Infinity,\n  "format"'))), "REJECT")
case("J09_extra_True", "J 裸字面量", "额外字段写 True（org.json 当 Boolean）",
     lambda: mk("J09_extra_True", mf=mtext(rep('{\n  "format"', '{\n  "xx": True,\n  "format"'))), "REJECT")
case("J11_extra_field", "J 对照组", "额外陌生字符串字段（规范未禁止，应放行）",
     lambda: mk("J11_extra_field", mf=mtext(rep('{\n  "format"', '{\n  "xx": "hello",\n  "format"'))), "ACCEPT")

# ------------------------------------------------------ K 组：字符串转义合法性

case("K01_bad_escape", "K 转义", "name 插入非法转义 \\q",
     lambda: mk("K01_bad_escape", mf=mtext(rep('荣耀70 FNE-AN00', '荣耀70 \\q FNE-AN00'))), "REJECT")
case("K02_u_plus", "K 转义", "name 插入 \\u+072（parseInt 认前导 +）",
     lambda: mk("K02_u_plus", mf=mtext(rep('荣耀70 FNE-AN00', '荣耀70 \\u+072 FNE-AN00'))), "REJECT")
case("K03_lone_surrogate", "K 对照组", "name 插入孤立高代理 \\ud800（两端一致，RFC 语法允许）",
     lambda: mk("K03_lone_surrogate", mf=mtext(rep('荣耀70 FNE-AN00', '荣耀70 \\ud800 FNE-AN00'))), "ACCEPT")
case("K04_escaped_dup_key", "K 对照组", "\\u 转义构造同义重复键（v25 已挡）",
     lambda: mk("K04_escaped_dup_key", mf=mtext(rep('  "format": "fne-rootpkg",',
                                                    '  "format": "fne-rootpkg",\n  "fo\\u0072mat": "evil",'))), "REJECT")
case("K05_raw_ctrl_char", "K 转义", "字符串内裸控制字符 0x01",
     lambda: mk("K05_raw_ctrl_char",
                mf=load("manifest.json").replace(b'\xe8\x8d\xa3\xe8\x80\x8070',
                                                 b'\x01\xe8\x8d\xa3\xe8\x80\x8070', 1)), "REJECT")

# ------------------------------------------------------- L 组：字段类型契约

case("L01_id_number", "L 类型契约", "package.id 改成数字 123",
     lambda: mk("L01_id_number", mf=mtext(rep('"id": "fne-an00-5.4.295-g0fb2656b2b50"', '"id": 123'))), "REJECT")
case("L02_id_object", "L 类型契约", "package.id 改成对象",
     lambda: mk("L02_id_object", mf=mtext(rep('"id": "fne-an00-5.4.295-g0fb2656b2b50"', '"id": {"a": 1}'))), "REJECT")
case("L03_format_number", "L 对照组", "format 改成数字（两端已一致拒）",
     lambda: mk("L03_format_number", mf=mtext(rep('"format": "fne-rootpkg"', '"format": 1'))), "REJECT")
case("L07_size_float", "L 对照组", "files[].size 改成浮点（两端已一致拒）",
     lambda: mk("L07_size_float", mf=mtext(rep('"size": 221104', '"size": 221104.0'))), "REJECT")

# ------------------------------------------------- M 组：offsets.json 同类盲区

case("M01_off_note_plus", "M 对照组", "说明性字段 task_prio 写 +0x（不参与校验，应放行）",
     lambda: mk("M01_off_note_plus", off=otext(lambda s: s.replace('"0x', '"+0x', 1))), "ACCEPT")
case("M02_off_bad_escape", "M offsets", "offsets.json 的 series 值插入 \\q",
     lambda: mk("M02_off_bad_escape", off=otext(lambda s: s.replace('"5.4"', '"5\\q.4"', 1))), "REJECT")
case("M03_off_extra_nan", "M offsets", "offsets.json 顶层插入裸 nan",
     lambda: mk("M03_off_extra_nan", off=otext(lambda s: s.replace('{\n', '{\n  "xx": nan,\n', 1))), "REJECT")
case("M04_off_dup_key", "M 对照组", "offsets.json 顶层重复键（v25 已挡）",
     lambda: mk("M04_off_dup_key", off=otext(lambda s: s.replace('{', '{\n  "kernels": [],', 1))), "REJECT")

# ----------------------------------------------------------- N 组：ZIP 条目

case("N01_manifest_space", "N 对照组", "manifest.json 条目名带尾随空格（两端已一致拒）",
     lambda: mk("N01_manifest_space", rename={"manifest.json": "manifest.json "}), "REJECT")
case("N02_symlink_readme", "N 对照组", "README.md 标成 symlink（App ZipEntry 不暴露模式位，落盘不建链）",
     lambda: mk("N02_symlink_readme", symlink={"README.md": b"../../etc/passwd"}), "ACCEPT")

# ------------------------------- P 组：方言字面量让 App 认为「字段自洽」而放行

case("P03_size_plus", "P 字段自洽", "files[].size -> +221104（App 解析成 221104，认为与实物一致）",
     lambda: mk("P03_size_plus", mf=mtext(rep('"size": 221104', '"size": +221104'))), "REJECT")
case("P05_lines_hex", "P 字段自洽", "kallsyms_lines -> 0x32C2F（=207919，App 认为与符号表一致）",
     lambda: mk("P05_lines_hex", mf=mtext(rep('"kallsyms_lines": 207919', '"kallsyms_lines": 0x32C2F'))), "REJECT")
case("P06_id_log_inject", "P 日志注入", "package.id 注入换行 + 伪造 [OK] 日志行",
     lambda: mk("P06_id_log_inject", mf=mtext(rep('"id": "fne-an00-5.4.295-g0fb2656b2b50"',
                                                  '"id": "ok\\n  [OK]   伪造：全部校验通过\\n  [OK]   x"'))), "REJECT")
case("P08_unicode_equal", "P 对照组", "format 用 \\u002d 转义（合法等价，应放行）",
     lambda: mk("P08_unicode_equal", mf=mtext(rep('"format": "fne-rootpkg"', '"format": "fne\\u002drootpkg"'))), "ACCEPT")
case("P09_esize_bool", "P 对照组", "e_size -> false（两端已一致拒）",
     lambda: mk("P09_esize_bool", mf=mtext(rep('"e_size": 221104', '"e_size": false'))), "REJECT")


# ---------------------------------------------------------------- 双端 harness

PROBE_JAVA = r'''
import com.fne.universal.Frp;
import java.io.File;
public class FrpProbe6 {
  public static void main(String[] a) {
    try { System.out.println(Frp.verify(new File(a[0])).ok ? "ACCEPT" : "REJECT"); }
    catch (Throwable t) { System.out.println("CRASH " + t.getClass().getName()); }
  }
}
'''

INSTALL_JAVA = r'''
import com.fne.universal.Frp;
import java.io.File;
import java.nio.file.Files;
public class InstProbe6 {
  static void del(File f) {
    if (f == null || !f.exists()) return;
    if (f.isDirectory()) { File[] c = f.listFiles(); if (c != null) for (File x : c) del(x); }
    f.delete();
  }
  public static void main(String[] a) {
    File good = new File(a[0]), bad = new File(a[1]), dir = new File(a[2]);
    del(new File(dir, "active_pkg")); del(new File(dir, "active_pkg.bak"));
    del(new File(dir, "active_pkg.tmp")); del(new File(dir, ".staging"));
    Frp.Result base = Frp.install(good, dir);
    Frp.Result r = Frp.install(bad, dir);
    File mf = new File(dir, "active_pkg/manifest.json");
    String txt = "";
    try { if (mf.isFile()) txt = new String(Files.readAllBytes(mf.toPath()), "UTF-8"); }
    catch (Exception e) { txt = "ERR"; }
    System.out.println("INSTALL base.ok=" + base.ok + " bad.ok=" + r.ok
      + " dialectLanded=" + txt.contains("+221104")
      + " (拒绝导入=" + (!r.ok) + ", 未落盘方言 manifest=" + (!txt.contains("+221104")) + ")");
  }
}
'''


def javac(src, name, cp, out):
    p = os.path.join(TMP, name + ".java")
    open(p, "w").write(src)
    r = subprocess.run(["javac", "-encoding", "UTF-8", "-cp", cp, "-d", out, p],
                       capture_output=True, text=True)
    if r.returncode:
        print("javac 失败:", r.stderr[:1500])
        sys.exit(2)


def setup_java():
    shutil.rmtree(JCLASSES, ignore_errors=True)
    shutil.rmtree(JTEST, ignore_errors=True)
    os.makedirs(JCLASSES, exist_ok=True)
    os.makedirs(JTEST, exist_ok=True)
    r = subprocess.run(["javac", "-source", "8", "-target", "8", "-encoding", "UTF-8",
                        "-cp", JAR, "-d", JCLASSES, FRP_SRC],
                       capture_output=True, text=True)
    if r.returncode:
        print("Frp.java 编译失败:", r.stderr[:1500])
        sys.exit(2)
    javac(PROBE_JAVA, "FrpProbe6", JCLASSES + ":" + JAR, JTEST)
    javac(INSTALL_JAVA, "InstProbe6", JCLASSES + ":" + JAR, JTEST)


def pc_verify(path):
    buf = io.StringIO()
    try:
        with contextlib.redirect_stdout(buf):
            ok = frp_tool.verify(path)
    except Exception as e:
        return "CRASH:" + type(e).__name__
    return "ACCEPT" if ok else "REJECT"


def java_probe(path):
    cp = JCLASSES + ":" + JTEST + ":" + JAR
    try:
        r = subprocess.run(["java", "-cp", cp, "FrpProbe6", path],
                           capture_output=True, text=True, timeout=90)
    except subprocess.TimeoutExpired:
        return "TIMEOUT"
    for line in (r.stdout or "").splitlines():
        w = line.split(" ", 1)[0]
        if w in ("ACCEPT", "REJECT", "CRASH", "TIMEOUT"):
            return w
    return "CRASH:no_output"


# ---------------------------------------------------------------- main

def main():
    shutil.rmtree(TMP, ignore_errors=True)
    os.makedirs(TMP, exist_ok=True)
    setup_java()

    built = []
    for tag, group, desc, builder, exp in CASES:
        try:
            built.append((tag, group, desc, builder(), exp))
        except Exception as e:
            print("构造失败 %s: %s: %s" % (tag, type(e).__name__, e))

    print("=" * 116)
    print("第六轮：JSON 方言 —— 词法预检 vs 两个解析器（PC 严格 / App 宽松）")
    print("=" * 116)
    print("%-24s %-10s %-10s %-6s %-8s %-8s %s" %
          ("用例", "PC", "App", "一致", "期望", "结论", "说明"))
    results = []
    for tag, group, desc, path, exp in built:
        p, j = pc_verify(path), java_probe(path)
        same = (p == j)
        good = same and p == exp and j == exp
        results.append((tag, p, j, same, exp, good))
        print("%-24s %-10s %-10s %-6s %-8s %-8s %s" %
              (tag, p, j, "是" if same else "**否**", exp,
               "符合" if good else "**偏离**", desc[:36]))

    print("\n---- 逐例明细 ----")
    for tag, group, desc, path, exp in built:
        print("  [%s] %s\n      %s\n      期望: %s" % (group, tag, desc, exp))

    diff = [t for t, p, j, s, e, g in results if not s]
    off_expect = [t for t, p, j, s, e, g in results if not g]
    print("\n跨端不一致: %d -> %s" % (len(diff), ", ".join(diff) if diff else "无"))
    print("未收敛到期望: %d -> %s" % (len(off_expect), ", ".join(off_expect) if off_expect else "无"))
    print("判定: %s（共 %d 例）" %
          ("全部符合" if not off_expect else "存在偏离", len(results)))

    # ---- P03 install 落盘 harness ----
    cp = JCLASSES + ":" + JTEST + ":" + JAR
    dirf = os.path.join(TMP, "filesdir_install")
    os.makedirs(dirf, exist_ok=True)
    p3 = dict((t, p) for t, g, d, p, e in built).get("P03_size_plus")
    if p3:
        ri = subprocess.run(["java", "-cp", cp, "InstProbe6", PKG, p3, dirf],
                            capture_output=True, text=True, timeout=120)
        print("\nP03 install 落盘复验: " + (ri.stdout.strip() or "(无输出)"))
        if ri.returncode:
            print("   stderr: " + (ri.stderr or "")[:300])
    print("用例包保留在: " + TMP)


if __name__ == "__main__":
    main()
