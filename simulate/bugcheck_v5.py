#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
第五轮 Bug 实证 —— 主题「校验盲区：第二份 JSON 与白名单文档」。

前四轮依次覆盖：
  v21 畸形输入崩溃 / 释放误报
  v22 格式自洽但违反整包语义（role↔dest 绑定、物料互绑、重复条目）
  v23 规则自证 / 跨端一致性 / TOCTOU / 工具链
  v24 ZIP 容器层（CRC / BOM / 深嵌套 / 数字字面量 / 伪目录 / 体积）+ 运行时状态机

本轮换的角度：**校验器根本没覆盖到的包内成员**。
  - manifest.json 有 manifestGuard（BOM / 非法 UTF-8 / 重复键 / 深度），
    但 offsets/offsets.json 是第二份独立 JSON，直接 new JSONObject() 解析，零预检。
  - PC 端 zf.testzip() 校验【所有】条目的 CRC；App 端只在 read() 里对
    【被读取的条目】算 CRC，而白名单文档 README.md 从来不被任何一端读取。
  - PC parse_num 用 Python 无限精度 int；App parseNumOk 只认 Integer/Long，
    超 2^63-1 的 JSON 整数在 org.json 里变成 Double/BigDecimal -> 两端相反。

交叉跑：PC frp_tool.verify  +  App Frp.verify（纯 Java SE 真跑，org.json 用
android-all-13.jar 真实现）。每个包单独起一次 JVM，防止用例之间互相污染。

用法：python3 simulate/bugcheck_v5.py
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
TMP = "/tmp/frp_bugcheck_v5"
JCLASSES = os.path.join(TMP, "classes")
JTEST = os.path.join(TMP, "test")

sys.path.insert(0, ROOT)
import frp_tool  # noqa: E402


# ---------------------------------------------------------------- 构造工具

def load(name, pkg=PKG):
    return zipfile.ZipFile(pkg).read(name)


def mutate(tag, changes=None, mm=None, drop=None, extra=None, raw_manifest=None):
    """changes: {条目名: 新 bytes}；mm: manifest 变体函数；extra: 追加条目。"""
    out = os.path.join(TMP, tag + ".frp")
    changes = changes or {}
    with zipfile.ZipFile(PKG) as src, zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as dst:
        for it in src.infolist():
            if drop and it.filename in drop:
                continue
            b = src.read(it.filename)
            if it.filename == "manifest.json":
                if raw_manifest is not None:
                    b = raw_manifest
                else:
                    m = json.loads(b)
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


def patch_field(path, entry, off, value, width=4):
    """改【中央目录】里某个条目的字段：off=16 -> CRC，off=24 -> 解压后 size。
    只改字段、不动数据，用于制造「PC 查得出 / App 读不到」的分歧。"""
    d = bytearray(open(path, "rb").read())
    i = 0
    hit = 0
    while True:
        i = d.find(b"PK\x01\x02", i)
        if i < 0:
            break
        fnlen = int.from_bytes(d[i + 28:i + 30], "little")
        exlen = int.from_bytes(d[i + 30:i + 32], "little")
        cmlen = int.from_bytes(d[i + 32:i + 34], "little")
        name = bytes(d[i + 46:i + 46 + fnlen]).decode("utf-8", "replace")
        if name == entry:
            d[i + off:i + off + width] = value.to_bytes(width, "little")
            hit += 1
        i += 46 + fnlen + exlen + cmlen
    open(path, "wb").write(bytes(d))
    return hit


CASES = []


def case(tag, group, desc, builder, note):
    CASES.append((tag, group, desc, builder, note))


# ---------------------------------------------------------------- G 组：offsets.json 盲区

def g1():
    # offsets.json 是第二份 JSON，App 直接 new String(bytes,"UTF-8") + new JSONObject，
    # 没有 manifestGuard 的严格 UTF-8 解码；Java String 会把非法字节替换成 U+FFFD 并继续解析。
    raw = load("offsets/offsets.json")
    bad = raw.replace(b'"series": "5.4"', b'"series": "\xff.4"', 1)
    assert bad != raw, "G1 替换未命中"
    return mutate("G1_offsets_bad_utf8", changes={"offsets/offsets.json": bad})


case("G1_offsets_bad_utf8", "G offsets 盲区",
     "offsets.json 的 series 值塞入非法 UTF-8 字节 0xFF（CRC 重算正确）",
     g1, "预期：PC 严格 decode 拒绝 / App 替换 U+FFFD 放行")


def g2():
    return mutate("G2_offsets_bom", changes={"offsets/offsets.json":
                  b"\xef\xbb\xbf" + load("offsets/offsets.json")})


case("G2_offsets_bom", "G offsets 盲区",
     "offsets.json 前置 UTF-8 BOM（offsets 无 BOM 预检，对照 manifest 的 E3）",
     g2, "预期：两端都靠解析异常拒绝（对照）")


def g3():
    # 同一对象内两个 kernels 键：前一个空数组、后一个合法 11 内核。
    # org.json 与 json.loads 都是 last-wins -> 都解析到合法表 -> 都放行。
    raw = load("offsets/offsets.json").decode("utf-8")
    idx = raw.index('"kernels"')
    bad = raw[:idx] + '"kernels": [],\n  ' + raw[idx:]
    return mutate("G3_offsets_dup_key", changes={"offsets/offsets.json": bad.encode()})


case("G3_offsets_dup_key", "G offsets 盲区",
     "offsets.json 放两个 kernels 键（前空数组 / 后合法），歧义 JSON",
     g3, "预期：两端都 ACCEPT —— 应拒未拒，且与 manifest 同类已拒绝不对称")


def g4():
    raw = load("offsets/offsets.json").decode("utf-8").rstrip()
    junk = '"junk": ' + "[" * 5000 + "0" + "]" * 5000
    return mutate("G4_offsets_deep", changes={"offsets/offsets.json":
                  (raw[:-1] + ",\n  " + junk + "\n}").encode()})


case("G4_offsets_deep", "G offsets 盲区",
     "offsets.json 追加 5000 层嵌套 junk（无深度预检，靠解析器异常兜底）",
     g4, "预期：两端 REJECT（App catch Throwable / PC RecursionError，对照）")


def g5():
    o = json.loads(load("offsets/offsets.json"))
    # Python json.loads 认 NaN / Infinity，org.json 不认裸字面量
    o["kernels"][0]["offsets"]["off_init_cred"] = float("nan")
    raw = json.dumps(o, ensure_ascii=False, indent=2, allow_nan=True).encode()
    return mutate("G5_offsets_nan", changes={"offsets/offsets.json": raw})


case("G5_offsets_nan", "G offsets 盲区",
     "offsets.json 偏移值写成裸 NaN 字面量（Python 解析成功 / org.json 抛异常）",
     g5, "预期：两端 REJECT（路径不同，对照）")


def g6():
    # 2^64-1：PC 无限精度 int，parse_num 上界 0xFFFFFFFFFFFFFFFF -> ACCEPT；
    # org.json 解析成 Double/BigDecimal，parseNumOk 不认 -> REJECT。
    o = json.loads(load("offsets/offsets.json"))
    o["kernels"][0]["offsets"]["off_init_cred"] = 18446744073709551615
    raw = json.dumps(o, ensure_ascii=False, indent=2).encode()
    return mutate("G6_offsets_bigint", changes={"offsets/offsets.json": raw})


case("G6_offsets_bigint", "G offsets 盲区",
     "偏移值写成 JSON 整数 18446744073709551615（2^64-1，> Java Long.MAX）",
     g6, "预期：PC ACCEPT / App REJECT —— 数值类型跨端分歧")


# ---------------------------------------------------------------- H 组：README.md / CRC 盲区

def h1():
    p = mutate("H1_readme_bad_crc")
    patch_field(p, "README.md", 16, 0xDEADBEEF)   # 只改中央目录 CRC，数据不变
    return p


case("H1_readme_bad_crc", "H 白名单盲区",
     "README.md 中央目录 CRC 改坏（数据/sha256 不变）——白名单条目从不被读取",
     h1, "预期：PC testzip 全量拒绝 / App 只查被 read 的条目 -> ACCEPT")


def h2():
    # README 是纯文档，两端都不校验其内容；塞非法 UTF-8 看是否两端一致放行
    return mutate("H2_readme_bad_utf8", changes={"README.md": b"FNE \xff\xfe readme\n"})


case("H2_readme_bad_utf8", "H 白名单盲区",
     "README.md 塞非法 UTF-8 字节（文档不参与运行，观察两端是否一致）",
     h2, "预期：两端都 ACCEPT（低危对照，与 G1 形成反差）")


def h3():
    p = mutate("H3_offsets_bad_crc")
    patch_field(p, "offsets/offsets.json", 16, 0xDEADBEEF)
    return p


case("H3_offsets_bad_crc", "H 白名单盲区",
     "offsets.json CRC 改坏（对照：两端都 read 它 -> 都应拒绝）",
     h3, "预期：两端 REJECT（对照，反证 H1 的盲区正是「未被读取」）")


def h4():
    p = mutate("H4_manifest_bad_crc")
    patch_field(p, "manifest.json", 16, 0xDEADBEEF)
    return p


case("H4_manifest_bad_crc", "H 白名单盲区",
     "manifest.json CRC 改坏（对照：两端都 read 它 -> 都应拒绝）",
     h4, "预期：两端 REJECT（对照）")


def h5():
    # 第四轮 E8 回归：真实 24MB README，ZIP 头声明也是 24MB -> sizeOk 拒绝
    return mutate("H5_readme_24mb", changes={"README.md": b"R" * (24 * 1024 * 1024)})


case("H5_readme_24mb", "H 白名单盲区",
     "README.md 换成真实 24MB（第四轮 E8 回归，ZIP 头声明同样为 24MB）",
     h5, "预期：两端 REJECT（体积上限，回归对照）")


def h6():
    # zip bomb 变体：真实 6MB，但把【中央目录声明的解压后 size】伪造成 100。
    # verifyZip 用 ze.getSize()（声明值）算体积 -> 通过；README 不被 read -> 不触发流式上限；
    # install 落盘 getInputStream 按 deflate 流解压全量 -> 写出 6MB 且无上限。
    p = mutate("H6_readme_fake_size", changes={"README.md": b"R" * (6 * 1024 * 1024)})
    patch_field(p, "README.md", 24, 100)   # CRC 保持真实 6MB 数据的 CRC
    return p


case("H6_readme_fake_size", "H 白名单盲区",
     "README 真实 6MB 但中央目录声明 size 伪造成 100（zip bomb 白名单条目）",
     h6, "预期：PC testzip CRC 不符拒绝 / App 信声明值放行")


# ---------------------------------------------------------------- I 组：数值边界回归（验证 INT_MAX 收紧未引入新分歧）

def set_offset(tag, value):
    o = json.loads(load("offsets/offsets.json"))
    o["kernels"][0]["offsets"]["off_init_cred"] = value
    nb = json.dumps(o, ensure_ascii=False, indent=2).encode()
    return mutate(tag, {"offsets/offsets.json": nb})


case("I1_long_max_int", "I 数值边界",
     "偏移值写 JSON 整数 Long.MAX(9223372036854775807)（合法边界，两端应一致放行）",
     lambda: set_offset("I1_long_max_int", 9223372036854775807),
     "预期：两端 ACCEPT（PC int 分支 / App Long 分支）")
case("I2_u64_hex_str", "I 数值边界",
     '偏移值写 16 位十六进制字符串 "0xFFFFFFFFFFFFFFFF"（官方同类，两端应一致放行）',
     lambda: set_offset("I2_u64_hex_str", "0xFFFFFFFFFFFFFFFF"),
     "预期：两端 ACCEPT（字符串分支不受 INT_MAX 影响）")
case("I3_over_u64_int", "I 数值边界",
     "偏移值写 JSON 整数 2^64(18446744073709551616)（双超界，两端应一致拒绝）",
     lambda: set_offset("I3_over_u64_int", 18446744073709551616),
     "预期：两端 REJECT")


# 修后每个用例应收敛到的结论。H2 是「白名单纯文档不参与运行」的低危一致放行，
# I1/I2 是合法边界一致放行；其余一律应拒绝。判定「一致」还不够，必须同时等于期望。
EXPECT_REJECT = {
    "G1_offsets_bad_utf8", "G2_offsets_bom", "G3_offsets_dup_key", "G4_offsets_deep",
    "G5_offsets_nan", "G6_offsets_bigint", "H1_readme_bad_crc", "H3_offsets_bad_crc",
    "H4_manifest_bad_crc", "H5_readme_24mb", "H6_readme_fake_size", "I3_over_u64_int",
}


def expect(tag):
    return "REJECT" if tag in EXPECT_REJECT else "ACCEPT"


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
public class FrpProbe5 {
    public static void main(String[] a) {
        try {
            Frp.Result r = Frp.verify(new File(a[0]));
            System.out.println((r.ok ? "ACCEPT" : "REJECT"));
        } catch (Throwable t) {
            System.out.println("CRASH " + t.getClass().getName());
        }
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
    javac(PROBE_JAVA, "FrpProbe5", JCLASSES + ":" + JAR, JTEST)


def java_probe(path, xmx=None, timeout=90):
    cp = JCLASSES + ":" + JTEST + ":" + JAR
    cmd = ["java"] + (["-Xmx" + xmx] if xmx else []) + ["-cp", cp, "FrpProbe5", path]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
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
    for tag, group, desc, builder, note in CASES:
        try:
            built.append((tag, group, desc, builder(), note))
        except Exception as e:
            print("构造失败 %s: %s: %s" % (tag, type(e).__name__, e))

    print("=" * 118)
    print("第五轮：校验盲区（offsets.json 第二份 JSON / README.md 白名单文档）—— PC 与 App 交叉")
    print("=" * 118)
    print("%-24s %-9s %-9s %-6s %-8s %-6s %s" %
          ("用例", "PC", "App", "一致", "期望", "结论", "说明"))
    results = []
    for tag, group, desc, path, note in built:
        p = pc_verify(path)
        j = java_probe(path)
        same = (p == j)
        exp = expect(tag)
        # 真正修好的条件：两端一致，且结论等于期望（不是「两个都放行」就算过）
        good = same and p == exp and j == exp
        results.append((tag, p, j, same, exp, good))
        print("%-24s %-9s %-9s %-6s %-8s %-6s %s" %
              (tag, p, j, "是" if same else "**否**", exp,
               "符合" if good else "**偏离**", note[:30]))

    print("\n---- 逐例明细 ----")
    for tag, group, desc, path, note in built:
        print("  [%s] %s\n      %s\n      %s" % (group, tag, desc, note))

    diff = [t for t, p, j, s, e, g in results if not s]
    off_expect = [t for t, p, j, s, e, g in results if not g]
    print("\n跨端不一致用例: %d -> %s" % (len(diff), ", ".join(diff) if diff else "无"))
    print("未收敛到期望结论: %d -> %s" % (len(off_expect), ", ".join(off_expect) if off_expect else "无"))
    print("判定: %s" % ("全部符合 ✔" if not off_expect else "存在偏离 ✘"))

    # ---------------- H6 install 落盘面复验 ----------------
    # 修前实测：H6 包 install.ok=true，active_pkg/README.md 被写入 6,291,456 B。
    # 修后必须拒绝导入、且已有激活包保持不变（不写白名单 zip bomb）。
    INSTALL_JAVA = r'''
import com.fne.universal.Frp;
import java.io.File;
public class InstProbe5 {
  static void del(File f){ if(f==null||!f.exists())return;
    if(f.isDirectory()){File[]c=f.listFiles();if(c!=null)for(File x:c)del(x);} f.delete(); }
  public static void main(String[] a){
    File good=new File(a[0]), bad=new File(a[1]), dir=new File(a[2]);
    del(new File(dir,"active_pkg")); del(new File(dir,"active_pkg.bak"));
    del(new File(dir,"active_pkg.tmp")); del(new File(dir,".staging"));
    Frp.Result base=Frp.install(good,dir);
    long before=new File(dir,"active_pkg/README.md").length();
    Frp.Result r=Frp.install(bad,dir);
    File rm=new File(dir,"active_pkg/README.md");
    long after=rm.isFile()?rm.length():-1;
    System.out.println("INSTALL base.ok="+base.ok+" bad.ok="+r.ok
      +" readmeBefore="+before+" readmeAfter="+after
      +" (拒绝导入=" +(!r.ok) + ", 原包未变=" +(after==before) + ")");
  }
}
'''
    javac(INSTALL_JAVA, "InstProbe5", JCLASSES + ":" + JAR, JTEST)
    cp = JCLASSES + ":" + JTEST + ":" + JAR
    dirf = os.path.join(TMP, "filesdir_install")
    os.makedirs(dirf, exist_ok=True)
    h6path = dict((t, p) for t, g, d, p, n in built).get("H6_readme_fake_size")
    ri = subprocess.run(["java", "-cp", cp, "InstProbe5", PKG, h6path, dirf],
                        capture_output=True, text=True, timeout=120)
    print("\nH6 install 落盘复验: " + (ri.stdout.strip() or "(无输出)"))
    if ri.returncode:
        print("   stderr: " + (ri.stderr or "")[:300])
    print("用例包保留在: " + TMP)


if __name__ == "__main__":
    main()
