#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
第四轮 Bug 实证：前三轮分别测「畸形输入会不会崩」「格式自洽但违反整包语义」
「规则自证 / 跨端一致性 / TOCTOU」。本轮下探两个此前完全没碰的层面：

  E. ZIP 容器 / 编码层 —— CRC 字段、JSON 重复键 / BOM / 超深嵌套、
     数字字面量的两端解析差异、伪目录条目夹带、允许条目的体积、
     NUL / Unicode 条目名、解压尺寸上限。
  F. App 运行时状态机 —— 两次 install 并发、install 与 release 并发、
     sh -n 的 stdin/stderr 死锁与无超时、超大条目在受限堆下的 OOM。

交叉跑：PC frp_tool.verify  +  App Frp.verify（纯 Java SE 真跑，
org.json 用 android-all-13.jar 真实现）。每个包单独起一次 JVM，
避免某个用例把 JVM 拖垮后污染其它用例的结论。

用法：python3 simulate/bugcheck_v4.py
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
TMP = "/tmp/frp_bugcheck_v4"
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


def offset_value(tag, value):
    """把 offsets.json 第 0 条内核的 off_init_cred 改成指定值。"""
    o = json.loads(load("offsets/offsets.json"))
    o["kernels"][0]["offsets"]["off_init_cred"] = value
    nb = json.dumps(o, ensure_ascii=False, indent=2).encode()
    return mutate(tag, {"offsets/offsets.json": nb})


def patch_crc(path, entry, new_crc):
    """把某个条目的「中央目录 CRC」改成错误值（数据本身不变、sha256 不变）。
    Python zipfile.testzip() 用中央目录 CRC 比对解压数据 -> 失败；
    Java ZipFile.getInputStream() 不校验 CRC -> 正常读取。"""
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
            d[i + 16:i + 20] = new_crc.to_bytes(4, "little")
            hit += 1
        i += 46 + fnlen + exlen + cmlen
    open(path, "wb").write(bytes(d))
    return hit


CASES = []


def case(tag, group, desc, builder, expect):
    CASES.append((tag, group, desc, builder, expect))


# ---------------------------------------------------------------- E1 CRC
case("E1_crc_mismatch", "E 容器层",
     "把 payload/e 的中央目录 CRC 改坏（数据/sha256 不变）：PC 查 CRC、App 不查",
     lambda: (lambda p: (patch_crc(p, "payload/e", 0xDEADBEEF), p)[1])(
         mutate("E1_crc_mismatch")), "REJECT")


# ---------------------------------------------------------------- E2 JSON 重复键
def e2():
    raw = load("manifest.json")
    s = raw.decode("utf-8")
    # 在合法 format 之前插一个恶意 format，观察两端取哪个
    s2 = s.replace('"format": "fne-rootpkg"',
                   '"format": "evil-format",\n  "format": "fne-rootpkg"', 1)
    return mutate("E2_dup_json_key", raw_manifest=s2.encode())


case("E2_dup_json_key", "E 容器层",
     'manifest 里两个 "format" 键（前一个 evil，后一个合法），观察两端取值差异',
     e2, "REJECT")


# ---------------------------------------------------------------- E3 BOM
def e3():
    return mutate("E3_bom", raw_manifest=b"\xef\xbb\xbf" + load("manifest.json"))


case("E3_bom", "E 容器层",
     "manifest.json 前置 UTF-8 BOM（Python json.loads 与 Android org.json 行为差异）",
     e3, "REJECT")


# ---------------------------------------------------------------- E4 超深嵌套
def e4():
    raw = load("manifest.json").decode("utf-8").rstrip()
    # 在合法 JSON 末尾追加一个 5000 层嵌套的无用键
    junk = '"junk": ' + "[" * 5000 + "0" + "]" * 5000
    return mutate("E4_deep_json", raw_manifest=(raw[:-1] + ",\n  " + junk + "\n}").encode())


case("E4_deep_json", "E 容器层",
     "manifest 追加 5000 层嵌套数组（递归解析器栈溢出 / 崩溃）",
     e4, "REJECT")


# ---------------------------------------------------------------- E5 数字字面量
for tag, val, desc in [
    ("E5_0b", "0b101", "偏移值写成二进制字面量 0b101"),
    ("E5_0o", "0o17", "偏移值写成八进制字面量 0o17"),
    ("E5_underscore", "1_000", "偏移值写成带下划线 1_000"),
    ("E5_plus_hex", "+0x10", "偏移值写成带正号 +0x10"),
    ("E5_neg_hex", "-0x10", "偏移值写成负十六进制 -0x10"),
    ("E5_huge", "9" * 400, "偏移值写成 400 位十进制巨数（解析成本 / 溢出）"),
]:
    case(tag, "E 容器层", desc, (lambda t=tag, v=val: (lambda: offset_value(t, v))()), "REJECT")


# ---------------------------------------------------------------- E6 伪目录夹带
def e6():
    # ZIP 允许「名字以 / 结尾但带文件内容」的条目；两端都按名字判断为目录，
    # 于是既不进 entryNames/names，也不触发「无未声明条目」检查。
    return mutate("E6_fake_dir_entry", extra={"payload/sneaky/": b"Z" * 4096})


case("E6_fake_dir_entry", "E 容器层",
     '夹带一个带 4KB 内容的伪目录条目 "payload/sneaky/"（两端都当目录跳过）',
     e6, "REJECT")


# ---------------------------------------------------------------- E7 控制字符条目名
def e7():
    # 允许条目 README.md 不参与任何校验；换成含 NUL 的条目名，看两端是否一致
    return mutate("E7_nul_entry", extra={"README\x00.md": b"X" * 64})


case("E7_nul_entry", "E 容器层",
     "夹带含 NUL 字节的条目名 README\\x00.md（文件名合法性 / 两端一致性）",
     e7, "REJECT")


# ---------------------------------------------------------------- E8 README 体积
def e8():
    # README.md 是 allowed 白名单条目，verify 完全不读它，也没有体积上限。
    # 用「替换」而非「追加」：追加会变成重复条目，测到的就不是体积问题了。
    return mutate("E8_huge_readme", changes={"README.md": b"R" * (24 * 1024 * 1024)})


case("E8_huge_readme", "E 容器层",
     "白名单条目 README.md 塞 24MB（无体积上限；PC testzip 全量解压 / App install 全量落盘）",
     e8, "REJECT")


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
public class FrpProbe4 {
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
    javac(PROBE_JAVA, "FrpProbe4", JCLASSES + ":" + JAR, JTEST)


def java_probe(path, xmx=None, timeout=60):
    cp = JCLASSES + ":" + JTEST + ":" + JAR
    cmd = ["java"] + (["-Xmx" + xmx] if xmx else []) + ["-cp", cp, "FrpProbe4", path]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return "TIMEOUT"
    for line in (r.stdout or "").splitlines():
        w = line.split(" ", 1)[0]
        if w in ("ACCEPT", "REJECT", "CRASH", "TIMEOUT"):
            return w
    return "CRASH:no_output"


# ---------------------------------------------------------------- F 组 harness
F1_JAVA = r'''
import com.fne.universal.Frp;
import java.io.*;
public class ConcProbe {
    static String diskId(File dir) {
        try {
            String s = new String(java.nio.file.Files.readAllBytes(
                new File(dir, "active_pkg/manifest.json").toPath()), "UTF-8");
            int p = s.indexOf("\"id\""), c = s.indexOf(':', p);
            int q1 = s.indexOf('"', c + 1), q2 = s.indexOf('"', q1 + 1);
            if (q1 < 0 || q2 < 0) return "CORRUPT";
            return s.substring(q1 + 1, q2);
        } catch (Exception e) { return "MISSING"; }
    }
    /** 激活包必须 10 项 payload 齐全、无 0 字节残片；否则判为「内容损坏」。 */
    static boolean payloadIntact(File dir) {
        File p = new File(dir, "active_pkg/payload");
        File[] fs = p.listFiles();
        if (fs == null || fs.length != 10) return false;
        for (File f : fs) if (!f.isFile() || f.length() == 0) return false;
        return new File(dir, "active_pkg/offsets/offsets.json").isFile();
    }
    public static void main(String[] a) throws Exception {
        File A = new File(a[0]), B = new File(a[1]), dir = new File(a[2]);
        int N = Integer.parseInt(a[3]);
        int lost = 0, corrupt = 0, bothOk = 0, mismatch = 0, errors = 0, baseFail = 0;
        int damaged = 0, oneFail = 0;
        for (int i = 0; i < N; i++) {
            // 贴近真机：先建立「已有激活包」的基线，再模拟用户快速连点两次导入
            del(new File(dir, "active_pkg"));
            del(new File(dir, "active_pkg.bak"));
            del(new File(dir, "active_pkg.tmp"));
            del(new File(dir, ".staging"));
            Frp.Result base = Frp.install(A, dir);
            if (base == null || !base.ok) { baseFail++; continue; }
            final Frp.Result[] rs = new Frp.Result[2];
            final Throwable[] ex = new Throwable[2];
            Thread t1 = new Thread(new Runnable() { public void run() {
                try { rs[0] = Frp.install(A, dir); } catch (Throwable t) { ex[0] = t; }
            }});
            Thread t2 = new Thread(new Runnable() { public void run() {
                try { rs[1] = Frp.install(B, dir); } catch (Throwable t) { ex[1] = t; }
            }});
            t1.start(); t2.start(); t1.join(); t2.join();
            if (ex[0] != null || ex[1] != null) errors++;
            boolean ok1 = rs[0] != null && rs[0].ok, ok2 = rs[1] != null && rs[1].ok;
            if (ok1 && ok2) bothOk++;
            if (ok1 != ok2) oneFail++;
            String id = diskId(dir);
            if ("MISSING".equals(id) || "CORRUPT".equals(id)) lost++;
            if ("CORRUPT".equals(id)) corrupt++;
            if (!payloadIntact(dir)) damaged++;
            if (ok1 && ok2 && !"A".equals(id) && !"B".equals(id)) mismatch++;
        }
        System.out.println("CONC N=" + N + " baseFail=" + baseFail + " bothOk=" + bothOk
            + " oneFail=" + oneFail + " lost=" + lost + " corrupt=" + corrupt
            + " damaged=" + damaged + " mismatch=" + mismatch + " errors=" + errors);
    }
    static void del(File f) {
        if (f == null || !f.exists()) return;
        if (f.isDirectory()) { File[] c = f.listFiles(); if (c != null) for (File x : c) del(x); }
        f.delete();
    }
}
'''


def build_id_pkgs():
    """造两个只有 package.id 不同的合法包 A / B。"""
    out = []
    for tag, ident in (("A", "A"), ("B", "B")):
        m = json.loads(load("manifest.json"))
        m["package"]["id"] = ident
        raw = json.dumps(m, ensure_ascii=False, indent=2).encode()
        p = os.path.join(TMP, "id_" + tag + ".frp")
        with zipfile.ZipFile(PKG) as src, zipfile.ZipFile(p, "w", zipfile.ZIP_DEFLATED) as dst:
            for it in src.infolist():
                dst.writestr(it, raw if it.filename == "manifest.json" else src.read(it.filename))
        out.append(p)
    return out


# ---------------------------------------------------------------- main
def main():
    shutil.rmtree(TMP, ignore_errors=True)
    os.makedirs(TMP, exist_ok=True)
    setup_java()

    built = []
    for tag, group, desc, builder, expect in CASES:
        try:
            built.append((tag, group, desc, builder(), expect))
        except Exception as e:
            print("构造失败 %s: %s: %s" % (tag, type(e).__name__, e))

    print("=" * 108)
    print("第四轮 E 组：ZIP 容器 / 编码层 —— PC 与 App 交叉校验（每包单独 JVM）")
    print("=" * 108)
    print("%-20s %-10s %-10s %-8s %-9s %s" % ("用例", "PC", "App", "一致", "期望", "说明"))
    results = []
    for tag, group, desc, path, expect in built:
        p = pc_verify(path)
        j = java_probe(path)
        same = p == j
        # 判定：ACCEPT 即 BUG（放行）；CRASH/TIMEOUT 也是 BUG（应收敛为 REJECT）
        bad = (p == "ACCEPT" or j == "ACCEPT" or p.startswith("CRASH")
               or j.startswith("CRASH") or j == "TIMEOUT" or not same)
        verdict = "放行/崩溃/不一致" if bad else "两端拒绝"
        print("%-20s %-10s %-10s %-8s %-9s %s" %
              (tag, p, j, "是" if same else "**否**", expect, verdict))
        results.append((tag, p, j, same, bad))

    n_bug = sum(1 for r in results if r[4])
    print("\nE 组坐实: %d/%d" % (n_bug, len(results)))

    # ---------------- F1 并发 ----------------
    print("\n" + "=" * 108)
    print("第四轮 F 组：App 运行时状态机")
    print("=" * 108)
    javac(F1_JAVA, "ConcProbe", JCLASSES + ":" + JAR, JTEST)
    A, B = build_id_pkgs()
    dirf = os.path.join(TMP, "filesdir_conc")
    os.makedirs(dirf, exist_ok=True)
    cp = JCLASSES + ":" + JTEST + ":" + JAR
    r = subprocess.run(["java", "-cp", cp, "ConcProbe", A, B, dirf, "80"],
                       capture_output=True, text=True, timeout=300)
    print("F1 两次 install 并发: " + (r.stdout.strip() or "(无输出)"))
    if r.returncode:
        print("   stderr: " + (r.stderr or "")[:300])

    # ---------------- F3 sh -n 无超时 / 死锁 ----------------
    # 构造 shebang + 大量语法错误行：sh -n 会往 stderr 写海量错误并提前退出
    sh_bad = (b"#!/system/bin/sh\n" + b"if [ ; then\n" * 20000)
    shp = mutate("F3_bad_sh", {"payload/fne_local.sh": sh_bad})
    import time
    t0 = time.time()
    j = java_probe(shp, timeout=25)
    dt = time.time() - t0
    print("F3 畸形大脚本(约 %d KB) sh -n: App=%s 耗时=%.1fs" %
          (len(sh_bad) // 1024, j, dt))

    # ---------------- F4 受限堆下的大条目 ----------------
    # 40MB 全 'a' 的符号表（自洽：补到 >=200000 行），Java read() 全部读进内存
    big = (b"a\n" * 200001) + b"a" * (40 * 1024 * 1024 - 400002)
    bigp = mutate("F4_big_syms", {"payload/fne_syms.txt": big})
    j4 = java_probe(bigp, xmx="64m", timeout=90)
    print("F4 40MB 符号表 + -Xmx64m: App=%s（OOM=未做解压尺寸上限）" % j4)

    # ---------------- F2 install 与 release 并发 ----------------
    # 用两个线程：一个反复 install，一个反复 release，看 release 是否读到半包/抛异常
    F2_JAVA = r'''
import com.fne.universal.Frp;
import java.io.*;
public class RelProbe {
    public static void main(String[] a) throws Exception {
        File A = new File(a[0]), dir = new File(a[1]);
        int N = Integer.parseInt(a[2]);
        final int[] fail = {0}, ex = {0}, ok = {0};
        for (int i = 0; i < N; i++) {
            Thread ti = new Thread(new Runnable() { public void run() {
                try { Frp.install(A, dir); } catch (Throwable t) { synchronized(ex){ex[0]++;} }
            }});
            Thread tr = new Thread(new Runnable() { public void run() {
                try { Frp.Result r = Frp.release(dir);
                      if (r.ok) synchronized(ok){ok[0]++;} else synchronized(fail){fail[0]++;}
                } catch (Throwable t) { synchronized(ex){ex[0]++;} }
            }});
            ti.start(); tr.start(); ti.join(); tr.join();
        }
        System.out.println("F2 install+release 并发 N=" + N + " releaseOk=" + ok[0]
            + " releaseFail=" + fail[0] + " 未捕获异常=" + ex[0]);
    }
}
'''
    javac(F2_JAVA, "RelProbe", JCLASSES + ":" + JAR, JTEST)
    dir2 = os.path.join(TMP, "filesdir_rel")
    os.makedirs(dir2, exist_ok=True)
    r2 = subprocess.run(["java", "-cp", cp, "RelProbe", A, dir2, "30"],
                        capture_output=True, text=True, timeout=300)
    print("F2: " + (r2.stdout.strip() or "(无输出)"))
    if r2.returncode:
        print("   stderr: " + (r2.stderr or "")[:300])

    print("\n用例包保留在: " + TMP)


if __name__ == "__main__":
    main()
