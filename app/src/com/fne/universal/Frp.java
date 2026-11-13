package com.fne.universal;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

/**
 * FNE 通用提权包（.frp）扫描 / 校验 / 原子导入 / 释放。
 *
 * 与 PC 端 frp_tool.py 使用同一套规则（docs/包格式规范.md）。
 *   - 导入单元只能是完整 .frp，界面没有「单换 e / 单换 sh」入口。
 *   - 先解到 staging 全项校验，通过后才备份+原子替换 active_pkg；失败保留原包。
 *   - 首次释放后不再做 md5/尺寸校验（避免历史上「自愈覆盖把 e 写坏」）。
 */
public final class Frp {

    static final String FORMAT = "fne-rootpkg";
    static final int FORMAT_VERSION = 1;
    static final String WORKDIR = "/data/local/tmp/ksu_fne";
    static final String E_PATH = WORKDIR + "/e";
    static final String SD_STAGE = "/sdcard/Download/ksu_fne";
    static final String PKG_DIR = "/sdcard/Download";
    static final String PKG_SUBDIR = "/sdcard/Download/fne_packages";

    // ---- 内置规则（第三轮）：校验基准不再从包内 manifest / offsets.json 自述读取 ----
    static final String OFFSETS_REF = "offsets/offsets.json";
    static final String ENTRY_SCRIPT = "fne_local.sh";
    static final int MIN_KALLSYMS_LINES = 200000;

    // ---- 资源上限（第四轮）：与 frp_tool.py 逐字一致，防 zip bomb / OOM ----
    // 官方示范包实测：13 条目、最大单条目 11,095,147 B、总解压 25,024,800 B、
    // 压缩后 8.8 MB、manifest 4716 B；阈值均留有充分余量。
    static final long MAX_PKG_SIZE = 64L * 1024 * 1024;
    static final int MAX_ENTRIES = 64;
    static final long MAX_ENTRY_SIZE = 16L * 1024 * 1024;
    static final long MAX_TOTAL_SIZE = 48L * 1024 * 1024;
    static final int MAX_MANIFEST_SIZE = 64 * 1024;
    // 第五轮：offsets/offsets.json 是包内第二份独立 JSON，必须与 manifest 一样过词法预检
    // （官方 11 内核表 52,213 B，给 4 MB 余量；同时受 MAX_ENTRY_SIZE 16 MB 兜底）
    static final int MAX_OFFSETS_SIZE = 4 * 1024 * 1024;
    static final int MAX_JSON_DEPTH = 64;
    static final int MAX_SCRIPT_SIZE = 2 * 1024 * 1024;
    /** 5.4 系偏移需求表的 75 个必备字段（与 frp_tool.py OFFSET_FIELDS 逐字一致）。 */
    static final String[] OFFSET_FIELDS = {
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
        "fops_no_iter", "mcast_route", "dm_va_absolute"
    };

    /** 10 个必需角色 -> (释放目标文件名, 权限)。path 固定为 payload/<dest>。 */
    static final String[][] ROLES = {
        {"exploit", "e", "0755"}, {"entry_script", "fne_local.sh", "0755"},
        {"chain_hook", "chain_hook.sh", "0755"}, {"kallsyms", "fne_syms.txt", "0644"},
        {"kernelsu_ko", "kernelsu.ko", "0644"}, {"ksud", "ksud", "0755"},
        {"magiskpolicy", "magiskpolicy", "0755"}, {"load_ko", "load_ko", "0755"},
        {"kmsg_dumper", "kmsg_dumper", "0755"}, {"ksu_rules", "ksu_rules", "0644"}
    };

    public static class Result {
        public boolean ok;
        public List<String> lines = new ArrayList<String>();
        public String id = "", name = "", kernel = "", vermagic = "";
        public int fileCount, offsetCount;
        public void log(boolean good, String msg) {
            lines.add((good ? "  [OK]   " : "  [FAIL] ") + msg);
            if (!good) ok = false;
        }
    }

    private Frp() {}

    // ---------------------------------------------------------------- helpers

    private static String hex(byte[] b) {
        StringBuilder s = new StringBuilder();
        for (int i = 0; i < b.length; i++) {
            String h = Integer.toHexString(b[i] & 0xff);
            if (h.length() == 1) s.append('0');
            s.append(h);
        }
        return s.toString();
    }

    private static String sha256(byte[] b) {
        try { return hex(MessageDigest.getInstance("SHA-256").digest(b)); }
        catch (Exception e) { return ""; }
    }

    private static byte[] read(ZipFile z, String name) throws Exception {
        ZipEntry e = z.getEntry(name);
        if (e == null) return null;
        long declared = e.getSize();
        if (declared < 0 || declared > MAX_ENTRY_SIZE) return null;
        InputStream in = z.getInputStream(e);
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        java.util.zip.CRC32 crc = new java.util.zip.CRC32();
        byte[] buf = new byte[65536];
        int n;
        long total = 0;
        while ((n = in.read(buf)) != -1) {
            total += n;
            // zip 头里的 size 可能是伪造的：边读边卡硬上限，防 OOM（第四轮 F4）
            if (total > MAX_ENTRY_SIZE) { in.close(); return null; }
            crc.update(buf, 0, n);
            out.write(buf, 0, n);
        }
        in.close();
        // Java ZipFile.getInputStream 不校验 CRC，而 PC 端 zipfile 会校验：
        // 不自己算一遍就会出现「PC 崩 / App 放行」的跨端分歧（第四轮 E1）
        long want = e.getCrc();
        if (want >= 0 && crc.getValue() != want) return null;
        return out.toByteArray();
    }

    private static boolean safeName(String n) {
        if (n == null || n.length() == 0) return false;
        if (n.startsWith("/") || n.startsWith("\\") || n.indexOf('\\') >= 0) return false;
        if (n.matches("^[A-Za-z]:.*")) return false;
        String[] parts = n.split("/", -1);
        for (String p : parts) if (p.equals("..")) return false;
        return true;
    }

    private static String str(JSONObject o, String k) {
        if (o == null) return "";
        Object v = o.opt(k);
        // 第六轮：只取真正的 JSON 字符串。org.json 的 optString 会把数字 /
        // 对象 / 数组 / Boolean 用 toString() 转成文本（package.id=123 变 "123"、
        // {} 变 "{}"），让字段类型契约形同虚设（L01/L02）。
        return (v instanceof String) ? (String) v : "";
    }

    /** 自由文本字段：非空、<=256 字符、无控制字符（防日志注入 / UI 伪造，P06）。 */
    private static boolean safeText(String s) {
        if (s == null || s.length() == 0 || s.length() > 256) return false;
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c < 0x20 || c == 0x7f) return false;
        }
        return true;
    }

    private static boolean isMode(String s) {
        return s != null && s.matches("0[0-7]{3}");
    }

    /** 角色白名单查询：返回 {dest, mode}，未知 role 返回 null。 */
    private static String[] roleSpec(String role) {
        for (int i = 0; i < ROLES.length; i++)
            if (ROLES[i][0].equals(role)) return new String[]{ROLES[i][1], ROLES[i][2]};
        return null;
    }

    /**
     * 只接受 JSON 整数：字符串 "1" / 布尔 / null 一律返回 -1。
     * 与 frp_tool.py 的 isinstance(v, int) 对齐，避免同一包两端结论相反。
     */
    private static int strictInt(JSONObject o, String k) {
        if (o == null) return -1;
        Object v = o.opt(k);
        if (v instanceof Integer) return ((Integer) v).intValue();
        if (v instanceof Long) {
            long l = ((Long) v).longValue();
            return (l >= Integer.MIN_VALUE && l <= Integer.MAX_VALUE) ? (int) l : -1;
        }
        return -1;
    }

    /**
     * 与 frp_tool.py 的 parse_num 对齐：偏移字段值必须是可解析的数字
     * （JSON 整数 / 十进制串 / 0x 十六进制串，可带 UuLl 后缀）。
     * null、JSONObject.NULL、布尔、对象/数组、非数字串一律 false。
     */
    private static boolean parseNumOk(Object v) {
        // 与 frp_tool.py parse_num 逐字对齐：只接受非负、无前导 +、无下划线、
        // 长度受限的十进制或 0x 十六进制。旧实现用 BigInteger 与 PC 的 int(s,0)
        // 语法不一致，导致 0b/0o/下划线/+0x/-0x 全部「PC 放行 / App 拒绝」（第四轮 E5）。
        if (v == null || v == JSONObject.NULL || v instanceof Boolean) return false;
        if (v instanceof Integer) return ((Integer) v).intValue() >= 0;
        if (v instanceof Long) return ((Long) v).longValue() >= 0L;
        if (v instanceof String) {
            String s = ((String) v).trim();
            while (s.length() > 0 && "UuLl".indexOf(s.charAt(s.length() - 1)) >= 0)
                s = s.substring(0, s.length() - 1);
            if (s.matches("0[xX][0-9a-fA-F]{1,16}")) return true;
            if (s.matches("[0-9]{1,20}")) return true;
            return false;
        }
        return false;
    }

    /**
     * 通用 JSON 严格词法裁决（第六轮）：manifest.json 与 offsets/offsets.json 共用。
     * 与 frp_tool.py json_guard 逐条对齐：
     * BOM / 非法 UTF-8 / 体积 / 括号嵌套深度 / 同一对象内重复键 / 非标准裸字面量。
     * 前四轮只把它用在 manifest.json 上；offsets/offsets.json 是包内第二份独立
     * JSON，却直接 new JSONObject(new String(bytes,"UTF-8")) —— Java 会把非法字节
     * 替换成 U+FFFD 照常解析、org.json 会吞掉 BOM、重复键取最后一个，于是同一份
     * 畸形 offsets 出现「PC 拒 / App 放行」（第五轮 G1/G2/G3）。
     * 返回 {ok(1/0), reason, decodedText}：decodedText 是严格 UTF-8 解码后的文本，
     * 调用方必须用它构造 JSONObject，杜绝宽松解码替换非法字节。
     */
    private static String[] jsonGuard(byte[] raw, int maxSize) {
        if (raw.length >= 3 && (raw[0] & 0xff) == 0xEF
                && (raw[1] & 0xff) == 0xBB && (raw[2] & 0xff) == 0xBF)
            return new String[]{"0", "含 UTF-8 BOM", ""};
        if (raw.length > maxSize)
            return new String[]{"0", "超过 " + maxSize + " B", ""};
        String s;
        try {
            java.nio.charset.CharsetDecoder dec = java.nio.charset.StandardCharsets.UTF_8
                    .newDecoder()
                    .onMalformedInput(java.nio.charset.CodingErrorAction.REPORT)
                    .onUnmappableCharacter(java.nio.charset.CodingErrorAction.REPORT);
            s = dec.decode(java.nio.ByteBuffer.wrap(raw)).toString();
        } catch (Exception e) {
            return new String[]{"0", "不是合法 UTF-8", ""};
        }
        // 第六轮：严格 RFC 8259 词法裁决（与 frp_tool.py json_guard 逐条对齐）。
        // 第五轮只查 BOM / UTF-8 / 深度 / 重复键 / 大写 NaN+Infinity，把
        // 「什么算合法 JSON」交给了两个方言差异极大的解析器：org.json 会把
        // +1 / 01 / 0x1 当数值、nan / inf / None 当字符串、True 当 Boolean、
        // 非法转义吞掉反斜杠、u 转义的 parseInt 还认前导 +。于是同一份畸形
        // JSON 出现「PC 拒 / App 放」，甚至 App 把 +221104 / 0x32C2F 当成
        // 正常整数、认为 size / kallsyms_lines 自洽而整体放行。
        // 现在在把文本交给 new JSONObject 之前，用确定性状态机统一裁决。
        final String WS = " " + (char) 9 + (char) 10 + (char) 13;
        final String HEX = "0123456789abcdefABCDEF";
        final String ENDCH = WS + ",}]";
        final java.util.regex.Pattern NUM_RE = java.util.regex.Pattern.compile(
                "-?(?:0|[1-9][0-9]*)(?:[.][0-9]+)?(?:[eE][+-]?[0-9]+)?");
        final int VAL = 0, VAL_REQ = 1, KEY = 2, KEY_REQ = 3, COLON = 4, DELIM = 5;
        java.util.ArrayList<java.util.HashSet<String>> stack =
                new java.util.ArrayList<java.util.HashSet<String>>();
        int expect = VAL_REQ;
        int depth = 0;
        int i = 0, n = s.length();
        while (i < n) {
            char c = s.charAt(i);
            if (WS.indexOf(c) >= 0) { i++; continue; }

            // ---- 字符串（键或值）----
            if (c == '"') {
                if (expect != VAL && expect != VAL_REQ && expect != KEY && expect != KEY_REQ)
                    return new String[]{"0", "字符串位置非法 @" + i, ""};
                boolean isKey = (expect == KEY || expect == KEY_REQ);
                i++;
                StringBuilder buf = new StringBuilder();
                boolean closed = false;
                while (i < n) {
                    char ch = s.charAt(i);
                    if (ch == '"') { i++; closed = true; break; }
                    if (ch < 0x20)
                        return new String[]{"0", "字符串内裸控制字符 @" + i, ""};
                    if (ch == 92) {
                        i++;
                        if (i >= n) return new String[]{"0", "转义不完整", ""};
                        char e = s.charAt(i);
                        if (e == 'u') {
                            if (i + 5 > n)
                                return new String[]{"0", "u 转义必须是 4 位十六进制", ""};
                            String h = s.substring(i + 1, i + 5);
                            for (int k = 0; k < 4; k++)
                                if (HEX.indexOf(h.charAt(k)) < 0)
                                    return new String[]{"0", "u 转义必须是 4 位十六进制", ""};
                            buf.append((char) Integer.parseInt(h, 16));
                            i += 5;
                            continue;
                        }
                        switch (e) {
                            case 'b': buf.append((char) 8); break;
                            case 'f': buf.append((char) 12); break;
                            case 'n': buf.append((char) 10); break;
                            case 'r': buf.append((char) 13); break;
                            case 't': buf.append((char) 9); break;
                            case '/': buf.append('/'); break;
                            case '"': buf.append('"'); break;
                            case 92: buf.append((char) 92); break;
                            default:
                                return new String[]{"0", "非法转义 (反斜杠 + " + e + ")", ""};
                        }
                        i++;
                        continue;
                    }
                    buf.append(ch);
                    i++;
                }
                if (!closed) return new String[]{"0", "字符串未闭合", ""};
                if (isKey) {
                    int j = i;
                    while (j < n && WS.indexOf(s.charAt(j)) >= 0) j++;
                    if (j >= n || s.charAt(j) != ':')
                        return new String[]{"0", "对象键后缺少冒号", ""};
                    if (stack.isEmpty() || stack.get(stack.size() - 1) == null)
                        return new String[]{"0", "键出现在数组上下文", ""};
                    java.util.HashSet<String> keys = stack.get(stack.size() - 1);
                    String key = buf.toString();
                    if (keys.contains(key))
                        return new String[]{"0", "JSON 重复键 " + key, ""};
                    keys.add(key);
                    expect = COLON;
                } else {
                    expect = DELIM;
                }
                continue;
            }

            // ---- 容器与分隔符 ----
            if (c == '{') {
                if (expect != VAL && expect != VAL_REQ)
                    return new String[]{"0", "对象位置非法 @" + i, ""};
                stack.add(new java.util.HashSet<String>());
                depth++;
                if (depth > MAX_JSON_DEPTH)
                    return new String[]{"0", "嵌套深度 > " + MAX_JSON_DEPTH, ""};
                expect = KEY;
                i++;
                continue;
            }
            if (c == '[') {
                if (expect != VAL && expect != VAL_REQ)
                    return new String[]{"0", "数组位置非法 @" + i, ""};
                stack.add(null);
                depth++;
                if (depth > MAX_JSON_DEPTH)
                    return new String[]{"0", "嵌套深度 > " + MAX_JSON_DEPTH, ""};
                expect = VAL;
                i++;
                continue;
            }
            if (c == '}') {
                if ((expect != KEY && expect != DELIM) || stack.isEmpty()
                        || stack.get(stack.size() - 1) == null)
                    return new String[]{"0", "对象结束位置非法 @" + i, ""};
                depth--;
                stack.remove(stack.size() - 1);
                expect = DELIM;
                i++;
                continue;
            }
            if (c == ']') {
                if ((expect != VAL && expect != DELIM) || stack.isEmpty()
                        || stack.get(stack.size() - 1) != null)
                    return new String[]{"0", "数组结束位置非法 @" + i, ""};
                depth--;
                stack.remove(stack.size() - 1);
                expect = DELIM;
                i++;
                continue;
            }
            if (c == ':') {
                if (expect != COLON) return new String[]{"0", "冒号位置非法 @" + i, ""};
                expect = VAL_REQ;
                i++;
                continue;
            }
            if (c == ',') {
                if (expect != DELIM || stack.isEmpty())
                    return new String[]{"0", "逗号位置非法 @" + i, ""};
                expect = (stack.get(stack.size() - 1) != null) ? KEY_REQ : VAL_REQ;
                i++;
                continue;
            }

            // ---- 数字：严格 RFC 8259 ----
            if (c == '-' || (c >= '0' && c <= '9')) {
                if (expect != VAL && expect != VAL_REQ)
                    return new String[]{"0", "数字位置非法 @" + i, ""};
                java.util.regex.Matcher m = NUM_RE.matcher(s);
                m.region(i, n);
                if (!m.lookingAt()) return new String[]{"0", "非法数字字面量 @" + i, ""};
                int end = m.end();
                if (end < n && ENDCH.indexOf(s.charAt(end)) < 0)
                    return new String[]{"0", "非法数字字面量（尾部粘连）@" + i, ""};
                i = end;
                expect = DELIM;
                continue;
            }

            // ---- 裸标识符：只允许精确小写 true / false / null ----
            if (c == 't' || c == 'f' || c == 'n') {
                if (expect != VAL && expect != VAL_REQ)
                    return new String[]{"0", "字面量位置非法 @" + i, ""};
                String lit = null;
                String[] cands = {"true", "false", "null"};
                for (int k = 0; k < cands.length; k++)
                    if (s.startsWith(cands[k], i)) { lit = cands[k]; break; }
                if (lit == null)
                    return new String[]{"0", "非标准裸字面量 @" + i, ""};
                int end = i + lit.length();
                if (end < n && ENDCH.indexOf(s.charAt(end)) < 0)
                    return new String[]{"0", "非标准裸字面量（尾部粘连）@" + i, ""};
                i = end;
                expect = DELIM;
                continue;
            }
            return new String[]{"0", "字符串外非法字符 U+"
                    + Integer.toHexString(c) + " @" + i, ""};
        }
        if (depth != 0 || !stack.isEmpty() || expect != DELIM)
            return new String[]{"0", "JSON 结构不完整 / 括号不配对", ""};
        return new String[]{"1", "词法预检通过", s};
    }
    /**
     * 真正的 shell 语法检查：把脚本从 stdin 喂给 sh -n，零临时文件、零执行。
     * PC 端 frp_tool.py 用 subprocess 跑 sh -n；两端用同一个系统 sh 判定，
     * 避免「静态括号/关键字配平」误伤合法脚本（官方 sh 里 case/注释本就不配平）。
     * 真机优先 /system/bin/sh，云电脑 Java SE 回退到 PATH 里的 sh。
     * 没有可用 sh 时返回 false（fail-closed，绝不冒充语法通过）。
     */
    private static boolean shSyntaxOk(byte[] script) {
        if (script == null || script.length > MAX_SCRIPT_SIZE) return false;
        String[] shells = {"/system/bin/sh", "sh"};
        for (String sh : shells) {
            Process p = null;
            try {
                p = Runtime.getRuntime().exec(new String[]{sh, "-n"});
                // 先启动排空线程再写 stdin：sh -n 遇语法错误会往 stderr 写大量
                // 内容并提前退出，若先阻塞在写 stdin、stderr 缓冲又满，就会死锁。
                Thread d1 = drain(p.getErrorStream());
                Thread d2 = drain(p.getInputStream());
                java.io.OutputStream os = p.getOutputStream();
                try { os.write(script); } finally { os.close(); }
                boolean done = p.waitFor(10, java.util.concurrent.TimeUnit.SECONDS);
                if (!done) { p.destroyForcibly(); return false; }
                d1.join(1000); d2.join(1000);
                return p.exitValue() == 0;
            } catch (Throwable t) {
                // 换下一个 sh；waitFor(timeout) / destroyForcibly 在低版本
                // Runtime 上可能不可用，catch Throwable 保证 fail-closed
            } finally {
                if (p != null) p.destroy();
            }
        }
        return false;
    }

    private static Thread drain(final java.io.InputStream in) {
        Thread t = new Thread(new Runnable() {
            public void run() {
                try { byte[] b = new byte[4096]; while (in.read(b) != -1) { } }
                catch (Exception ignored) {}
            }
        });
        t.setDaemon(true);
        t.start();
        return t;
    }

    // ---------------------------------------------------------------- verify

    /** 完整包校验。任一项失败即整体拒绝，不写任何业务文件。 */
    public static Result verify(File pkg) {
        Result r = newResult(pkg);
        if (!r.ok) return r;
        ZipFile z = null;
        try {
            z = new ZipFile(pkg);
            verifyZip(z, r);
        } catch (Throwable e) {
            // 必须兜住 Error：org.json 对超深嵌套抛 StackOverflowError，
            // 只 catch(Exception) 会让它冲出 verify、把导入线程打崩（第四轮 E4）
            r.log(false, "打开包失败: " + e.getClass().getSimpleName() + " " + e.getMessage());
        } finally {
            if (z != null) try { z.close(); } catch (Exception ignored) {}
        }
        r.lines.add(r.ok ? "结论: 完整包校验通过 ✔" : "结论: 拒绝导入 ✘");
        return r;
    }

    private static Result newResult(File pkg) {
        Result r = new Result();
        r.ok = true;
        if (pkg == null || !pkg.isFile()) { r.log(false, "包文件不存在"); return r; }
        r.lines.add("包: " + pkg.getName() + " (" + pkg.length() + " B)");
        r.log(pkg.length() <= MAX_PKG_SIZE,
              "包文件 <= " + MAX_PKG_SIZE + " B（实际 " + pkg.length() + " B）");
        return r;
    }

    /**
     * 第五轮 · 容器层全量校验（对齐 PC 端 zf.testzip() + 真实字节数检查）。
     *
     * 前四轮的 CRC 只在 read() 里、且只对「本次校验会读取的条目」做：manifest.json、
     * offsets/offsets.json、files[] 里 10 个 payload。白名单文档 README.md 从不被
     * read()，于是：
     *   - H1 把 README 的中央目录 CRC 改坏，PC testzip 全量拒绝 / App 完全不查 -> 放行；
     *   - H6 把 README 声明 size 伪造成 100（真实 6MB），verifyZip 的 size/total 都
     *     读 ZipEntry.getSize()（声明值）而被骗过，install 落盘 getInputStream 又会
     *     按 deflate 流写出全部 6MB（zip bomb 落地面）。
     * 这里对每个条目做一次独立流式扫描：算真实 CRC、累计真实解压字节数，与
     * ZipEntry 声明的 CRC / size 逐条比对，任一条不符即整体拒绝；边读边卡硬上限，
     * 不把整条目读进内存，防 OOM。全程用同一个已打开的 ZipFile，无 TOCTOU。
     */
    private static void verifyContainer(ZipFile z, Result r) {
        boolean crcOk = true, sizeMatch = true, bounded = true;
        long realTotal = 0;
        Enumeration<? extends ZipEntry> en = z.entries();
        while (en.hasMoreElements()) {
            ZipEntry ze = en.nextElement();
            long declared = ze.getSize();
            long wantCrc = ze.getCrc();
            InputStream in = null;
            try {
                in = z.getInputStream(ze);
                java.util.zip.CRC32 crc = new java.util.zip.CRC32();
                byte[] buf = new byte[65536];
                long real = 0;
                int n;
                while ((n = in.read(buf)) != -1) {
                    real += n;
                    crc.update(buf, 0, n);
                    if (real > MAX_ENTRY_SIZE) { bounded = false; break; }
                }
                realTotal += real;
                if (declared >= 0 && real != declared) sizeMatch = false;
                if (wantCrc >= 0 && crc.getValue() != wantCrc) crcOk = false;
            } catch (Throwable t) {
                // 打不开 / 解压损坏：与 PC testzip 抛 BadZipFile 一致，收敛为拒绝
                crcOk = false; sizeMatch = false;
            } finally {
                if (in != null) try { in.close(); } catch (Exception ignored) {}
            }
        }
        r.log(bounded, "容器层：所有条目真实解压 <= " + MAX_ENTRY_SIZE + " B（无 zip bomb）");
        r.log(realTotal <= MAX_TOTAL_SIZE,
              "容器层：真实解压总量 <= " + MAX_TOTAL_SIZE + "（实际 " + realTotal + "）");
        r.log(sizeMatch, "容器层：真实解压字节数 == ZIP 头声明 size（防声明伪造）");
        r.log(crcOk, "容器层：全量条目 CRC 正确（含 README.md 等白名单文档）");
    }

    /** 对「已经打开的同一个 ZipFile」做全项校验；install 与 verify 共用，杜绝 TOCTOU。 */
    private static void verifyZip(ZipFile z, Result r) {
        try {
            Enumeration<? extends ZipEntry> en = z.entries();
            List<String> entryNames = new ArrayList<String>();
            Set<String> seen = new HashSet<String>();
            boolean pathsOk = true, dupOk = true, sizeOk = true;
            long total = 0;
            int count = 0;
            while (en.hasMoreElements()) {
                ZipEntry ze = en.nextElement();
                String n = ze.getName();
                // 第四轮 E6：目录条目（以 / 结尾）也全部收集，参与「无未声明
                // 条目」检查。旧实现跳过它们，导致「名字是目录但带内容」的
                // 条目可以夹带任意数据而两端都不报。
                entryNames.add(n);
                if (!seen.add(n)) dupOk = false;
                if (!safeName(n)) pathsOk = false;
                count++;
                long sz = ze.getSize();
                if (sz < 0 || sz > MAX_ENTRY_SIZE) sizeOk = false;
                total += Math.max(sz, 0);
            }
            r.log(pathsOk, "ZIP 条目路径安全（无 zip-slip / 绝对路径）");
            // 同名条目在不同 ZIP 实现里 getEntry / 遍历顺序不一致，会造成
            // 「校验读 A、install 落盘 B」的歧义；完整包不允许出现重复条目
            r.log(dupOk, "ZIP 内无重复条目名（共 " + seen.size() + " 个唯一条目）");
            r.log(count <= MAX_ENTRIES,
                  "ZIP 条目数 <= " + MAX_ENTRIES + "（实际 " + count + "）");
            r.log(sizeOk, "每个条目解压尺寸 <= " + MAX_ENTRY_SIZE + " B");
            r.log(total <= MAX_TOTAL_SIZE,
                  "总解压尺寸 <= " + MAX_TOTAL_SIZE + "（实际 " + total + "）");

            // 第五轮：容器层全量校验。前四轮只在 read() 里对「被读取的条目」算 CRC，
            // 白名单文档 README.md 从不被读取，且体积用的是 ZIP 头声明值；
            // 于是「README CRC 坏」「声明 size 伪造的 zip bomb」两端结论相反（H1/H6）。
            verifyContainer(z, r);

            byte[] mr = read(z, "manifest.json");
            if (mr == null) { r.log(false, "manifest.json 存在 / CRC 正确"); return; }
            r.log(true, "manifest.json 存在 / CRC 正确");
            String[] g = jsonGuard(mr, MAX_MANIFEST_SIZE);
            r.log("1".equals(g[0]), "manifest 词法预检：" + g[1]);
            if (!"1".equals(g[0])) return;
            // 用严格 UTF-8 解码后的文本构造，杜绝 new String(bytes) 替换非法字节
            JSONObject m = new JSONObject(g[2]);

            r.log(FORMAT.equals(str(m, "format")), "format == fne-rootpkg");
            r.log(strictInt(m, "format_version") == FORMAT_VERSION,
                  "format_version == 1（必须是 JSON 整数）");
            r.log("5.4".equals(str(m, "kernel_series")), "kernel_series == 5.4");

            JSONObject pk = m.optJSONObject("package");
            JSONObject ex = m.optJSONObject("execution");
            if (pk == null || ex == null) { r.log(false, "package / execution 存在"); return; }
            // 第六轮：id / name / ko_vermagic 必须是单行纯文本 JSON 字符串。
            // 数字与对象被 str() 严格化挡下；含换行 + 伪造 [OK] 行的 id 会进
            // Result 并显示在界面日志里，属日志注入（P06）。
            r.log(safeText(str(pk, "id")),
                  "package.id 是单行纯文本且 <= 256 字符（JSON 字符串）");
            r.log(safeText(str(pk, "name")),
                  "package.name 是单行纯文本且 <= 256 字符（JSON 字符串）");
            r.log(safeText(str(pk, "ko_vermagic")),
                  "package.ko_vermagic 是单行纯文本且 <= 256 字符（JSON 字符串）");
            r.id = str(pk, "id");
            r.name = str(pk, "name");
            r.vermagic = str(pk, "ko_vermagic");

            JSONArray rel = pk.optJSONArray("kernel_releases");
            boolean relOk = rel != null && rel.length() > 0;
            if (relOk) {
                for (int i = 0; i < rel.length(); i++)
                    if (!rel.optString(i, "").startsWith("5.4.")) relOk = false;
                r.kernel = rel.optString(0, "");
            }
            r.log(relOk, "kernel_releases 非空且全为 5.4 系");

            r.log(WORKDIR.equals(str(ex, "workdir")), "execution.workdir == /data/local/tmp/ksu_fne");
            r.log(E_PATH.equals(str(ex, "e_path")), "execution.e_path 正确");
            r.log(ENTRY_SCRIPT.equals(str(ex, "entry_script")),
                  "execution.entry_script == " + ENTRY_SCRIPT + "（写死的名字）");
            JSONObject env = ex.optJSONObject("env");
            r.log(env != null && str(env, "DM_PAGE_OFFSET").startsWith("0xffffff8"),
                  "execution.env 含 DM_PAGE_OFFSET");

            // 第三轮：路径固定、字段清单内置、值必须可解析、releases 全覆盖
            String offRef = str(m, "offsets_ref");
            r.log(OFFSETS_REF.equals(offRef),
                  "offsets_ref == " + OFFSETS_REF + "（固定路径，当前 " + offRef + "）");
            byte[] offRaw = read(z, OFFSETS_REF);
            // 第五轮：offsets.json 是包内第二份独立 JSON，必须与 manifest 一样过词法预检，
            // 且用严格 UTF-8 解码文本构造（否则 PC 严格拒绝 / App 替换 U+FFFD 放行，G1/G2/G3）
            String[] og = offRaw == null
                    ? new String[]{"0", OFFSETS_REF + " 不存在 / CRC 错误", ""}
                    : jsonGuard(offRaw, MAX_OFFSETS_SIZE);
            r.log("1".equals(og[0]), "offsets.json 词法预检：" + og[1]);
            if ("1".equals(og[0])) {
                JSONObject off = new JSONObject(og[2]);
                JSONArray ks = off.optJSONArray("kernels");
                boolean ok = ks != null && ks.length() > 0;
                r.offsetCount = ks == null ? 0 : ks.length();
                int missing = 0;
                Set<String> unames = new HashSet<String>();
                int unameTotal = 0;
                if (ks != null) {
                    for (int i = 0; i < ks.length(); i++) {
                        JSONObject k = ks.optJSONObject(i);
                        if (k == null) { ok = false; continue; }
                        String u = str(k, "uname_r");
                        unames.add(u); unameTotal++;
                        if (!u.startsWith("5.4.")) ok = false;
                        JSONObject ko = k.optJSONObject("offsets");
                        if (ko == null) { ok = false; missing += OFFSET_FIELDS.length; continue; }
                        for (String f : OFFSET_FIELDS)
                            if (!parseNumOk(ko.opt(f))) missing++;
                    }
                }
                // 5.4 系「需求表」允许覆盖多个内核（官方表 11 条）；
                // 但 package.kernel_releases 声明的每个内核都必须在表里有条目（全覆盖）。
                boolean coverAll = rel != null;
                if (rel != null) for (int j = 0; j < rel.length(); j++)
                    if (!unames.contains(rel.optString(j, ""))) coverAll = false;
                r.log(ok, "offsets.json 完整（" + r.offsetCount + " 条 5.4 内核）");
                r.log(unameTotal == unames.size(), "offsets.json uname_r 无重复");
                r.log(coverAll, "offsets.json 全覆盖 kernel_releases");
                r.log(missing == 0,
                      "每条内核覆盖内置 " + OFFSET_FIELDS.length
                      + " 字段且值可解析（缺/非法 " + missing + " 项）");
            } else r.log(false, OFFSETS_REF + " 预检未通过，跳过偏移表字段校验");

            JSONArray files = m.optJSONArray("files");
            if (files == null) { r.log(false, "files[] 存在"); return; }
            java.util.Map<String, Integer> roleCount = new java.util.HashMap<String, Integer>();
            Set<String> declared = new HashSet<String>();
            Set<String> dests = new HashSet<String>();
            Set<String> paths = new HashSet<String>();
            r.fileCount = files.length();
            r.log(files.length() == ROLES.length,
                  "files[] 恰好 " + ROLES.length + " 项（实际 " + files.length() + "）");
            byte[] eBlob = null, koBlob = null, symBlob = null, shBlob = null, chainBlob = null;

            for (int i = 0; i < files.length(); i++) {
                JSONObject f = files.optJSONObject(i);
                if (f == null) { r.log(false, "files[" + i + "] 是对象"); continue; }
                String path = str(f, "path"), role = str(f, "role"), dest = str(f, "dest");
                if (role.length() > 0) {
                    Integer c = roleCount.get(role);
                    roleCount.put(role, c == null ? 1 : c + 1);
                }
                declared.add(path);

                // 角色 ↔ 目标名 ↔ 权限 ↔ path 全绑定，杜绝物料错位 / 相互覆盖 / 夹带
                String[] spec = roleSpec(role);
                r.log(spec != null,
                      "  files[" + i + "].role 在 10 项白名单内 (" + role + ")");
                if (spec != null) {
                    r.log(spec[0].equals(dest),
                          "  role=" + role + " 的 dest 必须为 " + spec[0]);
                    r.log(spec[1].equals(str(f, "mode")),
                          "  role=" + role + " 的 mode 必须为 " + spec[1]);
                    r.log(("payload/" + spec[0]).equals(path),
                          "  role=" + role + " 的 path 必须为 payload/" + spec[0]);
                }
                r.log(dest.length() > 0 && safeName(dest), "  " + path + " dest 合法");
                r.log(dests.add(dest), "  files[" + i + "].dest 唯一 (" + dest + ")");
                r.log(paths.add(path), "  files[" + i + "].path 唯一 (" + path + ")");
                if (!safeName(path)) { r.log(false, "  files[" + i + "].path 安全 (" + path + ")"); continue; }
                byte[] b = read(z, path);
                if (b == null) { r.log(false, "  " + path + " 条目存在"); continue; }
                r.log(b.length == strictInt(f, "size"),
                      "  " + path + " size 一致（JSON 整数）");
                r.log(sha256(b).equals(str(f, "sha256")), "  " + path + " sha256 一致");
                r.log(isMode(str(f, "mode")), "  " + path + " mode 格式合法");
                if ("exploit".equals(role)) eBlob = b;
                if ("kernelsu_ko".equals(role)) koBlob = b;
                if ("kallsyms".equals(role)) symBlob = b;
                if ("entry_script".equals(role)) shBlob = b;
                if ("chain_hook".equals(role)) chainBlob = b;
            }
            for (int i = 0; i < ROLES.length; i++) {
                Integer c = roleCount.get(ROLES[i][0]);
                r.log(c != null && c == 1,
                      "必需物料 role=" + ROLES[i][0] + " 有且仅有 1 项");
            }
            // 无夹带条目：包内不得出现清单外的文件（完整包语义，与 frp_tool.py 一致）
            Set<String> allowed = new HashSet<String>();
            allowed.add("manifest.json");
            allowed.add("README.md");
            allowed.add(OFFSETS_REF);
            List<String> undeclared = new ArrayList<String>();
            for (String n : entryNames)
                if (!declared.contains(n) && !allowed.contains(n)) undeclared.add(n);
            r.log(undeclared.isEmpty(),
                  "无未声明条目（" + undeclared.size() + " 项）"
                  + (undeclared.isEmpty() ? "" : " -> " + undeclared.get(0)));

            // 交叉校验：物料之间的配套关系，这才是「必须整包」的核心
            if (eBlob != null) {
                // 与 PC 端 struct.unpack_from("<H", e, 18)[0] == 0xB7 对齐：
                // 低字节 0xB7 且高字节必须为 0，只查低字节会放行 EM=0x1B7 等伪架构
                boolean elf = eBlob.length > 20 && eBlob[0] == 0x7f && eBlob[1] == 'E'
                        && eBlob[2] == 'L' && eBlob[3] == 'F'
                        && (eBlob[18] & 0xff) == 0xB7 && (eBlob[19] & 0xff) == 0;
                r.log(elf, "e 为 aarch64 ELF（e_machine == 0x00B7）");
                r.log(strictInt(ex, "e_size") == eBlob.length,
                      "execution.e_size 与脚本内尺寸断言一致 (" + eBlob.length + " B，JSON 整数)");
            } else r.log(false, "e 可读");

            if (koBlob != null) {
                String s = new String(koBlob, "ISO-8859-1");
                int p = s.indexOf("vermagic=");
                String got = "";
                if (p >= 0) {
                    int q = p + 9;
                    while (q < s.length()) {
                        char c = s.charAt(q);
                        if (c == ' ' || c == 0 || c == '\n') break;
                        got += c; q++;
                    }
                }
                r.log(got.equals(r.vermagic), "ko vermagic 与 package.ko_vermagic 一致 (" + got + ")");
            } else r.log(false, "kernelsu.ko 可读");

            if (symBlob != null) {
                int lines = 0;
                for (int i = 0; i < symBlob.length; i++) if (symBlob[i] == '\n') lines++;
                // 内置硬下限恒成立：包内 assertions.kallsyms_lines 只做一致性核对，
                // 不能把期望自述成 1 行就放行（第三轮 A4）
                r.log(lines >= MIN_KALLSYMS_LINES,
                      "fne_syms.txt 行数 >= 内置下限 " + MIN_KALLSYMS_LINES + "（实际 " + lines + "）");
                JSONObject as0 = ex.optJSONObject("assertions");
                int declaredLines = as0 == null ? -1 : strictInt(as0, "kallsyms_lines");
                if (declaredLines > 0)
                    r.log(declaredLines == lines,
                          "assertions.kallsyms_lines 与实际行数一致 (" + declaredLines + " / " + lines + ")");
            } else r.log(false, "fne_syms.txt 可读");

            r.log(shBlob != null && shBlob.length > 2 && shBlob[0] == '#' && shBlob[1] == '!',
                  "fne_local.sh 有 shebang");
            r.log(chainBlob != null && chainBlob.length > 2 && chainBlob[0] == '#' && chainBlob[1] == '!',
                  "chain_hook.sh 有 shebang");
            // 两端都用真正的 sh -n（从 stdin 读，零临时文件 / 零执行），
            // 静态括号配平会误伤官方 sh（case / 注释 / 跨行引号本就不配平），故不用启发式
            r.log(shSyntaxOk(shBlob), "fne_local.sh 通过 sh -n 语法检查");
            r.log(shSyntaxOk(chainBlob), "chain_hook.sh 通过 sh -n 语法检查");

            // 物料互相绑定：manifest / e / sh / chain / ko / syms 必须指向同一套东西。
            // 只换物料再让 build 自动重算 size/sha256（manifest 自洽）并不算配套，
            // 设备端会被 sh 里的尺寸 / workdir / 内核门控断言挡下或直接跑飞。
            String shText = shBlob == null ? "" : new String(shBlob, "ISO-8859-1");
            String chainText = chainBlob == null ? "" : new String(chainBlob, "ISO-8859-1");
            JSONObject as = ex.optJSONObject("assertions");
            int eLen = eBlob == null ? -1 : eBlob.length;
            r.log(eLen > 0 && shText.contains(String.valueOf(eLen)),
                  "fne_local.sh 含 e 尺寸断言 " + eLen + " B（换 e 不改 sh 应拒绝）");
            if (as != null) {
                int a = strictInt(as, "e_size_in_entry_script");
                if (a > 0) r.log(a == eLen, "assertions.e_size_in_entry_script 与 e 尺寸一致");
            }
            r.log(shText.contains(WORKDIR) && chainText.contains(WORKDIR),
                  "两个 sh 的 workdir 与 execution.workdir 一致");
            String vm = r.vermagic;
            r.log(vm.length() > 0 && shText.contains(vm) && chainText.contains(vm),
                  "两个 sh 的内核门控与 ko vermagic 一致 (" + vm + ")");
            if (as != null) {
                String a1 = str(as, "ko_vermagic_in_entry_script");
                String a2 = str(as, "kernel_release_gate_in_chain_hook");
                if (a1.length() > 0)
                    r.log(vm.equals(a1), "assertions.ko_vermagic_in_entry_script 一致");
                if (a2.length() > 0)
                    r.log(vm.equals(a2), "assertions.kernel_release_gate_in_chain_hook 一致");
            }
        } catch (Throwable e) {
            // 兜住 StackOverflowError 等 Error，绝不让它冲出校验流程
            r.log(false, "解析失败: " + e.getClass().getSimpleName() + " " + e.getMessage());
        }
    }

    // ---------------------------------------------------------------- scan

    public static List<File> scan() {
        List<File> out = new ArrayList<File>();
        String[] dirs = {PKG_DIR, PKG_SUBDIR};
        for (String d : dirs) {
            File dir = new File(d);
            File[] fs = dir.listFiles();
            if (fs == null) continue;
            for (File f : fs)
                if (f.isFile() && f.getName().toLowerCase().endsWith(".frp")) out.add(f);
        }
        return out;
    }

    // ---------------------------------------------------------------- install

    /**
     * 原子导入：先 staging 全量校验，再备份旧包并替换。
     * 任一步失败立即返回、原激活包保持不变；只有确认备份存在时才会回滚。
     */
    /** synchronized：两次导入 / 导入与释放共用 .staging、active_pkg.tmp、.bak，
     *  并发会互相 rmrf 造成随机失败（第四轮 F1/F2）。静态方法锁 Frp.class 串行化。 */
    public static synchronized Result install(File pkg, File filesDir) {
        Result v = newResult(pkg);
        if (!v.ok) return v;
        // 第三轮：只打开一次 ZIP，校验与落盘共用同一个 ZipFile 句柄。
        // 旧实现先 verify(pkg) 打开+关闭一次，再 new ZipFile(pkg) 落盘，中间文件
        // 若被替换就会出现「校验的是合法包、落盘的是恶意包」（TOCTOU）。
        ZipFile z = null;
        try {
            z = new ZipFile(pkg);
            verifyZip(z, v);
        } catch (Throwable e) {
            v.log(false, "打开包失败: " + e.getClass().getSimpleName() + " " + e.getMessage());
        }
        v.lines.add(v.ok ? "结论: 完整包校验通过 ✔" : "结论: 拒绝导入 ✘");
        if (!v.ok) {
            if (z != null) try { z.close(); } catch (Exception ignored) {}
            return v;
        }
        Result r = new Result();
        r.ok = true;
        File staging = new File(filesDir, ".staging");
        File active = new File(filesDir, "active_pkg");
        File tmp = new File(filesDir, "active_pkg.tmp");
        File backup = new File(filesDir, "active_pkg.bak");
        rmrf(staging); rmrf(tmp); rmrf(backup);
        if (!staging.mkdirs()) {
            r.log(false, "创建 staging 目录失败");
            r.lines.add("导入失败 ✘（原激活包保持不变）");
            if (z != null) try { z.close(); } catch (Exception ignored) {}
            return r;
        }
        boolean backedUp = false;
        try {
            Enumeration<? extends ZipEntry> en = z.entries();
            while (en.hasMoreElements()) {
                ZipEntry e = en.nextElement();
                if (e.isDirectory() || !safeName(e.getName())) continue;
                File dst = new File(staging, e.getName());
                File par = dst.getParentFile();
                if (par != null) par.mkdirs();
                InputStream in = z.getInputStream(e);
                FileOutputStream fo = new FileOutputStream(dst);
                byte[] buf = new byte[65536];
                int n;
                long wrote = 0;
                // 必须是 != -1：InflaterInputStream 可能返回 0，用 > 0 会提前
                // 结束写入，落盘出被截断的物料，而校验阶段读到的却是完整数据。
                // 第五轮：边写边卡真实字节上限——ZipEntry.getSize() 是声明值，
                // 伪造过的声明骗得过体积检查，但骗不过实际从 deflate 流读出的字节。
                while ((n = in.read(buf)) != -1) {
                    wrote += n;
                    if (wrote > MAX_ENTRY_SIZE) {
                        fo.close(); in.close();
                        throw new java.io.IOException("条目 " + e.getName() + " 解压超出上限");
                    }
                    fo.write(buf, 0, n);
                }
                fo.close(); in.close();
            }
            if (!new File(staging, "manifest.json").isFile()) {
                r.log(false, "staging 内容不完整");
                rmrf(staging);
                r.lines.add("导入失败 ✘（原激活包保持不变）");
                return r;
            }

            if (!staging.renameTo(tmp)) {
                r.log(false, "staging -> active_pkg.tmp 失败");
                rmrf(staging);
                r.lines.add("导入失败 ✘（原激活包保持不变）");
                return r;
            }
            r.log(true, "staging -> active_pkg.tmp");

            if (active.exists()) {
                backedUp = active.renameTo(backup);
                r.log(backedUp, "备份旧激活包");
                if (!backedUp) {
                    rmrf(tmp);            // 关键：备份失败就停，绝不删 active
                    r.lines.add("导入失败 ✘（原激活包保持不变）");
                    return r;
                }
            }

            boolean swapped = tmp.renameTo(active);
            r.log(swapped, "原子替换为 active_pkg");
            if (swapped) {
                rmrf(backup);
            } else {
                // 只有确认备份存在才清理并回滚，否则原封不动保留 active
                if (backedUp && backup.exists()) {
                    rmrf(active);
                    backup.renameTo(active);
                }
                rmrf(tmp);
                r.lines.add("导入失败 ✘（" + (backedUp ? "已回滚到原激活包" : "原激活包保持不变") + "）");
                return r;
            }
            rmrf(staging);
            r.id = v.id; r.name = v.name; r.kernel = v.kernel;
            r.fileCount = v.fileCount; r.offsetCount = v.offsetCount;
            r.lines.add("导入完成 ✔（当前激活包已切换）");
        } catch (Throwable e) {
            r.log(false, "导入异常: " + e.getMessage());
            rmrf(staging); rmrf(tmp);
            if (backedUp && backup.exists() && !active.exists()) backup.renameTo(active);
            r.lines.add("导入失败 ✘（原激活包保持不变或已回滚）");
        } finally {
            if (z != null) try { z.close(); } catch (Exception ignored) {}
        }
        return r;
    }

    private static void rmrf(File f) {
        if (f == null || !f.exists()) return;
        if (f.isDirectory()) {
            File[] cs = f.listFiles();
            if (cs != null) for (File c : cs) rmrf(c);
        }
        f.delete();
    }

    // ---------------------------------------------------------------- info

    public static boolean hasActive(File filesDir) {
        return new File(filesDir, "active_pkg/manifest.json").isFile();
    }

    public static String info(File filesDir) {
        File mf = new File(filesDir, "active_pkg/manifest.json");
        if (!mf.isFile()) return "当前无激活包 —— 请先「扫描」并「导入完整包」";
        try {
            JSONObject m = new JSONObject(new String(readAll(mf), "UTF-8"));
            JSONObject pk = m.optJSONObject("package"), ex = m.optJSONObject("execution");
            JSONArray rel = pk == null ? null : pk.optJSONArray("kernel_releases");
            StringBuilder s = new StringBuilder();
            s.append("ID      : ").append(str(pk, "id")).append('\n');
            s.append("名称    : ").append(str(pk, "name")).append('\n');
            s.append("机型    : ").append(str(pk, "device")).append('\n');
            s.append("内核    : ").append(rel == null ? "-" : rel.optString(0, "")).append('\n');
            s.append("vermagic: ").append(str(pk, "ko_vermagic")).append('\n');
            s.append("workdir : ").append(str(ex, "workdir")).append('\n');
            int es = strictInt(ex, "e_size");
            s.append("e 尺寸  : ").append(es < 0 ? 0 : es).append(" B\n");
            JSONArray farr = m.optJSONArray("files");
            s.append("物料数  : ").append(farr == null ? 0 : farr.length()).append('\n');
            String ref = str(m, "offsets_ref");
            s.append("偏移表  : ").append(
                    ref.length() > 0 && safeName(ref)
                    && new File(filesDir, "active_pkg/" + ref).isFile()
                    ? ref + " 已就位" : "缺失");
            return s.toString();
        } catch (Exception e) {
            return "读取 manifest 失败: " + e.getMessage();
        }
    }

    // ---------------------------------------------------------------- release

    /**
     * 释放：active_pkg/payload/* -> /sdcard/Download/ksu_fne/（App 自己能写）。
     *
     * 【刻意不做】rm -rf / cp / chmod 到 /data/local/tmp/ksu_fne：
     *   App 是 untrusted_app uid，那条命令几乎必然 Permission denied；
     *   更糟的是「曾经用 root 跑过 App」时 tmp 属主可能变成 app，rm -rf 会
     *   把用户手工布置的物料清掉。所以搬到 tmp 交给 adb / 文件管理器，
     *   这里只做只读探测，绝不改动 tmp，也不把「写 sdcard 成功」冒充成
     *   「tmp 已就位」。
     */
    public static synchronized Result release(File filesDir) {
        Result r = new Result();
        r.ok = true;
        if (!hasActive(filesDir)) { r.log(false, "无激活包，拒绝释放"); return r; }
        try {
            JSONObject m = new JSONObject(new String(
                    readAll(new File(filesDir, "active_pkg/manifest.json")), "UTF-8"));
            JSONArray files = m.optJSONArray("files");
            if (files == null) { r.log(false, "manifest.files 缺失"); return r; }
            File sd = new File(SD_STAGE);
            r.log(sd.exists() || sd.mkdirs(), "创建中转目录 " + SD_STAGE);

            int written = 0;
            Set<String> wanted = new HashSet<String>();
            for (int i = 0; i < files.length(); i++) {
                JSONObject f = files.optJSONObject(i);
                if (f == null) { r.log(false, "  files[" + i + "] 非法"); continue; }
                String path = str(f, "path"), dest = str(f, "dest");
                if (!safeName(path) || !safeName(dest)) {
                    r.log(false, "  files[" + i + "] 路径不安全"); continue;
                }
                wanted.add(dest);
                // 逐项独立 try：某一项失败不中断后续，日志如实反映每一项结果
                try {
                    File src = new File(filesDir, "active_pkg/" + path);
                    if (!src.isFile()) { r.log(false, "  缺文件 " + path); continue; }
                    byte[] b = readAll(src);
                    File dst = new File(sd, dest);
                    File par = dst.getParentFile();
                    if (par != null && !par.exists() && !par.mkdirs()) {
                        r.log(false, "  无法创建目标目录 " + dest); continue;
                    }
                    FileOutputStream fo = new FileOutputStream(dst);
                    try { fo.write(b); } finally { fo.close(); }
                    boolean good = dst.length() == b.length;
                    r.log(good, "  释放 " + dest + " (" + b.length + " B)");
                    if (good) written++;
                } catch (Exception e) {
                    r.log(false, "  释放 " + dest + " 失败: " + e.getMessage());
                }
            }
            r.log(written == files.length(),
                  "中转目录已写入 " + written + "/" + files.length() + " 项");

            // 残留只提示、不删除（不擅自动用户文件）；搬运命令显式列文件名，不会带上它们
            File[] left = sd.listFiles();
            List<String> extras = new ArrayList<String>();
            if (left != null) for (File f : left)
                if (f.isFile() && !wanted.contains(f.getName())) extras.add(f.getName());
            if (!extras.isEmpty())
                r.lines.add("  [提示] 中转目录还有 " + extras.size() + " 个非本包文件（"
                        + extras.get(0) + " 等）；搬运命令只列 10 项，不会把它们带进 tmp");

            // 只读探测，不动 tmp；App 无权限时给出可复制的搬运命令
            String probe = shell("ls -l " + WORKDIR + "/ 2>&1");
            boolean landed = new File(WORKDIR + "/e").isFile();
            r.lines.add("--- " + WORKDIR + " 只读探测 ---");
            for (String l : probe.split("\n"))
                if (l.length() > 0) r.lines.add("  " + l);
            r.lines.add(landed
                    ? "  [OK]   tmp 已就位（e 存在），可直接执行"
                    : "  [待手动] tmp 里还没有物料 —— App 不代搬，请用 adb 或文件管理器：");
            r.lines.add("  " + copyCommand().replace("\n", "\n  "));
            r.lines.add("提示：首次释放后不再校验；跑前请 rm -f " + WORKDIR + "/fne_run.log");
            r.lines.add(r.ok
                    ? "释放完成 ✔（中转已写入 10 项；tmp 是否就位见上方探测，搬运只会复制这 10 项）"
                    : "释放存在问题 ✘（请勿搬运，见上方 [FAIL]）");
        } catch (Throwable e) {
            r.log(false, "释放异常: " + e.getMessage());
            r.lines.add("释放存在问题 ✘");
        }
        return r;
    }

    /**
     * 供用户复制的 adb 搬运命令：显式列出 10 项源文件名，不用通配符。
     * 用 cp * 会把中转目录里上一次释放的残留 / 用户杂物一起搬进 tmp，
     * 破坏「e 与 sh 必须整包配套」；命令从 ROLES 派生，规则改了不会脱节。
     */
    public static String copyCommand() {
        StringBuilder src = new StringBuilder(), x755 = new StringBuilder(), x644 = new StringBuilder();
        for (int i = 0; i < ROLES.length; i++) {
            String d = ROLES[i][1];
            src.append(SD_STAGE).append('/').append(d).append(' ');
            if ("0755".equals(ROLES[i][2]))
                x755.append(WORKDIR).append('/').append(d).append(' ');
            else
                x644.append(WORKDIR).append('/').append(d).append(' ');
        }
        return "adb shell mkdir -p " + WORKDIR + " && \\\n"
             + "adb shell cp " + src.toString().trim() + " " + WORKDIR + "/ && \\\n"
             + "adb shell chmod 755 " + x755.toString().trim() + " && \\\n"
             + "adb shell chmod 644 " + x644.toString().trim();
    }

    private static byte[] readAll(File f) throws Exception {
        byte[] b = new byte[(int) f.length()];
        java.io.FileInputStream in = new java.io.FileInputStream(f);
        int off = 0;
        while (off < b.length) {
            int n = in.read(b, off, b.length - off);
            if (n < 0) break;
            off += n;
        }
        in.close();
        return b;
    }

    /** 以 App 自身 uid 执行 shell；无 shell 权限时返回错误文本，不冒充成功。 */
    public static String shell(String cmd) {
        try {
            Process p = Runtime.getRuntime().exec(new String[]{"/system/bin/sh", "-c", cmd});
            java.io.BufferedReader br = new java.io.BufferedReader(
                    new java.io.InputStreamReader(p.getInputStream()));
            java.io.BufferedReader be = new java.io.BufferedReader(
                    new java.io.InputStreamReader(p.getErrorStream()));
            StringBuilder s = new StringBuilder();
            String l;
            while ((l = br.readLine()) != null) s.append(l).append('\n');
            while ((l = be.readLine()) != null) s.append(l).append('\n');
            p.waitFor();
            return s.toString();
        } catch (Exception e) {
            return "shell 不可用: " + e.getMessage();
        }
    }

    public static String execCommand() {
        return "adb shell rm -f " + WORKDIR + "/fne_run.log\n"
             + "adb shell sh " + WORKDIR + "/fne_local.sh";
    }
}
