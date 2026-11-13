package com.fne.universal;

import android.app.Activity;
import android.app.AlertDialog;
import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.provider.Settings;
import android.text.method.ScrollingMovementMethod;
import android.view.Gravity;
import android.view.View;
import android.view.ViewGroup;
import android.widget.Button;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;
import android.widget.Toast;

import java.io.File;
import java.io.FileOutputStream;
import java.io.OutputStreamWriter;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.List;
import java.util.Locale;

/**
 * 荣耀Ghostlock提权工具 · 通用壳。
 *
 * 这个 App 本身不含任何设备物料：没有内置 e、没有内置 sh。
 * 唯一入口是「导入完整 .frp 包」，导入后所有物料从 active_pkg/payload 读取。
 * 界面刻意不提供「单独替换 e / 单独替换 sh」，因为二者与 ko/符号表/偏移互相写死。
 *
 * v2.7：外观参照 ghostlock-app 的状态卡片 + 醒目主按钮层级，
 * 但功能与校验链完全不变（不引入 conf/profile 导入，仍只认整包 .frp）；
 * 另新增「日志自定义放置目录」——把屏幕日志追加写入用户指定目录。
 */
public class MainActivity extends Activity {

    private static final int BG = 0xFF0B1020, CARD = 0xFF161D31, STROKE = 0xFF2A3550;
    private static final int ACCENT = 0xFF7AA2FF, MINT = 0xFF5AFFB4, WARN = 0xFFFFD246;
    private static final int TEXT = 0xFFDCE6FA, DIM = 0xFF8A99B8, RED = 0xFFFF7B7B;
    private static final String PREF = "fne_ui";
    private static final String KEY_LOG_DIR = "log_dir";
    private static final String LOG_FILE = "fne_app_log.txt";

    private TextView status, logView, logDirView;
    private LinearLayout pkgList;
    private ScrollView logScroll;
    private File selected = null;
    private final Handler ui = new Handler(Looper.getMainLooper());
    private File filesDir;
    private SharedPreferences prefs;
    private String logDir = null;              // null = 只显示不落盘
    private boolean logToFileFailed = false;   // 落盘失败只提示一次，不刷屏、不影响主流程

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        filesDir = getFilesDir();
        prefs = getSharedPreferences(PREF, MODE_PRIVATE);
        String saved = prefs.getString(KEY_LOG_DIR, null);
        if (saved != null && new File(saved).isDirectory()) logDir = saved;
        setContentView(buildLayout());
        updateLogDirView();
        log("荣耀Ghostlock提权工具 · v2.7 已启动");
        log("本 App 不含任何内置物料 —— 请先导入完整 .frp 包");
        log("格式规范见 docs/包格式规范.md；制作教程见《通用提权包制作教程_5.4系.md》");
        if (logDir != null) log("日志落盘: " + logDir + "/" + LOG_FILE);
        if (!hasAllFilesAccess()) {
            log("⚠ 未获得「所有文件访问权限」—— 点状态卡片或「⚙ 授权」开启，否则扫描不到 .frp");
        }
        refreshStatus();
        scan();
    }

    @Override
    protected void onResume() {
        super.onResume();
        refreshStatus();   // 从系统授权页返回时立即刷新状态
    }

    // ------------------------------------------------------------------ 权限

    /** Android 11+ 需要用户手动开启「所有文件访问权限」，只声明在 Manifest 里不够。 */
    private boolean hasAllFilesAccess() {
        if (Build.VERSION.SDK_INT < 30) return true;
        try {
            return android.os.Environment.isExternalStorageManager();
        } catch (Throwable t) {
            // 部分 ROM 在未授权时 /sdcard/Download 的 canRead() 也会返回 true，
            // 不能据此判定已授权；宁可按未授权提示，让用户去系统设置页确认
            return false;
        }
    }

    private void requestAllFiles() {
        try {
            Intent it = new Intent(Settings.ACTION_MANAGE_APP_ALL_FILES_ACCESS_PERMISSION,
                    Uri.parse("package:" + getPackageName()));
            startActivity(it);
        } catch (Throwable t) {
            try {
                startActivity(new Intent(Settings.ACTION_MANAGE_ALL_FILES_ACCESS_PERMISSION));
            } catch (Throwable t2) {
                toast("请在 设置→应用→本应用→权限 手动开启「所有文件访问权限」");
            }
        }
    }

    // ------------------------------------------------------------------ UI

    private View buildLayout() {
        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setPadding(dp(16), dp(20), dp(16), dp(12));
        android.graphics.drawable.GradientDrawable bg =
                new android.graphics.drawable.GradientDrawable(
                        android.graphics.drawable.GradientDrawable.Orientation.TOP_BOTTOM,
                        new int[]{0xFF080C18, 0xFF111A30, 0xFF0A0F1E});
        root.setBackgroundDrawable(bg);

        TextView title = new TextView(this);
        title.setText("荣耀Ghostlock提权工具");
        title.setTextColor(ACCENT);
        title.setTextSize(23);
        title.setTypeface(android.graphics.Typeface.DEFAULT_BOLD);
        title.setGravity(Gravity.CENTER);
        root.addView(title);

        TextView sub = new TextView(this);
        sub.setText("5.4 系 · 整包导入 · 一键准备");
        sub.setTextColor(DIM);
        sub.setTextSize(11);
        sub.setGravity(Gravity.CENTER);
        LinearLayout.LayoutParams sp = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        sp.bottomMargin = dp(14);
        root.addView(sub, sp);

        // 状态卡片：借鉴 ghostlock-app 的可点击状态卡（未授权点它直接跳授权页）
        LinearLayout card = card();
        card.setClickable(true);
        card.setOnClickListener(new View.OnClickListener() {
            public void onClick(View v) {
                if (!hasAllFilesAccess()) requestAllFiles();
                else { refreshStatus(); toast("状态已刷新"); }
            }
        });
        status = new TextView(this);
        status.setTextColor(TEXT);
        status.setTextSize(12);
        status.setLineSpacing(dp(2), 1f);
        card.addView(status);
        root.addView(card);

        // 醒目主按钮：对应 ghostlock-app 的「执行」。功能仍是生成并复制命令，不代跑脚本
        root.addView(btnPrimary("▶  执行 / 复制命令", 0xFF2EA043, new View.OnClickListener() {
            public void onClick(View v) { doExec(); }
        }));

        // 次级操作：原有功能一个不删，只是视觉降级为常规按钮区
        LinearLayout row1 = row();
        row1.addView(btn("🔍 扫描包", 0xFF1F6FEB, new View.OnClickListener() {
            public void onClick(View v) { scan(); }
        }));
        row1.addView(btn("📥 导入完整包", 0xFF238636, new View.OnClickListener() {
            public void onClick(View v) { doImport(); }
        }));
        root.addView(row1);

        LinearLayout row2 = row();
        row2.addView(btn("📦 释放物料", 0xFF8957E5, new View.OnClickListener() {
            public void onClick(View v) { doRelease(); }
        }));
        row2.addView(btn("ℹ 包信息", 0xFFD29922, new View.OnClickListener() {
            public void onClick(View v) { doInfo(); }
        }));
        root.addView(row2);

        LinearLayout row3 = row();
        row3.addView(btn("⚙ 授权文件访问", 0xFFB45309, new View.OnClickListener() {
            public void onClick(View v) { requestAllFiles(); }
        }));
        row3.addView(btn("📋 复制搬运命令", 0xFF0E7490, new View.OnClickListener() {
            public void onClick(View v) { doCopyMove(); }
        }));
        root.addView(row3);

        LinearLayout row4 = row();
        row4.addView(btn("🗑 清空日志", 0xFF30363D, new View.OnClickListener() {
            public void onClick(View v) { logView.setText(""); }
        }));
        row4.addView(btn("📁 日志目录", 0xFF6366F1, new View.OnClickListener() {
            public void onClick(View v) { chooseLogDir(); }
        }));
        root.addView(row4);

        TextView listTitle = new TextView(this);
        listTitle.setText("可导入的 .frp（点击选中，只能整包导入）");
        listTitle.setTextColor(ACCENT);
        listTitle.setTextSize(13);
        listTitle.setTypeface(android.graphics.Typeface.DEFAULT_BOLD);
        LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        lp.topMargin = dp(14);
        root.addView(listTitle, lp);

        pkgList = new LinearLayout(this);
        pkgList.setOrientation(LinearLayout.VERTICAL);
        root.addView(pkgList);

        TextView logTitle = new TextView(this);
        logTitle.setText("日志");
        logTitle.setTextColor(ACCENT);
        logTitle.setTextSize(13);
        logTitle.setTypeface(android.graphics.Typeface.DEFAULT_BOLD);
        LinearLayout.LayoutParams lp2 = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        lp2.topMargin = dp(12);
        root.addView(logTitle, lp2);

        logDirView = new TextView(this);
        logDirView.setTextColor(DIM);
        logDirView.setTextSize(10);
        root.addView(logDirView);

        logView = new TextView(this);
        logView.setTextColor(TEXT);
        logView.setTextSize(10);
        logView.setTypeface(android.graphics.Typeface.MONOSPACE);
        logView.setMovementMethod(new ScrollingMovementMethod());
        logView.setBackgroundColor(CARD);
        logView.setPadding(dp(8), dp(8), dp(8), dp(8));
        logScroll = new ScrollView(this);
        logScroll.addView(logView);
        LinearLayout.LayoutParams lp3 = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, 0, 1f);
        lp3.topMargin = dp(6);
        root.addView(logScroll, lp3);
        return root;
    }

    private LinearLayout card() {
        LinearLayout c = new LinearLayout(this);
        c.setOrientation(LinearLayout.VERTICAL);
        c.setPadding(dp(12), dp(10), dp(12), dp(10));
        android.graphics.drawable.GradientDrawable g =
                new android.graphics.drawable.GradientDrawable();
        g.setColor(CARD); g.setCornerRadius(dp(10)); g.setStroke(dp(1), STROKE);
        c.setBackgroundDrawable(g);
        return c;
    }

    private LinearLayout row() {
        LinearLayout r = new LinearLayout(this);
        r.setOrientation(LinearLayout.HORIZONTAL);
        r.setPadding(0, dp(6), 0, 0);
        return r;
    }

    private Button btn(String text, int color, View.OnClickListener l) {
        Button b = new Button(this);
        b.setText(text);
        b.setTextColor(0xFFFFFFFF);
        b.setTextSize(12);
        b.setAllCaps(false);
        android.graphics.drawable.GradientDrawable g =
                new android.graphics.drawable.GradientDrawable();
        g.setColor(color); g.setCornerRadius(dp(8));
        b.setBackgroundDrawable(g);
        b.setOnClickListener(l);
        LinearLayout.LayoutParams p = new LinearLayout.LayoutParams(0,
                ViewGroup.LayoutParams.WRAP_CONTENT, 1f);
        p.setMargins(dp(3), 0, dp(3), 0);
        b.setLayoutParams(p);
        return b;
    }

    /** 借鉴 ghostlock-app 的全宽醒目执行按钮。 */
    private Button btnPrimary(String text, int color, View.OnClickListener l) {
        Button b = new Button(this);
        b.setText(text);
        b.setTextColor(0xFFFFFFFF);
        b.setTextSize(15);
        b.setTypeface(android.graphics.Typeface.DEFAULT_BOLD);
        b.setAllCaps(false);
        android.graphics.drawable.GradientDrawable g =
                new android.graphics.drawable.GradientDrawable();
        g.setColor(color); g.setCornerRadius(dp(12));
        b.setBackgroundDrawable(g);
        b.setOnClickListener(l);
        LinearLayout.LayoutParams p = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, dp(48));
        p.topMargin = dp(12); p.bottomMargin = dp(4);
        b.setLayoutParams(p);
        return b;
    }

    private int dp(int v) {
        return (int) (v * getResources().getDisplayMetrics().density);
    }

    // ---------------------------------------------------- 日志自定义放置目录

    private void chooseLogDir() {
        final EditText et = new EditText(this);
        et.setHint("/sdcard/Download/fne_logs");
        et.setText(logDir == null ? "" : logDir);
        et.setSingleLine(true);
        et.setPadding(dp(16), dp(8), dp(16), dp(8));
        new AlertDialog.Builder(this)
                .setTitle("日志自定义放置目录")
                .setMessage("留空或点「关闭落盘」则只在屏幕显示。\n"
                        + "目录不存在会自动创建；界面日志按时间追加写入 <目录>/" + LOG_FILE + "。")
                .setView(et)
                .setPositiveButton("保存并启用", new android.content.DialogInterface.OnClickListener() {
                    public void onClick(android.content.DialogInterface d, int w) {
                        setLogDir(et.getText().toString());
                    }
                })
                .setNeutralButton("关闭落盘", new android.content.DialogInterface.OnClickListener() {
                    public void onClick(android.content.DialogInterface d, int w) {
                        setLogDir("");
                    }
                })
                .setNegativeButton("取消", null)
                .show();
    }

    private void setLogDir(String dir) {
        String d = dir == null ? "" : dir.trim();
        if (d.isEmpty()) {
            logDir = null;
            prefs.edit().remove(KEY_LOG_DIR).apply();
            logToFileFailed = false;
            updateLogDirView();
            log("日志落盘已关闭（仅屏幕显示）");
            return;
        }
        try {
            File f = new File(d);
            if (!f.isDirectory() && !f.mkdirs() && !f.isDirectory())
                throw new java.io.IOException("无法创建目录");
            // 先探针式写一行，确认目录真的可写，避免启用后每行都失败
            File probe = new File(f, LOG_FILE);
            appendLine(probe, "=== 日志落盘已启用 " + ts() + " ===");
            logDir = f.getAbsolutePath();
            prefs.edit().putString(KEY_LOG_DIR, logDir).apply();
            logToFileFailed = false;
            updateLogDirView();
            log("日志落盘目录: " + logDir + "/" + LOG_FILE);
        } catch (Throwable t) {
            toast("目录不可用: " + t.getClass().getSimpleName());
            log("✗ 日志目录不可用: " + d + " (" + t.getMessage() + ")");
        }
    }

    private void updateLogDirView() {
        if (logDirView == null) return;
        logDirView.setText("落盘: " + (logDir == null ? "未开启（仅屏幕）" : logDir + "/" + LOG_FILE));
    }

    private void appendLine(File f, String line) throws java.io.IOException {
        FileOutputStream fo = new FileOutputStream(f, true);
        OutputStreamWriter w = new OutputStreamWriter(fo, "UTF-8");
        try {
            w.write(line + "\n");
            w.flush();
        } finally {
            w.close();
            fo.close();
        }
    }

    private String ts() {
        return new SimpleDateFormat("HH:mm:ss", Locale.US).format(new Date());
    }

    // ------------------------------------------------------------------ logic

    private void refreshStatus() {
        StringBuilder s = new StringBuilder();
        boolean noPerm = !hasAllFilesAccess();
        String kv;
        try { kv = System.getProperty("os.version", "unknown"); }
        catch (Throwable t) { kv = "unknown"; }
        s.append("内核    ").append(kv).append("\n");
        s.append("授权    ").append(noPerm ? "✗ 未授予（点此卡片开启）" : "✓ 所有文件访问权限").append("\n");
        if (Frp.hasActive(filesDir)) {
            status.setTextColor(noPerm ? WARN : MINT);
            s.append("激活包  ● 已激活\n").append(Frp.info(filesDir));
        } else {
            status.setTextColor(noPerm ? RED : WARN);
            s.append("激活包  ○ 无\n把 .frp 放到 /sdcard/Download/，点「扫描包」→「导入完整包」");
        }
        status.setText(s.toString());
    }

    private void scan() {
        pkgList.removeAllViews();
        if (!hasAllFilesAccess())
            log("⚠ 未获得「所有文件访问权限」，可能扫不到 .frp；点「⚙ 授权文件访问」开启");
        final List<File> fs = Frp.scan();
        if (fs.isEmpty()) {
            TextView t = new TextView(this);
            t.setText("  未发现 .frp。可用 adb push 或文件管理器放到 /sdcard/Download/");
            t.setTextColor(DIM); t.setTextSize(11);
            pkgList.addView(t);
            selected = null;
            return;
        }
        for (int i = 0; i < fs.size(); i++) {
            final File f = fs.get(i);
            Button b = new Button(this);
            b.setText((i + 1) + ". " + f.getName() + "  (" + (f.length() / 1024) + " KB)");
            b.setTextColor(TEXT); b.setTextSize(11); b.setAllCaps(false);
            android.graphics.drawable.GradientDrawable g =
                    new android.graphics.drawable.GradientDrawable();
            g.setColor(CARD); g.setCornerRadius(dp(6)); g.setStroke(dp(1), STROKE);
            b.setBackgroundDrawable(g);
            b.setOnClickListener(new View.OnClickListener() {
                public void onClick(View v) {
                    selected = f;
                    log("已选中: " + f.getAbsolutePath());
                    toast("已选中整包，点「导入完整包」");
                }
            });
            LinearLayout.LayoutParams p = new LinearLayout.LayoutParams(
                    ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
            p.topMargin = dp(4);
            b.setLayoutParams(p);
            pkgList.addView(b);
        }
        log("扫描到 " + fs.size() + " 个 .frp，点列表选中后导入");
    }

    private void doImport() {
        if (selected == null) { toast("请先扫描并点选一个 .frp"); return; }
        final File f = selected;
        log("=== 导入 " + f.getName() + " ===");
        new Thread(new Runnable() {
            public void run() {
                Frp.Result rr;
                try { rr = Frp.install(f, filesDir); }
                catch (Throwable t) {
                    rr = new Frp.Result();
                    rr.ok = false;
                    rr.lines.add("导入异常（已拦截）: " + t.getClass().getName());
                }
                final Frp.Result r = rr;
                ui.post(new Runnable() {
                    public void run() {
                        for (String l : r.lines) log(l);
                        refreshStatus();
                        toast(r.ok ? "整包导入成功" : "拒绝导入：校验未通过");
                    }
                });
            }
        }).start();
    }

    private void doRelease() {
        if (!Frp.hasActive(filesDir)) { toast("请先导入完整包"); return; }
        log("=== 释放物料 ===");
        new Thread(new Runnable() {
            public void run() {
                Frp.Result rr;
                try { rr = Frp.release(filesDir); }
                catch (Throwable t) {
                    rr = new Frp.Result();
                    rr.ok = false;
                    rr.lines.add("释放异常（已拦截）: " + t.getClass().getName());
                }
                final Frp.Result r = rr;
                ui.post(new Runnable() {
                    public void run() {
                        for (String l : r.lines) log(l);
                        toast(r.ok ? "中转写入完成，见日志确认 tmp" : "释放有问题，看日志");
                    }
                });
            }
        }).start();
    }

    private void doInfo() {
        log("=== 当前激活包 ===");
        String[] lines = Frp.info(filesDir).split("\n");
        for (String l : lines) log("  " + l);
    }

    private void doCopyMove() {
        log("=== 搬运命令（把中转目录物料搬进 tmp）===");
        log("  " + Frp.copyCommand().replace("\n", "\n  "));
        copy(Frp.copyCommand());
    }

    private void doExec() {
        if (!Frp.hasActive(filesDir)) { toast("请先导入完整包"); return; }
        log("=== 执行 ===");
        log("App 自身是 untrusted_app uid，不代跑提权脚本（避免污染累积 fne_run.log）。");
        log("请用 adb / Shizuku / 已有 root 执行下面两条命令（已复制到剪贴板）：");
        log("  " + Frp.execCommand().replace("\n", "\n  "));
        log("判定：offsets matched / child is root! / grep kernelsu /proc/modules");
        copy(Frp.execCommand());
    }

    private void copy(String text) {
        try {
            ClipboardManager cm = (ClipboardManager) getSystemService(Context.CLIPBOARD_SERVICE);
            if (cm != null) {
                cm.setPrimaryClip(ClipData.newPlainText("fne-cmd", text));
                toast("命令已复制到剪贴板");
            }
        } catch (Throwable ignored) {}
    }

    // ------------------------------------------------------------------ util

    /** 屏幕日志 + 可选落盘。落盘失败只提示一次，绝不抛异常影响界面与主流程。 */
    private void log(String s) {
        logView.append(s + "\n");
        logScroll.post(new Runnable() {
            public void run() { logScroll.fullScroll(ScrollView.FOCUS_DOWN); }
        });
        if (logDir == null || logToFileFailed) return;
        try {
            appendLine(new File(logDir, LOG_FILE), ts() + " " + s);
        } catch (Throwable t) {
            logToFileFailed = true;
            logView.append("⚠ 日志落盘失败，已停止写入（不影响界面）: "
                    + t.getClass().getSimpleName() + "\n");
        }
    }

    private void toast(String s) {
        Toast.makeText(this, s, Toast.LENGTH_SHORT).show();
    }
}
