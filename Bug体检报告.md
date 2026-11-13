# FNE 通用提权包 · Bug 体检报告

> 2026-11-10 · 针对上一轮交付的 `.frp` 格式 / 工具 / 通用壳 App / 模拟器做全面复核
> 结论：**有问题，共查出 11 处，已全部修复并复验**。其中 4 处会直接导致 App 不可用、误报成功或丢数据。

---

## 1. 结论先说

| 等级 | 数量 | 状态 |
|---|---|---|
| 高危（功能失效 / 误报成功 / 数据丢失 / 崩溃） | 4 | 已修 + 实证 |
| 中危（校验可被绕过 / 输出不合规 / 文档与实现矛盾） | 4 | 已修 + 实证 |
| 低危（健壮性 / 一致性 / 多余权限） | 3 | 已修 |
| 设计边界（非 bug，已写明） | 4 | 不擅自改，见 §5 |

**数据层是干净的**：`offsets_5.4.json` 11 条内核 × 75 字段全部齐全、无 `None`、无非 5.4 条目；教程里 11 行内核表与 JSON 完全一致；示范包 10 项物料 md5 与官方物料一致。问题都出在**校验器健壮性、App 运行时逻辑和文档同步**上。

---

## 2. 高危 4 处

### H1 · `install()` 会删掉旧激活包，还提示「原激活包保持不变」

- **位置**：`Frp.java` 原 298–302 行
- **现象**：`active.renameTo(backup)` 若失败，代码只把 `r.ok` 置 false 却继续往下走；紧接着 `tmp.renameTo(active)` 因 active 仍在而失败 → 进入 `else { rmrf(active); if (backup.exists()) backup.renameTo(active); }` → **无条件删掉旧包**，而 backup 并不存在，无法恢复。界面同时显示「导入失败 ✘（原激活包保持不变）」，与事实相反。
- **影响**：一次失败的导入会永久丢失当前激活的完整包。
- **修复**：每一步 rename 失败都立即 `return` 并保留 active；只有确认 `backedUp && backup.exists()` 才清理并回滚；`staging` 内容不完整也提前退出。
- **实证**：`simulate/FrpInstallTest.java` 真跑 App 端 `Frp.install()` —— 畸形包被拒后 `active_pkg/manifest.json` md5 逐字节未变（`fd62faa3…`），重复导入后 `staging/tmp/bak` 全部清理。

### H2 · `release()` 误报「释放完成 ✔」，且 `rm -rf` 可能清掉用户布置的 tmp

- **位置**：`Frp.java` 原 386–397 行
- **现象**：App 以 `untrusted_app` uid 执行 `rm -rf /data/local/tmp/ksu_fne; cp /sdcard/... ; chmod ...`，几乎必然 `Permission denied`；但代码只把 shell 输出贴进日志、**不检查失败关键字**，`r.ok` 只由「sdcard 写文件成功」决定 → 界面显示「释放完成 ✔」，而 tmp 里什么都没有。这正是之前反复踩过的「假 success」。
- **更糟**：如果曾用 root 跑过 App（用户第 55 条明确遇到过），tmp 属主可能变成 app，那条 `rm -rf` 会真的执行，把用户手工布置的物料清空。
- **修复**：删掉写 tmp 的整段 shell，App 只做**只读** `ls -l` 探测；明确区分「中转目录已写入」与「tmp 已就位」，并输出可复制的 adb 搬运命令（显式列出 10 个文件，不用 Android sh 不保证支持的 `{}` 展开）。
- **依据**：用户原话「APP 释放可以使用 adb 或者使用文件管理」—— 搬 tmp 本来就该交给 adb / 文件管理器。

### H3 · 声明了 `MANAGE_EXTERNAL_STORAGE`，却没有任何授权引导

- **现象**：Manifest 有该权限，但全代码 `isExternalStorageManager` / `ACTION_MANAGE_APP_ALL_FILES_ACCESS_PERMISSION` **命中 0 次**。Android 11+ 这个权限必须由用户在系统设置里手动开启，装完不手动开 → `Frp.scan()` 扫不到 `/sdcard/Download/*.frp` → App 显示「未发现 .frp」，整个流程走不下去。
- **这是历史上踩过的同一个坑**（「officiale 的获取储存权限咋又没了」）。
- **修复**：新增「⚙ 授权文件访问」按钮直达系统设置页；`onResume()` 返回时刷新状态；未授权时状态栏红字警示 + `scan()` 前再提示一次。

### H4 · `frp_tool.py verify` 遇畸形 manifest 直接崩溃，而不是拒绝

- **实证**：往 `files[]` 塞一个字符串 / `None`，`f.get("path")` 抛 `AttributeError: 'str' object has no attribute 'get'`。
- **影响**：畸形包不是「被拒绝」，是让校验器挂掉；批量/脚本调用时无法拿到结论。
- **修复**：`files` 必须是数组、每项必须是对象、`path`/`dest` 必须过 `safe_name()`（且 `safe_name` 现在先判 `isinstance(str)`）；`read_zip()` 对非字符串 name 直接返回 `None`。

---

## 3. 中危 4 处

| # | 问题 | 实证 | 修复 |
|---|---|---|---|
| M1 | **夹带清单外条目被放行**：塞一个 `payload/evil.sh` 进包，`verify` 仍 ACCEPT；而 `build` 会把素材目录里**所有**文件（含临时/备份文件）塞进包 | 实证② 修前 ACCEPT | 加「包内条目白名单」检查；`build` 只打包 `files[]` 声明的 10 项 + `offsets.json` + `README.md` |
| M2 | **同一 role 重复声明被放行**：两份 `exploit` 也 ACCEPT | 实证③ 修前 ACCEPT | 每个 role **恰好 1 项**，PC 端与 App 端同步 |
| M3 | `--json` 输出不是纯 JSON：`vprint` 无条件逐行打印，早期失败（包不存在 / 非 ZIP）更是只输出纯文本 | 4 场景实测全部解析失败 | `as_json` 时静默收集、统一 `finish()` 输出单一合法 JSON；所有提前返回路径都走 `finish()` |
| M4 | **文档与实现矛盾**：`docs/包格式规范.md` §9 还写「写 `active.json`」「释放第一步是 `rm -rf` tmp 会被清掉」，而代码里根本没有 `active.json`，v21 也不再 `rm -rf` | 文档审读 | 重写 §9（含 v21 释放流程与授权要求），新增 §10 版本兼容、§11 威胁模型与 v21 校验补齐表 |

---

## 4. 低危 3 处（顺手修）

| # | 问题 | 修复 |
|---|---|---|
| L1 | `MainActivity.doExec()` 会**真跑** `sh /data/local/tmp/ksu_fne/fne_local.sh 2>&1 \| head -20`，可能污染累积 `fne_run.log`（用户明确说过不要反复复现、且累积日志会误报「ROOT 到手」） | 删掉真跑，只保留「复制执行命令到剪贴板」；新增「📋 复制搬运命令」按钮 |
| L2 | `build.sh` 里 `javac ... 2>&1 \| grep -v ... \|\| true` 用管道吞掉 javac 的退出码，编译失败可能被掩盖 | 改为输出落 `javac.log`，失败立即 `cat` 并 `exit 1` |
| L3 | 模拟用例 B4 依赖交付目录**之外**的工程包文件（找不到就记 FAIL）；`AndroidManifest` 有 App 用不到的 `INTERNET` 权限；`files[].dest` 缺路径穿越检查 | B4 改从仓库内 `289_baseline/e` 取真料、等尺寸假 e 兜底；删 `INTERNET`；`dest` 补 `safe_name`。另给 `parse_num` 加了 `"08"` 前导零的十进制回退 |

---

## 5. 明确不修的 4 个边界（不是 bug，但必须知道）

1. **`.frp` 没有数字签名**。manifest 可整体伪造（替换 `e` 后同步改 `size` / `sha256` / `e_size`，校验仍会通过）。校验器的定位是**防误配 / 防损坏 / 防散件导入**，不是防恶意篡改。需要防篡改得在包外做 detached 签名并先验签 —— 这会改变格式，本轮不擅自动，已写进 `docs/包格式规范.md` §11。
2. **`fne_local.sh` 里 `grep -q "child is root!" "$LOG"` 仍受累积日志影响**。按你「不要再去修改 sh 或者 e」的要求不动，靠跑前 `adb shell rm -f .../fne_run.log` 规避，README 和 App 命令里都写死了。
3. **单色 `monochrome` 图标放在 `mipmap-anydpi-v26/`**。规范做法是另建 `-v33` 版本，但旧系统解析 adaptive-icon 时忽略未知属性，不会崩；minSdk 24 还有 5 档 PNG fallback。属于规范性建议，不影响功能。
4. **内核提权无法在云电脑模拟**。x86_64、无 `/dev/kvm` / Android SDK / emulator，`e` 是 aarch64 内核态利用 —— 物理限制，报告首段已写死。

---

## 6. 为什么上一轮的「22/22 通过」没抓到这些

诚实交代，不是掩盖：

- 上一轮模拟只覆盖 **5 类篡改**（sha256 / 缺项 / 换 e / kernel_series / workdir），**没有测畸形 manifest、夹带条目、重复 role**，所以 M1/M2/H4 全在盲区。
- App 端只做了**静态检查**（dex 类存在、图标资源、签名），**没有实例化 `Frp.verify()` / `Frp.install()`**；H1/H2 的失败分支只有真跑才会暴露。
- H3（授权引导）和 H2 的 `rm -rf` 风险属于 **Android 运行时行为**，云电脑无 emulator，只能靠逐行审读发现 —— 上一轮是「看到编译通过 + 22 项自洽」就收了口，静态审读做得不够。
- 换句话说：**上一轮验证的是「正常路径自洽」，不是「异常路径健壮」**。这一轮补的正是后者。

本轮的关键改进是发现 `Frp.java` **不 import 任何 `android.*` 类**，因此可以用纯 Java SE 在云电脑里直接编译、实例化，写了 `FrpVerifyTest.java` / `FrpInstallTest.java` 两个 harness **真跑 App 端校验器与导入器**，而不是拿 Python 规则代替或只看代码。

---

## 7. 复验结果

| 项 | 结果 |
|---|---|
| PC 端畸形/篡改用例 | 10 个全部 REJECT；正常示范包 ACCEPT（修前 3 个被放行、1 个崩溃） |
| `verify --json` | 正常包 / 畸形包 / 非 ZIP / 文件不存在 4 场景，**全部输出合法 JSON** |
| App 端 Java 实测 | F0 编译成独立 harness ✔；F1 `Frp.verify` 5 个包结论与 PC 端逐包一致、无崩溃 ✔；F2 `install` 原子导入 / 失败保留 / 释放源完整 / 临时目录清理 4 项全过 ✔ |
| 完整模拟 | **25/25 通过**（原 22 项 + 新增 3 项 Java 实测） |
| 示范包 | 重新构建，条目收敛为 13 个（README + manifest + 10 payload + offsets），`verify` 0 项不通过 |
| APK | `FNERoot-通用壳-v21.apk`（38033 B，md5 `21a548dd…`），versionCode **21** / versionName `2.1-universal`，v1+v2+v3 全签，证书 `90f74ef2…f957` 不变 |
| 数据层 | 11 内核 × 75 字段全齐、无 `None`、教程表与 JSON 一致 |

**版本说明**：v21 与 v20 同包名同证书，可直接覆盖安装（不会掉「所有文件访问权限」）；`.frp` 格式未变，v20 制作的包仍可用。

---

## 8. 改动文件清单

| 文件 | 改动 |
|---|---|
| `frp_tool.py` | H4 / M1 / M2 / M3 + `build` 只打包声明文件 + `safe_name` / `parse_num` / `read_zip` 健壮性 + 临时文件必清理 |
| `app/src/com/fne/universal/Frp.java` | H1 / H2 / M1 / M2 + `dest` 路径检查 + 新增 `copyCommand()` |
| `app/src/com/fne/universal/MainActivity.java` | H3 / L1 + 授权按钮 + 搬运命令按钮 + 未授权提示 + `onResume` 刷新 |
| `app/src/AndroidManifest.xml` | 删多余 `INTERNET` |
| `app/src/build.sh` | L2（不再吞 javac 退出码）+ 版本号 20→21 / 输出文件名 v21 |
| `simulate/simulate_honor70.py` | L3（B4 可移植）+ APK 路径 v21 + 新增 `case_java()` + 报告 §2.3 |
| `simulate/FrpVerifyTest.java`、`FrpInstallTest.java` | 新增：纯 Java SE harness，真跑 App 端校验器/导入器 |
| `docs/包格式规范.md` | M4：重写 §9、新增 §10 / §11 |
| `README.md` | 版本同步 + v21 修复说明 + 授权/搬运步骤 + 边界 |
| `Bug体检报告.md` | 本文件 |
