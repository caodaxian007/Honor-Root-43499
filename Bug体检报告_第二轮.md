# FNE 通用提权包 · 第二轮 Bug 体检报告

> 2026-11-10 · 承接第一轮（`Bug体检报告.md`，v21，11 处）
> 结论：**又查出 25 处，已全部修复并复验**。核心不是「畸形输入会让校验器崩」，
> 而是「**一个完全自洽、格式合法的包，也能违反整包语义**」—— 上一轮的盲区。

---

## 1. 结论先说

| 分组 | 数量 | 最严重后果 |
|---|---|---|
| A · 校验规则可被合法绕过 | 9 | 物料错位 / 相互覆盖 / 夹带任意文件，而两端都判 ACCEPT |
| B · 释放与搬运链路 | 4 | 换包后旧物料被搬进 tmp；一项失败造成「半新半旧」 |
| C · 物料互绑与 ZIP 结构 | 5 | 换 e 不改 sh、重复同名条目，校验全过但设备端必失败 |
| D · 工具 / 健壮性 / 文档 | 7 | CLI 参数无效、状态误判、教程把用户引向错误操作 |
| **合计** | **25** | 已全部修复 |

**最要紧的三条**：

1. **角色与目标名没有绑定**。把 `exploit` 的 `dest` 改成 `ksud`、`ksud` 的改成 `e`，物料一个字节没动、manifest 全部自洽，PC 端和 App 端**都 ACCEPT**；释放后 `e` 位置放的是 ksud 二进制。
2. **`e` 与 `sh` 的硬编码断言完全没进校验**。换一个 200000 B 的 e、让 `build` 自动重算 `size`/`sha256`/`e_size`，校验全过；但 `fne_local.sh` 里仍是 `ESZ != 221104` 的自检，设备端直接退出。这恰恰是「必须整包」最该防的误配。
3. **搬运命令用 `cp /sdcard/.../*`**。换包后中转目录残留的旧物料会被一起搬进 tmp；而第一轮文档的 §9 已经写了「显式列出 10 个文件」，实现却没兑现。

---

## 2. 检验方法（与上一轮的区别）

上一轮验证的是「正常路径自洽 + 畸形输入不崩溃」。这一轮改成**主动构造自洽的违规包**，并交叉跑三条链路：

| 手段 | 说明 |
|---|---|
| `simulate/bugcheck_v2.py` | 18 个包（1 基准 + 17 畸形），**同时**跑 PC 端 `frp_tool.verify()` 与 App 端 `Frp.verify()`。App 端是纯 Java SE 真跑，`org.json` 来自 `android-all-13.jar`，不是拿 Python 规则代替、也不是静态看代码 |
| `FrpReleaseProbe`（脚本内生成） | 真跑 `Frp.install()` + `Frp.release()` + `copyCommand()`；在沙箱建 `/sdcard/Download/ksu_fne/` 并**预置一个旧残留文件**，观察释放与搬运后的实际内容 |
| `DupProbe` | 单独验证 Java `ZipFile.getEntry()` 与 `entries()` 遍历对**重复同名条目**的顺序差异 |
| 静态逐行审读 | `build` CLI、授权判定、流读取、`info()`、三份文档与实现的一致性 |

**约束遵守**：全程**没有修改** `fne_local.sh`、`chain_hook.sh`、`e` 中任何一个字节；新增的「物料互绑」只是**读取**脚本内容做静态比对。云电脑上也没有复现任何真机提权流程。

`DupProbe` 的实测结论（这是拒绝重复条目的依据）：

```
两个同名 manifest.json（第一个 evil、第二个合法）
  getEntry()  -> evil? 否，返回【最后一个】合法内容
  entries()#1 -> evil
  entries()#2 -> 合法
  PC verify: ACCEPT   App verify: ACCEPT     ← 包被放行
```

`ZipFile.getEntry()` 返回最后一个是**当前 JVM 的实现行为**，不是规范保证；不同 Android 版本 / ZIP 实现若返回第一个，就会变成「校验读 A、`install()` 落盘 B」。所以即使内容碰巧一致，也必须显式拒绝。

---

## 3. A 组 · 校验规则可被合法绕过（9 处）

实证脚本中的 C 组用例。修复前 **PC / App 两端结论完全一致地放行**。

| # | 用例 | 现象与后果 | 修复 |
|---|---|---|---|
| R1 | `C1_dest_swap` | 交换 `exploit`/`ksud` 的 `dest`，物料未动 → 释放后 `e` 位置是 ksud | role → dest 固定映射 |
| R2 | `C2_dest_dup` | 两个 role 的 `dest` 都写 `e` → 后者覆盖前者，物料丢失 | `dest` 全清单唯一 |
| R3 | `C4_extra_declared` | `files[]` 里多声明一项未知 `role`（含对应 ZIP 条目）→ 夹带任意文件，且 `release()` 会把它一起释放 | role 白名单 + `files[]` 恰好 10 项 |
| R4 | `C11_same_path` | `ksud` 与 `exploit` 指向同一个 `payload/e` → 少一份物料 | `path` 固定 `payload/<dest>` 且唯一 |
| R5 | `C5_str_int` | `format_version` / `size` / `e_size` 写成字符串 `"1"` / `"221104"` → **PC REJECT、App ACCEPT**，两端结论相反 | 两端统一严格 JSON 整数判定（App 停用 `optInt`） |
| R6 | `C6_e_size_missing` | 删掉 `execution.e_size` → **PC 有回退 ACCEPT、App 无回退 REJECT** | 去掉回退，两端都要求显式存在 |
| R7 | `C7_mode_value` | `exploit` 的 `mode` 写成 `0644` → 只验格式不验值，`mode` 形同虚设 | mode 由 role 唯一决定 |
| R8 | `C8_offsets_thin` | `offsets.json` 每条只留 `off_init_cred` 一个字段 → 仍通过，而文档宣称「75 字段完整」 | 覆盖 `field_dictionary` 全部 75 个 required 字段 |
| R9 | `C9_series_loose` | `kernel_series: "5.40"` → `startsWith("5.4")` 放行 | 严格 `== "5.4"` |

> `C10_abs_dest`（绝对路径 dest）是对照组，v21 已修，本轮仍正确拒绝。

---

## 4. B 组 · 释放与搬运链路（4 处）

`FrpReleaseProbe` 真跑结果（修复前）：

```
INSTALL OK / RELEASE_OK true / 中转目录已写入 10/10 项
adb shell cp /sdcard/Download/ksu_fne/* /data/local/tmp/ksu_fne/ && \
中转目录内容: OLD_STALE_e, chain_hook.sh, e, ... （残留旧文件还在）
[C3 dest 含子目录] INSTALL OK / RELEASE_OK false
  释放异常: .../sub/fne_local.sh (No such file or directory)
```

| # | 问题 | 后果 | 修复 |
|---|---|---|---|
| R10 | `dest` 允许子目录，但 `release()` 不建父目录 | 校验放行的包导入后释放直接抛异常，前面已写入的文件形成「半新半旧」 | `verify` 阶段固定 `dest` 为单文件名；`release()` 仍补 `mkdirs()` 兜底 |
| R11 | `copyCommand()` 用 `cp .../*` | 中转目录里任何残留 / 用户杂物都被搬进 tmp，破坏 e-sh 配套 | 由 `ROLES` 派生、**显式列出 10 个源文件名** |
| R12 | `release()` 不清也不提示残留 | 换包后用户不知道中转目录混了旧料 | 检测并输出提示（**不删用户文件**），命令只列 10 项 |
| R13 | 释放循环无逐项 `try/catch` | 一项失败中断全部，日志只剩「释放异常」，看不到哪几项成功 | 逐项独立 try，日志如实反映每一项 |

> 残留文件按「不擅自动用户文件」的原则保留，只提示 + 命令不搬运 —— 这比 `rm -rf` 安全，也符合历史上「tmp 属主被 root 改过」的教训。

---

## 5. C 组 · 物料互绑与 ZIP 结构（5 处）

D 组用例，全部是「物料改了 + `build` 自动重算 hash = manifest 自洽」的误配场景。

| # | 用例 | 修复前 | 修复 |
|---|---|---|---|
| R14 | `D1_e_size_vs_sh` e 换成 200000 B，sh 仍断言 221104 | 两端 ACCEPT | `fne_local.sh` 必须含 e 实际尺寸的十进制串；`assertions.e_size_in_entry_script` 与 e 实值比对 |
| R15 | `D2_sh_workdir` sh 内 workdir 改成 `.../other` | 两端 ACCEPT | 两个 sh 都必须含 `execution.workdir` 全路径 |
| R16 | `D3_chain_gate` chain 内核门改成 `5.4.999-...` | 两端 ACCEPT | 两个 sh 都必须含 ko 实际 vermagic；两条 `assertions` 断言与实值比对 |
| R17 | `D4_syms_thin` 符号表截到 100001 行 | 旧规则 `>100000` 放行 | 与 `assertions.kallsyms_lines`（207919）精确一致；未声明时 ≥ 200000 |
| R18 | `D5_dup_manifest` / `D6_dup_payload_e` 同名条目两次 | 两端 ACCEPT | ZIP 条目名唯一性检查 |

**这一组是本轮最实质的补强**：第一轮报告把「交叉校验」称为「必须整包的核心」，但当时实际只做了 e 的 ELF 头、ko vermagic、符号表行数、两个 shebang —— **sh 里的尺寸 / workdir / 内核门控断言一个都没参与校验**。现在它们与 e / ko / syms 实值逐项绑定。

---

## 6. D 组 · 工具 / 健壮性 / 文档（7 处）

| # | 问题 | 实证 / 依据 | 修复 |
|---|---|---|---|
| R19 | `build --id` / `--name` 完全无效 | `setdefault` 不覆盖模板已有值，实测 `id` 仍是模板值 | CLI 显式传值改为覆盖 |
| R20 | `build` 不强制覆盖 workdir / e_path / e_size / ko_vermagic；`meta` 非 dict 会崩；`ko_vermagic.decode()` 可能抛异常 | 静态审读 | 由物料实值强制覆盖；`meta` 类型检查；`decode("ascii","ignore")` |
| R21 | `Frp.info()` 硬编码 `offsets/offsets.json` | 自定义 `offsets_ref` 时误报「缺失」 | 改读 manifest 的 `offsets_ref`（带路径安全判断） |
| R22 | `read()` / `readAll()` 用 `> 0` / `<= 0` 判流结束 | `InputStream.read()` 返回 0 会提前截断 | 改为 `!= -1` / `< 0` |
| R23 | `hasAllFilesAccess()` 异常回退用 `canRead()` | 未授权时 `/sdcard/Download` 的 `canRead()` 也可能为 true，状态栏误判已授权 | 回退按**未授权**处理，宁可提示用户去设置页 |
| R24 | 教程仍写「并写 `active.json`」「释放第一步 `rm -rf` tmp 会被清掉」「App 会自己搬进 tmp」 | `make_tutorial.py` 第 7 节 + 避坑表 15 条；代码里根本没有 `active.json`，v21 起也不 `rm -rf` tmp | 重写教程 §7 / §6 / 避坑表，同步 `docs/包格式规范.md` §9～§11 |
| R25 | `docs` §9 承诺「显式列出 10 个文件」但实现是 `cp *`；README 写「8 个实锤」与第一轮 11 处不符、APK 路径指向 v21 | 文档审读 | 实现改为显式列出（R11），文档 / README / 教程 / 模拟报告全部同步到 v22 |

> R24 值得单独记一笔：第一轮 M4 号称修了「文档与实现矛盾」，但只改了 `docs/包格式规范.md`，**漏改了由 `make_tutorial.py` 生成的教程**，结果教程还在教用户「App 会 `rm -rf` tmp」—— 这会直接误导真机操作。本轮把生成源一起修了并重新生成。

---

## 7. 改动文件清单

| 文件 | 改动 |
|---|---|
| `app/src/com/fne/universal/Frp.java` | `ROLES` 扩为 {role, dest, mode} 三列并作唯一真源；新增 `roleSpec()` / `strictInt()`；重复条目、files 数量、白名单、dest/mode/path 绑定、offsets 全字段、物料互绑（`e` 尺寸 / workdir / vermagic / syms 行数）；`release()` 逐项 try + mkdirs + 残留提示；`copyCommand()` 显式列 10 项；`info()` / `read()` / `readAll()` |
| `app/src/com/fne/universal/MainActivity.java` | 授权 fallback 保守化；启动日志 v2.2 |
| `app/src/stubs/org/json/JSONObject.java` | 补 `opt()` / `optBoolean()` 声明 |
| `frp_tool.py` | 与 App 端逐条对齐的全部新规则；`build` CLI 覆盖、实值强制覆盖、类型健壮性 |
| `app/src/build.sh` | versionCode 21→22 / versionName `2.2-universal` / 输出 v22 |
| `simulate/bugcheck_v2.py` | **新增**：18 例交叉实证 + 释放链路实证 + 回归判定（全 PASS 才返回 0） |
| `simulate/simulate_honor70.py` | APK 路径 → v22 |
| `make_tutorial.py` / `通用提权包制作教程_5.4系.md` | §6 / §7 / 避坑表 / 交付清单重写并重新生成（541 行） |
| `docs/包格式规范.md` | §2 条目唯一、§3 类型约束、§5/§6 强绑定、§7 全字段、§8 交叉校验表、§9～§11 全面同步 v22 |
| `README.md` | 版本 / 清单 / 设计决策 / 复核命令 / 边界同步 |
| `app/_旧版_v21_规则收紧前/` | 归档 v21 APK 与 idsig |

---

## 8. 复验结果

| 项 | 结果 |
|---|---|
| `simulate/bugcheck_v2.py` | **18 PASS / 0 FAIL**（BASE ACCEPT；17 个畸形包两端全部 REJECT 且结论一致） |
| 释放链路实证 | 残留 `OLD_STALE_e` 仍在但**搬运命令不含它**；命令显式列出 10 项；C3 在**导入阶段**即被拒，不再出现半截释放 |
| `simulate/simulate_honor70.py` | **25/25 通过**（原有全套无回归） |
| 示范包 `verify` | 169 项检查、0 项不通过；`verify --json` 正常包 / 畸形包 / 非 ZIP / 文件不存在 4 场景全部输出合法 JSON |
| `build` 自检 | 新规则下重新构建素材包，自动校验 0 项不通过 |
| Java 编译 | `javac` 仅 4 条 obsolete/deprecation 警告，无 error；class 17 个 |
| APK | `app/FNERoot-通用壳-v22.apk`，**42129 B**，md5 `24db452c90a99f1c7ad2acc575186f5c`，versionCode **22** / `2.2-universal`；v1 三件套齐全、v2/v3 = true，证书 `90f74ef2…f957` 不变；零内置 assets |

---

## 9. 明确不修的边界（不是 bug，但必须知道）

1. **`.frp` 仍无数字签名**。新增的物料互绑是**静态文本匹配**：攻击者若同时改 `e`、两个 `sh`、`manifest.json` 并让四者自洽，校验依然通过。定位是**防误配**（尤其 `build` 自动重算 hash 后「换 e 没换 sh」），不是防恶意篡改。要防篡改需包外 detached 签名，同第一轮 §5.1。
2. **v1 只认官方 sh 的静态写法**。自制脚本若把 e 尺寸 / vermagic / workdir 改成变量或运行时计算，会被判「不配套」而拒绝 —— 刻意的严格，要放宽得另立 `format_version`。
3. **`fne_local.sh` 的累积日志问题不动**（按你的要求不改 sh/e）。跑前仍须 `adb shell rm -f /data/local/tmp/ksu_fne/fne_run.log`。
4. **云电脑边界**：x86_64、无 `/dev/kvm` / Android SDK / emulator。内核提权、W2 写 cred、KASLR、KernelSU late-load、Android Runtime 全都不能真跑；模拟里的 `e` 是等尺寸 stub。
5. **`v22 真机安装 / UI / 授权跳转仍待你在荣耀70 上验证** —— 这是本轮唯一没有闭环的部分。
6. 单色 `monochrome` 图标仍放在 `mipmap-anydpi-v26/`（规范性建议，不影响功能，同第一轮 §5.3）。

---

## 10. 为什么第一轮「25/25 通过」没抓到这些

诚实交代，不是掩盖：

- 第一轮的用例全是**破坏结构**（改 sha256、缺项、换 e、改 series、改 workdir），验的是「坏了能不能被拒」；本轮的用例全是**保持结构自洽、只改语义**（交换 dest、加一项声明、把数字写成字符串、换 e 后重算 hash），验的是「没坏但违规能不能被拒」。两轮是互补的，不是重复。
- 第一轮的「交叉校验」只做了 4 项，却在报告里写成「必须整包的核心」，**措辞超出了实现**；本轮把 sh 里的硬编码断言真正纳进来了。
- 第一轮只改 `docs/包格式规范.md` 就宣称修完文档矛盾，没有检查 `make_tutorial.py` 这个**生成源**，导致教程里的错误描述一直留着。
- 搬运命令的 `cp *` 在第一轮报告里被写成「显式列出 10 个文件」，但那是**修复计划**不是**已兑现的实现**，本轮实证才发现并补齐。

一句话：**第一轮验证了「异常输入不会崩」，第二轮验证了「正常输入不能骗过规则」**。
`simulate/bugcheck_v2.py` 已固化为回归测试，以后改规则先跑它。
