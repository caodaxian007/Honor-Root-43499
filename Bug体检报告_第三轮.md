# FNE 通用提权包 · 第三轮 Bug 体检报告（v23）

> 2026-11-10 · 承接「继续检验 bug / 继续寻找 bug」
> 交付：`app/FNERoot-通用壳-v23.apk`（42129 B，md5 `4c519802…f95e`，versionCode 23 / `2.3-universal`，v1+v2+v3 全签，证书 `90f74ef2…f957` 不变）
> 全程**未改动 `fne_local.sh` 与 `e` 一个字节**，也未在真机复现提权。

---

## 0. 这一轮换了什么角度

| 轮次 | 测什么 | 结论 |
|---|---|---|
| 第一轮（v21） | 畸形输入会不会让校验器**崩溃** | 11 处 |
| 第二轮（v22） | 格式合法但**违反整包语义**（dest 错位、夹带、重复条目、跨端差异） | 25 处 |
| **第三轮（v23）** | ① **规则自证**：校验基准本身写在包里，包改规则就跟着改；② **PC/App 检查项不对齐**；③ **校验→落盘链路与工具链** | **14 处** |

前两轮都在问「这个包合不合规」。第三轮问的是：**「合规」这件事由谁定义？** 结果发现校验器把「必备字段清单、符号表行数期望、偏移表路径、入口脚本名」都从包内 `manifest.json` / `offsets.json` 读取——攻击者同时改包内规则和物料，就能让校验器「自己出题自己判卷」。

新实证脚本 `simulate/bugcheck_v3.py`：13 个畸形包交叉跑 **PC `frp_tool.verify`** 与 **App `Frp.verify`（纯 Java SE 真跑，org.json 用 android-all-13.jar）**，外加 4 项工具/链路实证（含 `install` 竞态 harness）。

---

## 1. A 组：规则自证（8 例，修前 6 例放行）

校验基准写在包里，等于让被检查对象自己定义检查标准。

| 用例 | 修前实测（PC / App） | 危害 |
|---|---|---|
| **A1** `field_dictionary` 砍到 1 项 + 11 条内核 `offsets` 各只剩 1 字段 | ACCEPT / ACCEPT | 第二轮宣称的「75 字段全量校验」形同虚设：包说 1 个字段就只查 1 个 |
| **A2** 74 项标 `required:false` + 内核 offsets 同步只剩 1 字段 | ACCEPT / ACCEPT | 规则开关由包自己拨 |
| A3 `required` 写成字符串 `"false"` + 删 1 条 `off_init_cred` | REJECT / REJECT | 两端「碰巧」都拒，但解析语义不同（`optBoolean` vs truthy），属于潜在分歧 |
| **A4** `assertions.kallsyms_lines` 改成 1 + 符号表截成 1 行并重算 sha256 | ACCEPT / ACCEPT | 期望行数由包自述，1 行符号表直接放行，设备端 `fake_ksyms` 必挂 |
| **A5** `kernel_releases` 加 2 个假内核，偏移表只覆盖原来 1 个 | ACCEPT / ACCEPT | 旧规则「至少覆盖一个」，声明 3 个内核只给 1 份偏移数据也过 |
| **A6** `offsets_ref` 改成 `payload/offsets_evil.json` 并删原表 | ACCEPT / ACCEPT | 规范写死路径却未校验；且该路径被自动加入「允许条目」白名单，等于开了夹带后门 |
| **A7** `entry_script` 改成 `other.sh` | ACCEPT / ACCEPT | 只查非空，与 `copyCommand()` / `execCommand()` 写死的 `fne_local.sh` 脱节 |
| A8 `kernels` 只留 1 条且 `uname_r=5.4.999-qgki-notreal` | REJECT / REJECT | 旧规则靠覆盖检查拦住，修后靠「全覆盖」继续拦 |

**根因**：`OFFSET_FIELDS`（75 字段名）、`MIN_KALLSYMS_LINES`、`OFFSETS_REF`、`ENTRY_SCRIPT` 全部应该属于**格式规范**，却从包内自述读取。

---

## 2. B 组：PC / App 检查项不对齐（4 例，修前全部「PC 拒 / App 放」）

两端宣城「同一套规则」，实际 PC 端有 4 项 App 端没有：

| 用例 | 修前 PC | 修前 App | 缺的检查 |
|---|---|---|---|
| **B1** `off_init_cred` 值改成 `"garbage"` | REJECT | ACCEPT | PC 有 `parse_num`，App 只查「键是否存在」 |
| **B2** ELF `e_machine` 高字节改成 1（EM=0x1B7） | REJECT | ACCEPT | PC 读 2 字节 `0x00B7`，App 只查低字节 `0xB7` |
| **B3** `fne_local.sh` 追加一行语法错误 | REJECT | ACCEPT | PC 跑 `sh -n`，App 完全不查语法 |
| **B4** `off_init_cred = null` | REJECT | ACCEPT | Java `opt()` 对 JSON null 返回 `JSONObject.NULL`，被当成「存在」 |

> **B3 修复的一个关键判断**：一开始想用「静态括号/关键字配平」在 App 端复刻 `sh -n`，实测发现**官方脚本本身就不配平**——`fne_local.sh` 圆括号差 -10、`chain_hook.sh` 有跨行引号且 `if`/`fi` 计数 18/16（`case` 模式与注释里的括号/关键字所致）。启发式会误伤合法脚本，因此**否决**。
> 正解：两端都跑**真正的 `sh -n`**，脚本从 **stdin** 喂入（零临时文件、零执行、真机 `/system/bin/sh` 与云电脑 `sh` 都可用，极端无 sh 时 fail-closed 拒绝）。PC 端原先把 `FileNotFoundError` 静默 `pass`（等价于放行）也一并修掉。

---

## 3. C 组：链路与工具链（4 项）

| 项 | 修前实测 | 修复 |
|---|---|---|
| **C1** `frp_tool.py inspect` 畸形 manifest | `KeyError: 'package'` 未捕获崩溃 | 全部走 `.get()` + 顶层异常捕获，友好报错并 `sys.exit(1)` |
| **C2** `extract` 目标目录预置符号链接 `payload -> /tmp/x` | 物料被写出 dest 之外（5 个文件逃逸） | 解包前拒绝 dest 子树内任何符号链接；逐条目 `realpath` 越界检查；父目录是链接也拒绝 |
| **C3** `install` 两次独立打开 ZIP | **竞态 harness 22 次尝试命中 20 次「校验合法包、落盘恶意包」**，对照组正常 | `verify` 拆出 `verifyZip(ZipFile, Result)`；`install` 只 `new ZipFile(pkg)` **一次**，校验与落盘共用同一句柄 |
| **C4** `build` 沿用模板 `assertions.kallsyms_lines=1` + 换 1 行符号表 | 产出「校验通过但设备端必挂」的包 | `build` 从实际物料**重算并覆盖** `assertions`（行数 / e 尺寸 / vermagic），并强制覆盖 `entry_script` |

C3 是本轮最严重的一处：`verify(pkg)` 打开并关闭一次 ZIP，落盘时又 `new ZipFile(pkg)` 重新打开。`.frp` 位于 `/sdcard/Download/`（共享可写），中途被替换就会出现「校验的是 A、落盘的是 B」。

---

## 4. 修复清单（两端 + 工具 + 文档同步）

**内置常量（PC `frp_tool.py` / App `Frp.java` 逐字一致）**
- `OFFSET_FIELDS`：75 个必备字段名（带 `assert len == 75` 自检）；`field_dictionary` 降级为**说明文档**，不再参与判卷
- `MIN_KALLSYMS_LINES = 200000`：行数硬下限恒成立，`assertions.kallsyms_lines` 只做一致性核对，不能放宽下限
- `OFFSETS_REF = "offsets/offsets.json"`、`ENTRY_SCRIPT = "fne_local.sh"`：固定值强校验
- 偏移值必须可解析数字：`parse_num`（PC）/ `parseNumOk`（App，含 `JSONObject.NULL`、布尔、非数字串判定）

**规则收紧**
- `kernel_releases` **全覆盖**（不是「至少一个」）；`uname_r` 不重复且必须 5.4 系
- `e` 的 `e_machine` 两字节校验 `0x00B7`
- 两端都真跑 `sh -n`（stdin，fail-closed）

**链路 / 工具**
- `install` 单次打开 ZIP（`verifyZip` 共用句柄）→ 消除 TOCTOU
- `build` 从物料重算 `assertions`；`inspect` 防崩；`extract` 防符号链接逃逸

**文档**：`docs/包格式规范.md`（§5/§7/§8/§9/§10/§11）、`make_tutorial.py` 及生成的 `通用提权包制作教程_5.4系.md`（556 行）、`README.md` 全部同步到 v23。

---

## 5. 复验结果

| 检验 | 结果 |
|---|---|
| `simulate/bugcheck_v3.py`（本轮 13 例 + 4 项工具/链路） | **13 PASS / 0 FAIL，C 组全部通过**，退出码 0 |
| `simulate/bugcheck_v2.py`（第二轮 18 例） | **18 PASS / 0 FAIL**，无回归 |
| `simulate/simulate_honor70.py`（全套模拟） | **25/25 通过** |
| 示范包 `verify --json` | `ok=true`，170 项检查 / 0 不通过；畸形输入与不存在文件也都返回合法 JSON |
| `install` TOCTOU 竞态（修复后） | `tried=22 ok=22 mismatch=0 control=OK` |
| v23 APK | 42129 B，md5 `4c519802…f95e`，v1/v2/v3 全签，证书不变；dex 内含 `OFFSET_FIELDS` / `MIN_KALLSYMS_LINES` / `parseNumOk` / `shSyntaxOk` |

v22 已归档到 `app/_旧版_v22_规则自证修复前/`。

---

## 6. 遗留边界（必须说清）

1. **`.frp` 仍无数字签名**。v23 把基准内置到代码，只堵住「改包内规则就能自证」；攻击者构造一份**满足全部内置规则的全新恶意包**，校验依然会通过。定位仍是**防误配 / 防损坏 / 防散件导入**，不是防恶意篡改。分发链路要防篡改需在包外做 detached 签名。
2. **物料互绑仍是静态文本匹配**：同时改 `e` + 两个 `.sh` + `manifest.json` 让四者自洽，仍可绕过（同第一轮起的既有边界）。
3. **`sh -n` 依赖设备上有可用 sh**：真机 `/system/bin/sh` 必然存在；若极端环境无可用 sh，App 端 fail-closed **拒绝导入**（不会静默放行）。这是刻意选择。
4. **自制 sh 的严格性不变**：把 e 尺寸 / vermagic / workdir 改成变量或运行时计算会被判「不配套」；v1 只认官方 sh 的静态写法。
5. **v23 真机安装 / UI / 授权跳转 / `sh -n` 在 Android 上的实际行为仍待主人在荣耀70 验证**——这是本轮唯一没闭环的部分。云电脑是 x86_64 Linux，无 Android Runtime、无 KVM，内核提权与 App 真机交互无法模拟。
6. 通用包体系**尚未同步到私有 GitHub 仓库 / Release**（本轮未要求）。
7. 按你的要求，`fne_local.sh` 内累积日志 `grep -q "child is root!" "$LOG"` **未改动**，跑前仍需 `rm -f fne_run.log`。

---

## 7. 复现命令

```sh
cd FNERoot_通用提权包
python3 simulate/bugcheck_v3.py          # 第三轮 13 例 + 4 项链路
python3 simulate/bugcheck_v2.py          # 第二轮回归
python3 simulate/simulate_honor70.py     # 全套模拟 25 项
python3 frp_tool.py verify packages/FNE-AN00-5.4.295.frp --json
bash app/src/build.sh                    # 重新编译 v23
```
