# FNE 通用提权包 · 第四轮 Bug 体检报告（v24）

> 2026-11-10 · 承接第三轮 v23 · 全程**未改动 `fne_local.sh` 与 `e` 一个字节**、未复现真机提权
> 实证脚本：`simulate/bugcheck_v4.py`（13 个畸形包**每包单独 JVM**，交叉跑 PC `frp_tool.verify` 与
> App `Frp.verify`；外加 4 项运行时 harness）

---

## 1. 这一轮换的角度

前三轮依次覆盖：

| 轮次 | 版本 | 角度 |
|---|---|---|
| 第一轮 | v21 | 畸形输入会不会让校验器崩 / 释放链路误报 |
| 第二轮 | v22 | 格式完全自洽但违反整包语义（role↔dest 绑定、物料互绑、重复条目） |
| 第三轮 | v23 | 「合规」由谁定义（规则自证 / 跨端一致性 / TOCTOU / 工具链） |

**第四轮下探到两个此前完全没碰的层面**：

- **E 组 · ZIP 容器 / 编码层**：前三轮所有用例都是「语义合法或语义畸形的 JSON」，但从没测过
  **ZIP 本身的字段、JSON 文本的字节表示、两端解析器对同一字面量的不同解释**。
- **F 组 · App 运行时状态机**：前三轮都跑单线程 `verify()`，但从没测过
  **两次导入并发、导入与释放并发、以及受限堆下的解压行为**。

---

## 2. 修复前实测（E 组，13 例）

`PC` = `frp_tool.py verify`；`App` = Java SE 真跑 `Frp.verify()`（org.json 用
`android-all-13.jar` 真实现，非编译期 stub）。每个包**单独起一次 JVM**，防止某个用例
把 JVM 拖垮后污染其它用例。

| 用例 | 构造 | PC | App | 结论 |
|---|---|---|---|---|
| E1 CRC | 把 `payload/e` 的**中央目录 CRC** 改坏（数据、sha256 都不变） | `CRASH:BadZipFile` | **ACCEPT** | 三合一 bug：PC 工具崩溃 + App 放行 + 两端相反 |
| E2 重复键 | manifest 里两个 `"format"`（前一 evil 后一合法） | ACCEPT | ACCEPT | 歧义 JSON 两端放行 |
| E3 BOM | manifest 前置 `EF BB BF` | REJECT | **ACCEPT** | 跨端结论相反 |
| E4 深嵌套 | manifest 追加 5000 层数组 | REJECT | **CRASH** | App 抛 `StackOverflowError`，`catch(Exception)` 兜不住 → 导入线程崩 |
| E5 数字字面量 | 偏移值写 `0b101` / `0o17` / `1_000` / `+0x10` / `-0x10` | **ACCEPT ×5** | REJECT ×5 | Python `int(s,0)` 认、Java `BigInteger` 不认 |
| E5_huge | 偏移值写 400 位十进制 | ACCEPT | ACCEPT | 两端一致，但无长度约束 |
| E6 伪目录 | 夹带**带 4 KB 内容**的 `payload/sneaky/`（名字以 `/` 结尾） | ACCEPT | ACCEPT | 两端都按「目录」跳过，绕过「无未声明条目」 |
| E7 NUL 条目名 | 夹带 `README\x00.md` | REJECT | REJECT | **未坐实**，如实记录 |
| E8 大 README | 白名单条目 `README.md` 换成 24 MB | ACCEPT | ACCEPT | `verify` 完全不读它、无体积上限 |

> **E 组坐实 12/13**（E7 是唯一「修前就正确」的用例，保留作为对照）。
>
> 注：E8 初版误用「追加」导致撞上重复条目，测到的是别的规则；改成「替换」后才是真体积问题。
> 这类用例自检本身也是本轮的一部分，避免误判。

### 关键判读

- **E1 的根因**：Java `ZipFile.getInputStream()` **不校验 CRC**，而 Python `zipfile.read()` 会；
  PC 端 `read_zip()` 又没把 `BadZipFile` 列进 catch，于是「一端崩、一端放」。
- **E4 的根因**：`verifyZip` / `verify` 只 `catch (Exception e)`，
  `StackOverflowError` 是 `Error`，直接冲出校验流程。真实 App 里 `doImport` 的后台线程
  没有兜底 → **进程崩溃**，不是「拒绝导入」。
- **E5 的根因**：PC `parse_num` 用 `int(s, 0)`（支持 `0b`/`0o`/下划线/前导 `+`），
  App `parseNumOk` 用 `BigInteger`（只认十进制和 `0x`）。同一个包在 PC 上「校验通过」、
  在真机上「拒绝导入」，或反过来。

---

## 3. 修复前实测（F 组，运行时状态机）

| 用例 | 方法 | 修前实测 | 修后 |
|---|---|---|---|
| F1 两次 `install` 并发 | 80 轮，每轮先建立「已有激活包」基线，再两线程同时导入 id=A / id=B 的合法包 | `bothOk=0 / 80`、`oneFail=71`、`errors=0`；`lost=0 damaged=0`（原子 rename 保住了数据，但**没有一轮两个都成功**） | `bothOk=80 / 80`、`oneFail=0`、`lost=0 damaged=0` |
| F2 `install` + `release` 并发 | 30 轮 | `releaseOk=29`、`releaseFail=1` | `releaseOk=30`、`releaseFail=0` |
| F3 `sh -n` 大畸形脚本 | 234 KB、20000 行语法错误，观察是否死锁 / 无超时 | `REJECT`，0.5 s，**未复现死锁** | 仍 `REJECT` |
| F4 大条目 + 受限堆 | 40 MB 符号表（自洽）+ `java -Xmx64m` | **CRASH（OOM）** | `REJECT`（尺寸上限挡下，不再读进内存） |

> F1 的 `lost=0 / damaged=0` 要如实说：**本轮没有复现「激活包丢失或内容损坏」**，
> 原子 `renameTo` 守住了最终状态。坐实的是「缺同步导致随机导入失败」，不是数据损坏。
> 但 `rmrf(backup)` 在竞态下可能删掉另一线程刚做的备份、使回滚失效，这是静态审查发现的
> 潜在窗口，本轮未命中，仍按缺陷处理。
>
> F3 同样如实标注：**死锁 / 超时未复现**，加固属静态防御，不计入「实证坐实」。

---

## 4. 修复清单（12 项，其中 10 项实证坐实、2 项静态审查）

| # | 问题 | 证据 | 修复 |
|---|---|---|---|
| 1 | CRC 未两端校验 | E1 | App `read()` 自算 `CRC32` 与 `ZipEntry.getCrc()` 比对；PC `read_zip` catch `BadZipFile` 收敛成 REJECT |
| 2 | JSON 重复键放行 | E2 | 两端各一份 `manifestGuard` / `manifest_guard`，确定性词法扫描拒绝同一对象内重复键 |
| 3 | BOM 跨端相反 | E3 | 同上，字节层预检拒绝 `EF BB BF` 与非法 UTF-8 |
| 4 | 超深嵌套打崩 App | E4 | 同上，嵌套 > 64 拒绝；`verifyZip` / `verify` / `install` / `release` 的顶层 catch 全改 `Throwable`；`MainActivity` 线程兜 `Throwable` |
| 5 | 数字字面量跨端不一致 | E5×5 | 两端统一正则：非负 JSON 整数 / `0[xX][0-9a-fA-F]{1,16}` / `[0-9]{1,20}`，可带 `UuLl`；不再用 `int(s,0)` 与 `BigInteger` 两套语法 |
| 6 | 偏移值无长度上限 | E5_huge | 同上，十进制 ≤ 20 位、十六进制 ≤ 16 位 |
| 7 | 目录条目夹带 | E6 | 两端把 `/` 结尾条目也纳入 `entryNames` / `names`，参与「无未声明条目」；`allowed` 白名单固定为内置路径 |
| 8 | 条目 / 总体积无上限 | E8 | 内置 7 个常量（下表），两端逐字一致 |
| 9 | 大条目 OOM | F4 | `read()` 边读边累计、超 `MAX_ENTRY_SIZE` 立即放弃，不信 ZIP 头声明的 `size` |
| 10 | 并发无同步 | F1/F2 | `install()` / `release()` 改 `synchronized` 静态方法，串行化共享的 `.staging` / `active_pkg.tmp` / `.bak` |
| 11 | `sh -n` 无超时 / 潜在 stdin-stderr 死锁 | **静态审查**（F3 未复现） | 先启动 stdout/stderr 排空线程再写 stdin；`waitFor(10s)` 超时 `destroyForcibly` fail-closed；脚本 ≤ 2 MB；catch `Throwable` |
| 12 | `install` 落盘用 `> 0` 判流结束 | **静态审查** | 改 `!= -1`；`InflaterInputStream` 返回 0 时不会写出被截断的物料 |

### 内置资源上限（两端逐字一致）

| 常量 | 值 | 官方示范包实测 |
|---|---|---|
| `MAX_PKG_SIZE` | 64 MB | 压缩后 8.8 MB |
| `MAX_ENTRIES` | 64 | 13 条 |
| `MAX_ENTRY_SIZE` | 16 MB | 最大 11,095,147 B（`fne_syms.txt`） |
| `MAX_TOTAL_SIZE` | 48 MB | 25,024,800 B |
| `MAX_MANIFEST_SIZE` | 64 KB | 4,716 B |
| `MAX_JSON_DEPTH` | 64 | 正常 3～4 层 |
| `MAX_SCRIPT_SIZE` | 2 MB | 最大 11,517 B（`chain_hook.sh`） |

**修复前先核过官方数据**：13 个文件条目、**无目录条目**、偏移值 825 个全是 `0x` 十六进制
（最长 `0xFFFFFFC010080000`，16 位）、无负号 / 加号 / 下划线 / `0b` / `0o`、manifest 无 BOM。
所以上述收紧**不会误伤合法包** —— 这一点在合法包 `verify` 上已复验（175 项 / 0 不通过）。

---

## 5. 复验结果

| 项目 | 结果 |
|---|---|
| `simulate/bugcheck_v4.py` E 组 | **13/13 两端一致 REJECT**（含 E7 对照） |
| F1 并发 | `bothOk=80/80`、`oneFail=0`、`lost=0`、`damaged=0` |
| F2 并发 | `releaseOk=30/30`、`releaseFail=0`、未捕获异常 0 |
| F3 / F4 | `REJECT` / `REJECT`（不再 OOM，不再崩溃） |
| `simulate/bugcheck_v2.py`（第二轮回归） | **18 PASS / 0 FAIL** |
| `simulate/bugcheck_v3.py`（第三轮回归） | **13 PASS / 0 FAIL** |
| `simulate/simulate_honor70.py`（全套模拟） | **25/25 通过** |
| 示范包 `verify --json` | `ok=true`，**175 项 / 0 不通过** |
| `verify --json` 三场景 | 合法包 / 非 ZIP / 不存在文件，均输出合法 JSON |
| `frp_tool.py build` 自检 | 从素材重建 → 自动 `verify` 通过 |
| `FNERoot-通用壳-v24.apk` | 46225 B，md5 `4c90bfba1d5dbce9ceb91cb8b91b9ecb`，versionCode 24，`2.4-universal`，v1/v2/v3 全签，证书 `90f74ef2…f957` 不变 |

v23 已归档到 `app/_旧版_v23_容器层修复前/`；`.frp` 的 `format_version` 仍是 `1`，**格式未变**。

---

## 6. 同步更新的文件

| 文件 | 变更 |
|---|---|
| `frp_tool.py` | 内置常量、`parse_num` 重写、`manifest_guard`、`read_zip` 收敛 CRC、条目/体积检查、目录条目纳入夹带、`sh -n` 超时与尺寸上限 |
| `app/src/com/fne/universal/Frp.java` | 同上两端对齐；`read()` CRC32 + 流式上限；`manifestGuard`；`parseNumOk` 正则；`catch Throwable`；`install`/`release` synchronized；`shSyntaxOk` 排空线程 + 超时；落盘 `!= -1` |
| `app/src/com/fne/universal/MainActivity.java` | 版本字符串 v2.4；导入/释放线程兜 `Throwable` |
| `app/src/build.sh` | v24 / versionCode 24 / `2.4-universal` |
| `simulate/bugcheck_v4.py` | 本轮可复现实证脚本（新增） |
| `simulate/simulate_honor70.py` | APK 路径指向 v24 |
| `docs/包格式规范.md` | 新增 §8.1 容器层与资源上限；§7/§8/§9/§10/§11 同步；v24 修复清单表 |
| `make_tutorial.py` / `通用提权包制作教程_5.4系.md` | §6 校验项、避坑表增至 20 条、附录补第四轮产物；教程重新生成（569 行） |
| `README.md` | 版本线、交付清单、设计决策、复核命令、边界全部同步 |

---

## 7. 仍然成立的边界（不因本轮改变）

- `.frp` **没有数字签名**。本轮新增的词法预检、CRC、体积上限、两端正则对齐，定位是
  **防误配 / 防损坏 / 防散件 / 防畸形输入**，不防「攻击者构造一份满足全部内置规则的全新恶意包」。
  分发链路要防篡改，仍需包外 detached 签名。
- 物料互绑仍是**静态文本匹配**：同时改 `e` + 两个 `.sh` + `manifest.json` 让四者自洽，校验仍通过。
- `sh -n` 依赖设备上有可用 `/system/bin/sh`（真机必然有），`waitFor(timeout)` 需 Android 8.0+
  （荣耀70 满足）；极端环境无 sh 时 fail-closed 拒绝导入。
- `fne_local.sh` 内 `grep -q "child is root!" "$LOG"` 仍可能受累积日志影响 —— **按你要求不动 sh/e**，
  靠跑前 `rm -f fne_run.log` 规避。
- **v24 真机安装 / UI / 授权跳转仍待你在荣耀70 上验证** —— 云电脑无 Android Runtime，
  这是唯一没闭环的部分。
- 本轮**未复现**「并发导致激活包丢失/内容损坏」（F1 `lost=0 damaged=0`），也**未复现**
  `sh -n` 死锁（F3 0.5 s 正常 REJECT）；对应加固是静态审查驱动的防御，不冒充实证结论。
- 通用包体系**尚未同步到 GitHub 私有仓 / Release**（本轮未要求）。
