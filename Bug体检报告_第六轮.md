# FNE 通用提权包 · 第六轮 Bug 体检报告（v26）

> 2026-11-11 · 承接第五轮 v25 · 全程**未改动 `fne_local.sh` 与 `e` 一个字节**、未复现真机提权、
> `.frp` 的 `format_version` 仍为 `1`（格式未变）
> 实证脚本：`simulate/bugcheck_v6.py`（29 个畸形/边界包**每包单独 JVM**，交叉跑 PC `frp_tool.verify`
> 与 App `Frp.verify`；新增 `install` 落盘 harness 与「是否符合期望」判定）

---

## 1. 这一轮换的角度：**「什么算合法 JSON」到底由谁裁决**

前五轮把 `manifest.json`、`payload/*`、ZIP 容器、第二份 JSON、白名单文档逐层守严，
但都默认了一件事：**词法预检通过之后的文本，交给各自的 JSON 解析器去解析**。
本轮把这个默认翻出来看，发现它是整条链上最松的一环：

| 端 | 解析器 | 严格程度 |
|---|---|---|
| PC | Python `json.loads` | 严格 RFC 8259 |
| App | Android `org.json.JSONObject` | **宽松方言**（见下表） |

而 v24/v25 的 `jsonGuard` / `json_guard` 只查 **BOM / 非法 UTF-8 / 体积 / 括号深度 /
同对象重复键 / 大写 `NaN`+`Infinity`** 六项，既没验证字符串内的转义合法性，
也没验证字符串外的 token 是否合法。于是「合规」的最终裁决权落到了两个方言差异极大的
解析器手里 —— **同一个包，PC 拒、App 放**，甚至 App 把非标准数字当成正常整数、
认为字段与实际物料自洽而整体放行。

### org.json 方言实测（`android-all-13.jar` 真跑，非推断）

| 字面量 | org.json 解析结果 | Python `json.loads` |
|---|---|---|
| `1` | `Integer:1` | `int:1` |
| `+1` | **`Integer:1`** | `JSONDecodeError` |
| `01` | **`Integer:1`** | `JSONDecodeError` |
| `0x1` | **`Integer:1`** | `JSONDecodeError` |
| `1.` / `.5` | **`Double`** | `JSONDecodeError` |
| `nan` / `inf` / `None` / `1e` / `0b101` / `1_0` | **当字符串** | `JSONDecodeError` |
| `True` / `False` | **`Boolean`** | `JSONDecodeError` |
| `NaN` / `Infinity` / `-Infinity` | `JSONException` | `float` |
| 非法转义 `\q` | 吞掉反斜杠、保留 `q` | `JSONDecodeError` |
| `\u+072` | `Integer.parseInt` 认前导 `+` | `JSONDecodeError` |
| 字符串内裸控制字符 `0x01` | 接受 | `JSONDecodeError` |

> 这张表就是本轮所有缺陷的根：**不是某一处判断写漏，而是「词法预检」与「真实解析」
> 之间存在一整片没被裁决的方言区**。

---

## 2. 修前实测：29 例，16 处偏离

`simulate/bugcheck_v6.py` 构造 29 个定点改字节的包，每包单独 JVM 交叉跑两端，
并带**期望判定**（第五轮 G3 的教训：只判「两端一致」会放过「两个都放行」）。

### 2.1 跨端不一致（PC REJECT / App ACCEPT）—— 13 例

| 用例 | 构造 | 后果 |
|---|---|---|
| J02 / J03 / J05 | `format_version` 写 `+1` / `01` / `0x1` | App 把三者都解析成 `1`，格式版本校验被绕过 |
| J06 / J07 / J09 | 额外字段写裸 `nan` / `inf` / `True` | 词法层只挡大写 `NaN`/`Infinity`，小写与 `True` 全漏 |
| K01 | `package.name` 插入非法转义 `\q` | 词法层 `default` 分支吞掉反斜杠，org.json 也吞 → 放行 |
| K02 | 插入 `\u+072` | `Integer.parseInt("+072",16)` 认前导 `+` → 放行 |
| K05 | 字符串内裸控制字符 `0x01` | 词法层不查字符串内字符 → 放行 |
| M02 / M03 | `offsets.json` 里 `\q` / 裸 `nan` | 第二份 JSON 与 manifest 同病 |
| **P03** | `files[].size` 写 `+221104` | **App 解析成 221104，与 e 实际尺寸相等 → 整包放行** |
| **P05** | `assertions.kallsyms_lines` 写 `0x32C2F`（=207919） | **App 解析成 207919，与符号表行数相等 → 整包放行** |

P03 / P05 是最实的两例：不是「某个无关字段被忽略」，而是**校验器用来判定自洽的数值本身
被方言字面量伪造**，App 认为证据齐备。

### 2.2 两端一致放行、但应拒 —— 3 例

| 用例 | 构造 | 问题 |
|---|---|---|
| L01 | `package.id` 改成数字 `123` | PC `bool(123)` 为真；App `optString` 把数字转 `"123"` → 都放行 |
| L02 | `package.id` 改成对象 `{"a":1}` | PC `bool({})` 为真；App `optString` 转 `{"a":1}` → 都放行 |
| P06 | `package.id` 注入 `\n  [OK] 伪造：全部校验通过` | 该值进 `Result.id` 并显示在界面日志里，可伪造校验结论行 |

这三例正好复证第五轮的教训：**「两端一致」不等于「修好」**。

### 2.3 落地危害：`install` 真的把方言包写进了激活包

```
修前 INSTALL base.ok=true bad.ok=true dialectLanded=true
     (拒绝导入=false, 未落盘方言 manifest=false)
```

P03 包不仅 `verify` 放行，`install()` 也把带 `+221104` 的 manifest **落盘成 `active_pkg/`**。
后续 `info()` / `release()` 用 `new JSONObject(new String(readAll(mf)))` 再解析一次，
方言会一直跟着激活包走 —— 这已不只是「校验器分歧」，而是**污染落盘状态**。

### 2.4 对照组（修前即正确，用于确认收紧不误伤）

J01 `1.0`、J08 `-Infinity`、J10 尾随逗号、K04 `\u` 转义重复键、L03 `format` 数字、
L07 `size` 浮点、M04 offsets 重复键、N01 条目名尾随空格、P09 `e_size:false` —— 两端一致 REJECT；
J11 额外陌生字段、K03 孤立代理、M01 说明字段 `+0x`、N02 symlink 条目、
P08 `\u002d` 合法等价 —— 两端一致 ACCEPT。

---

## 3. 修复清单（两端逐条对齐，共 3 组）

### 3.1 `jsonGuard` / `json_guard` 升级为**严格 RFC 8259 词法状态机**

不再「抽查」，而是在把字节交给解析器之前，用确定性状态机统一裁决。
两端实现逐条对齐（Python `json_guard` / Java `Frp.jsonGuard`）：

**字符串内**
- 转义白名单 `" \ / b f n r t u`，其它一律拒（修 K01）；
- `\u` 后必须严格 4 位 `[0-9a-fA-F]`，不用 `Integer.parseInt` / `int()` 兜（修 K02）；
- 裸控制字符 `< 0x20` 一律拒（修 K05）。

**字符串外**
- 数字必须匹配 `-?(0|[1-9][0-9]*)(\.[0-9]+)?([eE][+-]?[0-9]+)?`，且尾部不得粘连
  非结构字符（修 J02/J03/J05/P03/P05，顺带 `1.` / `.5` / `1e` / `0x` / `0b`）；
- 裸标识符只允许精确小写 `true` / `false` / `null`（修 J06/J07/J09，
  统一覆盖 `NaN` / `Infinity` / `None` / `undefined`）；
- 结构字符 `{ } [ ] : ,` 的位置由 6 态状态机
  `VAL / VAL_REQ / KEY / KEY_REQ / COLON / DELIM` 判定，尾随逗号、双冒号、
  括号错配等一并拒绝；其它字符一律拒。

> 关键设计：**词法层成为唯一裁决者**。这样 org.json 的方言根本进不了解析器，
> 而不是「在 App 端补一堆特判去模拟 Python 的严格性」。

### 3.2 字段类型契约

- App 端 `str()` 由 `optString(k,"")` 改为 **`o.opt(k) instanceof String`**，
  非字符串一律返回 `""`（修 L01/L02，并顺带覆盖所有 `str()` 取值点）；
- PC 端 `safe_text(v)`：`isinstance(v, str)` + 非空 + `<= 256` + 无控制字符；
- 两端对 `package.id` / `package.name` / `package.ko_vermagic` 加 `safeText` 检查
  （修 P06 日志注入，顺带给出长度上限）。

### 3.3 收紧前先核官方数据（确认零误伤）

| 项 | 实测 |
|---|---|
| `str()` 涉及的全部字段类型 | 全为 `str`（含 `env.DM_PAGE_OFFSET`、`assertions.*` 字符串项） |
| 数值字段 | 全是标准十进制整数，可疑字面量 `+` / 前导零 / `0x` / 尾随点 **0 处** |
| 两份 JSON | `\u` 转义 0 处、裸控制字符 0 处 |
| ZIP 条目外部属性 | 13 条全为普通文件 `0x81a4` |

---

## 4. 复验结果

| 项目 | 结果 |
|---|---|
| `bugcheck_v6.py`（29 例） | **29/29 两端一致，且 29/29 收敛到期望结论，0 偏离、0 不一致** |
| 5 个对照组（J11/K03/M01/N02/P08） | 仍全部 ACCEPT，**零误伤** |
| P03 `install` 落盘复验 | `base.ok=true bad.ok=false dialectLanded=false`（拒绝导入、原激活包未变、方言 manifest 未落盘） |
| `bugcheck_v2.py` | **18 PASS / 0 FAIL**，install 原子性全过 |
| `bugcheck_v3.py` | **13 PASS / 0 FAIL**，A/B/C 组全过 |
| `bugcheck_v4.py` | E 组 **13/13 两端一致 REJECT**；F1 `bothOk=80/80`；F3 0.4s REJECT；F4 不 OOM |
| `bugcheck_v5.py` | **15/15 两端一致且符合期望**；H6 install 原包未变 |
| `simulate_honor70.py` | **25/25 通过** |
| 示范包 `verify --json` | `ok=true`，**179 项 / 0 不通过**（v25 为 178；本轮 -2 旧检查 +3 新检查） |
| `frp_tool.py build` 自检 | 从素材重建 → 自动 `verify` 179 项 0 不通过 |
| `verify --json` 三场景 | 合法包 / 非 ZIP / 不存在文件，均输出合法 JSON |
| v26 dex | 含 `safeText` / `jsonGuard` / `verifyContainer` / `MAX_OFFSETS_SIZE` |
| `FNERoot-通用壳-v26.apk` | 46225 B，md5 `e3605c6f51db2cc7395a2089375ffb8d`，versionCode `26`，`2.6-universal`，v1/v2/v3 全签，证书 `90f74ef2…f957` 不变 |

### 关于 F2 并发复验的一次波动（如实记）

v4 回归首轮跑出 `F2 releaseOk=29 releaseFail=1`，而 v24 报告写的是 `30/30`。
**没有直接当成退化，也没有略过**：读 harness 后确认它每轮同时起 `install` 与 `release`
两个线程，`release` 若抢在首次 `install` 之前执行，`hasActive()` 为假 →
`r.log(false, "无激活包，拒绝释放")`，这是**设计上的安全失败**（不误报成功）。
随后用同一编译产物**连跑 5 轮 × 30 次**，结果全部
`releaseOk=30 releaseFail=0 未捕获异常=0`。判定为**并发调度随机性**，
非本轮改动引入（本轮改动不触及锁与并发路径），`synchronized` 串行化仍然有效。

v25 已归档到 `app/_旧版_v25_JSON方言修复前/`。

---

## 5. 同步更新的文件

| 文件 | 变更 |
|---|---|
| `frp_tool.py` | `json_guard` 升级为严格状态机；新增 `safe_text`；`package.id/name/ko_vermagic` 改严格文本检查 |
| `app/src/com/fne/universal/Frp.java` | `jsonGuard` 同步状态机；`str()` 严格化；新增 `safeText()`；`verifyZip` 三项文本检查 |
| `app/src/com/fne/universal/MainActivity.java` | 版本串 v2.6 |
| `app/src/build.sh` | v26 / versionCode 26 / `2.6-universal` |
| `simulate/bugcheck_v6.py` | 本轮可复现实证脚本（29 例 + 期望判定 + install 落盘 harness） |
| `simulate/simulate_honor70.py` | APK 路径指向 v26 |
| `docs/包格式规范.md` | §7 / §8 校验表同步第六轮；新增 §8.3「JSON 严格词法裁决」 |
| `make_tutorial.py` / `通用提权包制作教程_5.4系.md` | 避坑表增至 26 条、附录补第六轮产物、APK 路径 v26；教程重新生成 |
| `README.md` | 版本线、交付清单、设计决策、复核命令、边界全部同步 |
| `Bug体检报告_第六轮.md` | 本报告 |

---

## 6. 仍然成立的边界（本轮明确不修，理由）

- **`.frp` 仍无数字签名**。本轮修的是「误配 / 损坏 / 畸形输入 / 解析器方言 / 字段类型」，
  **不防「构造一份满足全部内置规则的全新自洽恶意包」**。分发链路要防篡改仍需包外 detached 签名。
- **孤立代理 `\ud800`（K03）仍两端一致放行**。RFC 8259 语法上允许该转义，
  两端一致、不参与任何运行路径（只在 `name` 里展示）；修它需要在两端引入
  代理对配对状态机，收益低，记为设计选择，与第五轮 H2（README 非法 UTF-8）同一处理原则。
- **ZIP symlink 外部属性（N02）仍两端一致放行**。App 的 `java.util.zip.ZipEntry`
  **不暴露 Unix 模式位**，无法在不引入新依赖的前提下检查；且 `install()` 用
  `FileOutputStream` 写出的是 symlink 目标文本、**不会真的创建链接**，
  `release()` 也只读已落盘的普通文件 —— 无落地危害。PC `extract()` 自身已拒 symlink，
  此处仅 `verify` 不查，不构成提权面。
- **额外陌生字段（J11）仍放行**。规范未禁止，两端一致。
- **物料互绑仍是静态文本匹配**：同时改 `e` + 两个 `.sh` + `manifest.json` 让四者自洽，校验仍通过。
- `sh -n` 依赖设备上有可用 `/system/bin/sh`（真机必然有），`waitFor(timeout)` 需 Android 8.0+。
- `fne_local.sh` 内 `grep -q "child is root!" "$LOG"` 仍可能受累积日志影响 —— **按你要求不动 sh/e**。
- **v26 真机安装 / UI / 授权跳转仍待你在荣耀70 上验证** —— 云电脑无 Android Runtime，
  这是唯一没闭环的部分。
- 通用包体系**尚未同步到 GitHub 私有仓 / Release**（本轮未要求）。

---

## 7. 自省（本轮踩过的坑，如实记）

1. **探索阶段两个构造失误，靠实测纠正而非想当然**：
   - `M01` 最初把 `+0x` 替换落在 `struct_macro_5_4.task_prio`（说明性字段，不参与校验），
     实测两端 ACCEPT 是**正确行为**，改判期望为 ACCEPT 并留作对照组；
   - `N02` 第一版「symlink」其实没写 `ZipInfo.external_attr`，只是个普通包，
     后补 `S_IFLNK` 才成为真 symlink 用例。
2. **P01/P02 的十六进制值算错**：把 221104 写成 `0x35F90`（实为 221072），
     结果两端都因「值不匹配」正确 REJECT，一度误导为「hex 不绕过」；
     重算 `0x35FB0` 并改用 `kallsyms_lines = 0x32C2F`（207919）才坐实 P05。
3. **只做「字符白名单」不够**：最初设想只补转义白名单 + 数字正则，
     但那会留下「`:` / `,` 位置错误」这类结构畸形继续依赖两个解析器裁决，
     等于把分歧移到更深处。最终改成完整 6 态状态机，让词法层成为唯一裁决者。
4. **F2 波动没有直接写成「回归退化」也没有略过**：先读 harness 定位为
     `hasActive()` 的安全拒绝，再连跑 5 轮坐实随机性，见 §4。
5. `javac -source 8` 在 JDK 20 下仅 4 条 obsolete warning，非 error，构建正常。
6. **第六轮延续第五轮的方法论**：脚本必须带「是否符合期望」判定
     （L01/L02/P06 都是两端一致放行，只判一致会全部漏掉），
     且必须有 `install` 落盘 harness（否则只会看到 `verify` 分歧，看不到激活包被污染）。
