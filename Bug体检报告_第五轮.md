# FNE 通用提权包 · 第五轮 Bug 体检报告（v25）

> 2026-11-11 · 承接第四轮 v24 · 全程**未改动 `fne_local.sh` 与 `e` 一个字节**、未复现真机提权
> 实证脚本：`simulate/bugcheck_v5.py`（15 个畸形/边界包**每包单独 JVM**，交叉跑 PC `frp_tool.verify` 与
> App `Frp.verify`；外加 1 项 `install` 落盘 harness）

---

## 1. 这一轮换的角度：**校验器看不见的两块「免检区」**

前四轮依次把 `manifest.json` 和 `payload/*` 守得越来越严：

| 轮次 | 版本 | 角度 |
|---|---|---|
| 第一轮 | v21 | 畸形输入会不会让校验器崩 / 释放链路误报 |
| 第二轮 | v22 | 格式完全自洽但违反整包语义（role↔dest 绑定、物料互绑、重复条目） |
| 第三轮 | v23 | 「合规」由谁定义（规则自证 / 跨端一致性 / TOCTOU / 工具链） |
| 第四轮 | v24 | ZIP 容器层（CRC / BOM / 深嵌套 / 数字字面量 / 伪目录 / 体积）+ 运行时并发 |

**第五轮不看「规则严不严」，改看「规则覆盖到了没有」**。逐个文件核对 `.frp` 里每个成员到底
有没有被校验，发现两处此前完全没碰的盲区：

- **`offsets/offsets.json` 是包内第二份独立 JSON**。第四轮给 `manifest.json` 加了
  `manifestGuard()`（BOM / 非法 UTF-8 / 重复键 / 深度预检），但 offsets.json 一直是
  `new JSONObject(new String(bytes,"UTF-8"))` / `json.loads(off_raw.decode())` 直接解析，
  **零词法预检**。
- **`README.md` 是白名单文档，从不被任何一端 `read()`**。第四轮 E1 给「被读取的条目」加了
  CRC32，但白名单条目不读取、不查 CRC；E8 只测了它的体积，没测 CRC 与「ZIP 头声明 size 伪造」。

同时补测一类第四轮没收口的差异：**JSON 裸整数字面量在两端解析器里的类型分歧**（PC 无限精度
int vs org.json 的 Integer/Long/Double）。

---

## 2. 修前实测（G/H 组，12 例）

`PC` = `frp_tool.py verify`；`App` = Java SE 真跑 `Frp.verify()`（org.json 用
`android-all-13.jar` 真实现）。每个包**单独起一次 JVM**。

| 用例 | 构造 | PC | App | 结论 |
|---|---|---|---|---|
| G1 offsets 非法 UTF-8 | `offsets.json` 的 `series` 值塞入 `0xFF`（CRC 重算正确） | REJECT | **ACCEPT** | 跨端相反 |
| G2 offsets BOM | `offsets.json` 前置 `EF BB BF` | REJECT | **ACCEPT** | 跨端相反 |
| G3 offsets 重复键 | 放两个 `kernels` 键（前空数组 / 后合法 11 内核） | ACCEPT | ACCEPT | **应拒未拒**（manifest 同类已拒，规则不对称） |
| G4 offsets 深嵌套 | 追加 5000 层嵌套数组 | REJECT | REJECT | 对照（两端靠异常兜底，非空词法拒绝） |
| G5 offsets NaN | 偏移值写裸 `NaN` 字面量 | REJECT | REJECT | 对照（路径不同：PC `json.loads` 认 / App 抛异常） |
| G6 偏移大整数 | 偏移值写 JSON 整数 `18446744073709551615`(2^64-1) | **ACCEPT** | REJECT | 跨端相反 |
| H1 README CRC 坏 | `README.md` 中央目录 CRC 改坏（数据不变） | REJECT | **ACCEPT** | 跨端相反 |
| H2 README 非法 UTF-8 | `README.md` 塞 `0xFF` | ACCEPT | ACCEPT | 低危对照（纯文档，两端一致放行） |
| H3 offsets CRC 坏 | `offsets.json` CRC 改坏 | REJECT | REJECT | 对照（反证 H1 盲区正是「未被读取」） |
| H4 manifest CRC 坏 | `manifest.json` CRC 改坏 | REJECT | REJECT | 对照 |
| H5 README 24MB | 真实 24MB README（第四轮 E8 回归） | REJECT | REJECT | 回归对照（体积上限） |
| H6 README 声明 size 伪造 | 真实 6MB，中央目录声明 `size=100`（白名单 zip bomb） | REJECT | **ACCEPT** | 跨端相反 |

> **坐实 6 处缺陷**：5 个跨端不一致（G1 / G2 / G6 / H1 / H6）+ 1 个「应拒未拒」（G3）。
> G4 / G5 / H2 / H3 / H4 / H5 是**对照用例**，如实记录为「修前结论本就一致」。

### 关键根因（逐个实测定位，不靠猜）

- **G1**：App `new String(bytes, "UTF-8")` 把非法字节**替换成 U+FFFD** 后照常解析；PC
  `.decode("utf-8")` 严格报错。用严格 `CharsetDecoder(REPORT)` 的解码文本构造才能根治。
- **G2**：Android org.json 会**吞掉** UTF-8 BOM；`manifestGuard` 早已拒 BOM，但没套到 offsets 上。
- **G3**：两端 JSON 解析器都是 last-wins，两个 `kernels` 取最后一个（合法），于是都放行；
  但 manifest 里两个 `"format"` 键在第四轮 E2 已被拒绝 —— 同一份规范、同一类歧义，两半不同对待。
- **G5**：Python `json.loads` 认 `NaN`/`Infinity`（非标准扩展），org.json 不认，路径不同。
- **G6**：org.json 对 JSON 整数 ≤ `Long.MAX`(9223372036854775807) 给 Long，超了给 **Double**；
  `parseNumOk` 只认 Integer/Long/String，Double 一律拒。而 PC `parse_num` 的整数上界是
  `0xFFFFFFFFFFFFFFFF`，无限精度 int 照单全收。实测探针：

  ```
  9223372036854775807    -> Long      9223372036854775807
  9223372036854775808    -> Double    9.223372036854776E18
  18446744073709551615   -> Double    1.8446744073709552E19   ← G6 分歧点
  ```
- **H1**：PC `zf.testzip()` 校验**所有**条目 CRC；App 只在 `read()` 里对「被读取的条目」算
  CRC32，白名单 `README.md` 永远读不到 → 完全不查。
- **H6**：`ZipEntry.getSize()` 是**声明值**，可伪造。verifyZip 的 size/total 都读它，被骗过；
  `getInputStream()` 却按 deflate 流读满真实 6MB。

### H6 的 install 落地面（额外单独坐实）

`verify` 放行还不够直观，狐娘用 Java SE 真跑 `Frp.install()` 落了一次盘：

```
install.ok = true
active_pkg/README.md = 6291456 B        ← 真实 6MB 白名单 zip bomb 落地
active_pkg/payload/e = 221104 B
（ZIP 头声明 size = 100）
```

对照正常包 `active_pkg/README.md = 2260 B`。PC 侧按 deflate 流读会因 CRC 不符抛
`BadZipFile` 拒绝。**即 App 不仅「和 PC 结论相反」，还真把 6MB 伪造数据写进了激活包目录**。

---

## 3. 修复清单（7 项，两端逐字对齐）

| # | 问题 | 证据 | 修复 |
|---|---|---|---|
| 1 | 第二份 JSON 无词法预检 | G1/G2/G3 | `manifestGuard`→`jsonGuard(byte[],maxSize)` / `manifest_guard`→`json_guard(raw,max_size)`，**manifest 与 offsets 都过**同一套：BOM / 非法 UTF-8 / 体积 / 深度≤64 / 同一对象内重复键 |
| 2 | App 宽松 UTF-8 解码替换非法字节 | G1 | `jsonGuard` 返回**严格解码后的文本** `{ok,reason,text}`，App 用 `new JSONObject(g[2])` 构造，杜绝 `new String(bytes)` 的 U+FFFD 替换 |
| 3 | 数值类型跨端分歧 | G6 | PC 新增 `INT_MAX = 0x7FFFFFFFFFFFFFFF`（Long.MAX），整数分支上界从 2^64-1 收到此值；字符串分支（官方 825 个 `0x` 值）不受影响 |
| 4 | NaN/Infinity 解析路径不同 | G5 | 两端词法扫描在字符串外直接拒裸 `NaN` / `Infinity` 字面量，收敛到同一层 |
| 5 | 白名单/全量条目无 CRC、声明 size 可伪造 | H1/H6 | App 新增 `verifyContainer(ZipFile, Result)`：逐条目流式算真实 CRC + 累计**真实解压字节数**，与 `getCrc()` / `getSize()` 逐条比对，边读边卡 16MB 上限（不读进内存） |
| 6 | PC 端同样按声明值算体积 | H6 | PC 新增 `real_entry_len()`：复制 ZipInfo 并放大 `file_size`，按 deflate 流读**真实字节数**与声明比对 + 真实总量上限，堵住「CRC 自洽的声明伪造」变体 |
| 7 | install 落盘循环无真实字节上限 | H6 落地面 | `install()` 落盘循环边写边累计 `wrote`，超 16MB 抛异常触发回滚，纵深防御 |

`MAX_OFFSETS_SIZE = 4 MB`（官方 11 内核表 52,213 B，留足余量，另受 16MB 条目上限兜底）两端一致。
offsets 预检失败时记 `[FAIL]` 并**跳过字段校验**（不是提前 return），保证失败项如实累加。

**修复前先核官方数据**：13 条目、无目录条目、825 个偏移值全是 `0x` 十六进制**字符串**（最长
16 位 `0xFFFFFFC010080000`）、无裸整数字面量、manifest 4716 B 无 BOM。所以收紧整数上界、
给 offsets 加预检**不会误伤合法包** —— 合法包复验 178 项 0 不通过已证实。

---

## 4. 复验结果

| 项目 | 结果 |
|---|---|
| `bugcheck_v5.py` 修后（G/H/I 共 15 例） | **15/15 两端一致，且 15/15 收敛到期望结论，0 偏离、0 不一致** |
| 其中 I 组数值边界回归（防止 INT_MAX 收紧误伤） | `Long.MAX` 整数 / `0xFFFFFFFFFFFFFFFF` 串 → 两端 ACCEPT；`2^64` 整数 → 两端 REJECT |
| H6 `install` 落盘复验 | `base.ok=true bad.ok=false readmeBefore=2260 readmeAfter=2260`（**拒绝导入、原激活包未变**） |
| `bugcheck_v2.py`（第二轮回归） | **18 PASS / 0 FAIL** |
| `bugcheck_v3.py`（第三轮回归） | **13 PASS / 0 FAIL**，C 组全过 |
| `bugcheck_v4.py`（第四轮回归） | E 组 **13/13 两端一致 REJECT**；F1 `bothOk=80/80`、F2 `30/30`、F3 0.3s REJECT、F4 不 OOM |
| `simulate_honor70.py`（全套模拟） | **25/25 通过** |
| 示范包 `verify --json` | `ok=true`，**178 项 / 0 不通过**（v24 为 175，本轮 +3：offsets 预检 + 容器层 2 项） |
| `verify --json` 三场景 | 合法包 / 非 ZIP / 不存在文件，均输出合法 JSON |
| `frp_tool.py build` 自检 | 从素材重建 → 自动 `verify` 178 项 0 不通过 |
| v25 dex 内容 | 含 `jsonGuard` / `verifyContainer` / `MAX_OFFSETS_SIZE` / 容器层 / 非标准裸字面量 |
| `FNERoot-通用壳-v25.apk` | 46225 B，md5 `3ad79634534dd2f4490904d070bc2787`，versionCode 25，`2.5-universal`，v1/v2/v3 全签，证书 `90f74ef2…f957` 不变 |

> 「一致」不等于「修好」：脚本本轮新增**期望判定**。G3 修前两端都 ACCEPT 但应拒未拒；
> H2 两端都 ACCEPT 则是对的（纯文档）。只判「两端相同」会漏掉 G3 这类缺陷。

v24 已归档到 `app/_旧版_v24_校验盲区修复前/`；`.frp` 的 `format_version` 仍是 `1`，**格式未变**。

---

## 5. 同步更新的文件

| 文件 | 变更 |
|---|---|
| `frp_tool.py` | `json_guard`（泛化 + NaN/Infinity）、`INT_MAX`、`MAX_OFFSETS_SIZE`、`real_entry_len`、offsets 预检、容器层真实字节数校验 |
| `app/src/com/fne/universal/Frp.java` | `jsonGuard`（泛化 + 严格解码文本）、`MAX_OFFSETS_SIZE`、`verifyContainer()`、offsets 预检、install 落盘真实字节上限 |
| `app/src/com/fne/universal/MainActivity.java` | 版本字符串 v2.5 |
| `app/src/build.sh` | v25 / versionCode 25 / `2.5-universal` |
| `simulate/bugcheck_v5.py` | 本轮可复现实证脚本（新增，含期望判定 + install 落盘 harness） |
| `simulate/simulate_honor70.py` | APK 路径指向 v25 |
| `docs/包格式规范.md` | §7/§8/§8.1/§9/§10/§11 同步第五轮；新增 §8.2 校验盲区与容器层 |
| `make_tutorial.py` / `通用提权包制作教程_5.4系.md` | 避坑表增至 23 条、附录补第五轮产物；教程重新生成 |
| `README.md` | 版本线、交付清单、设计决策、复核命令、边界全部同步 |
| `Bug体检报告_第五轮.md` | 本报告 |

---

## 6. 仍然成立的边界（不因本轮改变）

- `.frp` **没有数字签名**。本轮的 offsets 预检、全量 CRC、真实字节数、数值边界对齐，定位是
  **防误配 / 防损坏 / 防散件 / 防畸形输入 / 防校验盲区**，不防「攻击者构造一份满足全部内置
  规则的全新恶意包」。分发链路要防篡改，仍需包外 detached 签名。
- 物料互绑仍是**静态文本匹配**：同时改 `e` + 两个 `.sh` + `manifest.json` 让四者自洽，校验仍通过。
- `README.md` 里的**非法 UTF-8 仍两端一致放行**（H2）：它是纯文档，不参与运行、不搬运、不解析，
  刻意只做 CRC / 真实字节数 / 体积校验，不做内容解码 —— **这是设计选择，不是遗漏**。与 G1 的反差
  正好说明必须区分「参与校验的 JSON」与「纯文档白名单」。
- `sh -n` 依赖设备上有可用 `/system/bin/sh`（真机必然有），`waitFor(timeout)` 需 Android 8.0+。
- `fne_local.sh` 内 `grep -q "child is root!" "$LOG"` 仍可能受累积日志影响 —— **按你要求不动 sh/e**。
- **v25 真机安装 / UI / 授权跳转仍待你在荣耀70 上验证** —— 云电脑无 Android Runtime，
  这是唯一没闭环的部分。
- 通用包体系**尚未同步到 GitHub 私有仓 / Release**（本轮未要求）。

---

## 7. 自省（本轮踩过的坑，如实记）

1. **G2 的预期一开始写错了**：原本按第四轮 E3 想当然标「两端都靠解析异常拒绝（对照）」，
   修前实测却是 **PC REJECT / App ACCEPT** —— org.json 会吞 BOM。是实测纠正了预期，
   不是预期指导实测。报告以实测为准。
2. **「一致」不等于「修好」**：第一版复验脚本只判「两端是否相同」，会放过 G3（两端都 ACCEPT
   的应拒未拒）。改为同时判「是否等于期望结论」后才算真正闭环。
3. **光修 `verify` 不够，得看落盘**：H6 在 verify 层放行只是表象，真正风险是 `install()` 按
   deflate 流写出 6MB。补了独立 install harness 复验「拒绝导入 + 原包不变」，才敢说修好。
4. **收紧边界必须配回归**：把 PC 整数上界收到 Long.MAX 时，专门补了 I 组 3 例
   （合法边界放行 / 十六进制串放行 / 双超界拒绝），确认没把官方 `0x` 值或合法整数误伤。

---

*第五轮完 · 累计 v21→v25 共修 11 + 25 + 14 + 12 + 6 = 68 处（含实证与静态审查），核心交付 v25。*
