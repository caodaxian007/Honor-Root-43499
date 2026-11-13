# 荣耀Ghostlock提权工具 · FNE-AN00 通用壳

面向 **荣耀 70（FNE-AN00）/ MagicOS 8 / 内核 5.4.295** 的 `.frp` 通用提权包体系。
本仓库为**公开部分**：只含核心源码、校验工具、文档与已签名成品 APK。

> **仅供自有设备安全研究**。本仓库不提供任何漏洞利用二进制、符号表、内核模块或提权物料；
> 不提供针对未授权设备的使用方法。使用者需自行确认行为符合所在地法律法规与设备厂商条款。

## 这是什么

早期版本把 9 个 native 资产直接打进 APK；现在的通用壳 **零内置物料**，只接受一份完整的
`.frp` 包导入，由 PC 端 `frp_tool.py` 与 App 端 `Frp.java` 共用同一套校验规则。
App **不代跑提权脚本**，只负责校验、释放并生成搬运命令。

| 文件 | 作用 |
|---|---|
| `frp_tool.py` | PC 端 `.frp` 构建 / 校验 / 查看 / 解包（可独立运行，无外部依赖） |
| `app/src/com/fne/universal/Frp.java` | App 端校验、导入、释放（与 PC 端规则逐字对齐） |
| `app/src/com/fne/universal/MainActivity.java` | 通用壳 UI |
| `docs/包格式规范.md` | `.frp` v1 包格式契约 |
| `通用提权包制作教程_5.4系.md` | 5.4 系内核包制作教程 |
| `Bug体检报告*.md` | 六轮 bug 实证与修复记录（累计 84 处） |
| `app/FNERoot-通用壳-v27.apk` | 已签名成品，v1/v2/v3 全签，versionCode 27 |

## 主推成品

- 应用名：**荣耀Ghostlock提权工具**
- 包名：`com.edge.Jinglian.fneroot`（沿用旧版，可覆盖安装）
- 图标：FNE-AN00 老版启动图标
- 证书 SHA-256：`90f74ef2…f957`

## 不包含什么

本仓库**不含** `.frp` 示范包、`payload/` 物料（`e` / `kernelsu.ko` / `ksud` / 符号表 /
`chain_hook.sh` / `fne_local.sh` 等）、签名私钥、构建脚本、偏移素材、回归实证脚本、
旧版归档与历史中间产物。这些 **APP 制作相关材料**保留在私有仓库，不对外分发。

六轮 bug 检验中用于双端交叉的回归脚本（`simulate/bugcheck_v*.py`，Java SE 真跑 App 侧
校验器）依赖本机构建环境与私有物料，同样保留在私有仓；本仓的六份报告已完整记录
用例设计、修前实测、修复与复验结论，可独立阅读。

## 尚未闭环

- 成品 APK 的真机安装 / UI / 授权跳转仍需在荣耀 70 上自行验证；本项目未提供 Android Runtime 实机验证环境。
- `.frp` 目前**无数字签名**：现有校验只防误配、损坏、散件与畸形输入，不防「构造一份满足全部内置规则的全新自洽包」。
- 内核提权、KASLR、KernelSU late-load 等仅做过静态 / 用户态验证。

## 校验链复现

```sh
python3 frp_tool.py verify <你的包>.frp --json
python3 frp_tool.py build  <素材目录>  <输出包>.frp
python3 frp_tool.py inspect <你的包>.frp
```

`frp_tool.py` 为单文件、仅依赖 Python 标准库，可直接运行。App 侧规则见
`app/src/com/fne/universal/Frp.java`，两端逐字对齐；两端差异与收敛结论见六份 Bug 体检报告。
