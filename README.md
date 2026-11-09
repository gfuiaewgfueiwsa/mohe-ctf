# 魔盒-CTF 万能 CTF 集合工具箱 v4.1.0

> 命名规范：产品名统一写作 **`魔盒-CTF`**（`CTF` 全大写），完整名为 **`魔盒-CTF v4.1.0`**。主程序按版本命名 `魔盒-CTFv4.1.0.exe`，同时提供 `魔盒-CTF.exe` 硬链接（同一文件），分发目录同名。

面向 **CTF 比赛 / 合法安全实验 / 电子数据取证练习** 的 Windows 桌面工具箱。
拖入任意后缀的文件或输入题目地址，软件自动识别类型、选择分析阶段、调用随包工具与脚本，递归下钻嵌套内容，直到找到 flag 或给出下一步线索。

本仓库发布**源码与文档**。打包后的便携工具链（Ghidra、jadx、ffmpeg、JDK、Node、独立 Python 等，约 3.1 GB）超出 GitHub 单文件限制，不随仓库分发，需要自行放入 `tools/` 后本地打包。仓库内的 `scripts/library/` 脚本库、`ctfbox/` 源码与 `tests/` 测试均可直接使用。

## 核心能力

- **唯一责任说明闸门**：GUI 每次启动展示《软件责任说明》，必须勾选「我已逐条阅读并同意」才能进入，拒绝或关闭窗口直接退出；CLI 首次使用需加 `--accept-responsibility`，确认结果保存在 `workspace/config/responsibility.json`，之后直接运行。责任条款覆盖授权与合法使用、能力与风险、数据与隐私、无担保与责任限制。`--ctf-only`、`--i-own-this-target`、`--consent` 仍可传入以兼容旧脚本，但不再强制、不再改变行为。
- **一键梭哈（文件 / URL）**：入口先做**首层判型**（`ctfbox/autopilot/triage.py`），按文件类别、文本特征、二进制特征与 Web 证据给出 `kind/category/subtype/confidence/evidence`，只执行被证据选中的阶段。文件链覆盖类型识别、哈希/熵/strings、单字节与重复密钥 XOR、编码套娃解码、PE/ELF 静态分析、Ghidra headless 反编译、RC4/AES/DES/3DES 密钥候选试解、RSA/ECC/HNP、加密 ZIP 与密码型 LSB 隐写；Web 链覆盖指纹、SPA 渲染、登录门槛识别、只读入口探测与按证据选择的利用阶段。每题独立工作区、证据链与 `mohe-wp-v1` 固定格式 WP。
- **本地模型裁判（可选，`--ai` / GUI「本地模型裁判」）**：内置 `Qwen2.5-3B-Instruct-abliterated` Q4_K_M（约 1.93 GB，魔搭 `huihui-ai` 无审查改版，apache-2.0），由随包 llama.cpp `llama-server` 本地推理，GPU 不可用时自动回退 CPU。它不直接解题：只在确定性流程结束后，读取工作区状态，在固定动作白名单（深度 MISC / 图片隐写 / 归档递归 / 二进制深度 / Ghidra 反编译 / 编码链 / XOR / 停止）内选择下一动作与 1–3 的深度，执行仍走原编排工具、证据链与责任闸门。GBNF 约束输出合法 JSON，动作、目标与深度逐项校验，并按目标类型限制可选动作（如 zip 只允许解压、图片才允许隐写），最多 3 次决策；模型缺失、启动失败或输出非法时静默回退，不影响原结果。`ngl=auto` 由 llama.cpp `--fit-target` 自动拟合，强制保留 4 GB 空闲显存；实测 37/37 层全部上 GPU 时模型+KV+计算缓冲约 2.06 GB（ctx 4096），8 GB 显存机器仍有约 5 GB 给 Ghidra/ffmpeg 等工具。
- **Web 全量利用（`--auto <URL> --exploit`）**：覆盖 PHP/Java/Python 反序列化、文件上传、SQLi/命令注入/SSTI/SSRF/XXE/LFI、XSS/CSRF/Cookie、JWT/IDOR/弱口令，AutoPilot 多步利用链按证据评分选择阶段。每次请求仍经地址校验（仅 http/https、拒绝 URL 内凭据）、逐请求审计、限速与请求预算；payload 只保存摘要，上传验证样本只写入任务 `artifacts`。仅限授权的 CTF 靶场与自有资产，不做公网批量扫描、免杀或持久化。
- **赛事专项（`--comp` / GUI「赛事专项」）**：**内存取证**（Volatility 3：进程/网络/注册表/凭据/文件）、**流量深度分析**（TCP 重组、HTTP 对象、DNS 隧道、文件雕刻）、**APK 审计**（清单权限/导出组件/证书/DEX/jadx 反编译/硬编码密钥）、**源码审计**（PHP/Java/Python 危险点与污点链，证据到文件:行号）、**安全基线**（Windows/Linux 只读检查 + 生成加固/回滚脚本）、**日志时间线**（EVTX/auth.log/syslog 暴破与横向线索）、**攻防验证**（WAF/NGFW 清单与无害检测用例，仅生成）、**加固前后对比**。全部离线只读，脚本与用例不执行、不发送。
- **平台闭环（`--platform`）**：CTFd / PolarCTF 登录态、题目列表、题目详情、开实例、一键梭哈、自动提交 flag 与 WP 归档。登录态保存在 `workspace/platform/`，不会打进交付包。
- **RAC 自动化（`ctfbox/rac/`）**：五合一自动化中心——题目流水线（Recognize → Assemble → Command，参数识别 + 脚本库评分装配 + 静默执行 + 强模式提取 flag）、侦察自动化（端口/HTTP/目录）、SSH 批量远程执行、Oracle RAC 只读巡检、JSON 步骤表驱动的 RPA 会话。
- **分类分析模块（`ctfbox/modules_*.py`）**：杂项编码、密码学、取证、隐写、图片/音频/视频、流量包、WebShell 流量、逆向、Python 反编译、归档、DNS、日志、文档、蓝牙、车辆与题目专项（Polar）、动态靶机利用等；一键分析自动匹配并串行执行，递归下钻嵌套容器。
- **媒体中心**：语谱图、LSB 多位面提取、视频抽帧、GIF 导出、音频隐写链、内置播放器与图片增强。
- **脚本库（`scripts/library/`）**：88 个脚本与速查表文件（含 69 个单文件 Python 脚本），按 7 个方向分类，支持 `--selftest`，既是「📚 脚本库」页的功能素材，也是 RAC 与一键梭哈的自动装配来源。
- **工具中心**：统一管理和静默调用随包 25 个便携工具（7z、Ghidra、jadx、nmap、sqlmap、hashcat、john、radare2、x64dbg、dnSpy、ffmpeg、ExifTool、MobaXterm 等），避免弹窗刷屏；支持官方下载、winget/pip 通道与 WSL2 Kali 工具集。

完整用法见 [使用说明.md](使用说明.md)，已知缺口与边界见 [不足与bug记录.md](不足与bug记录.md)，架构与验证记录见 [docs/架构.md](docs/架构.md) 与 [docs/交付与验证.md](docs/交付与验证.md)。

## 命令行入口

| 命令 | 说明 |
| --- | --- |
| `魔盒-CTF.exe` | 启动 GUI（首次进入须同意《软件责任说明》） |
| `魔盒-CTF.exe --cli <文件> [文件...]` | 批量附件分析，报告写入 `workspace/cli_report.txt` |
| `魔盒-CTF.exe --auto <文件\|URL> [--exploit] [--deep] [--render] [--ai]` | 一键梭哈；文件类输出 WP 与证据链；`--ai` 启用本地模型裁判 |
| `魔盒-CTF.exe --comp <memory\|traffic\|mobile\|codeaudit\|baseline\|logtime\|defense\|compare> ...` | 赛事专项，离线分析与只生成脚本/用例 |
| `魔盒-CTF.exe --platform polarctf --list [--category WEB]` | 平台题目列表 |
| `魔盒-CTF.exe --platform polarctf --solve <题目ID>` | 开实例 → 一键梭哈 → 提交 → 输出 WP |
| `魔盒-CTF.exe --rac "题目描述" [附件...]` | RAC 题目流水线，报告写入 `workspace/rac_cli_report.txt` |
| `魔盒-CTF.exe --webauto <URL>` | 只读 Web 取证（轻量） |
| `魔盒-CTF.exe --webattack <URL>` | 深度 Web 全自动（页面分析 + payload 矩阵 + 上传测试） |
| `魔盒-CTF.exe --pwn <ELF> [--host H --port P --offset N]` | ELF 静态定位与 ret2win 闭环 |

CLI 首次使用需加 `--accept-responsibility`；确认结果持久化后不再要求。兼容参数 `--ctf-only`、`--consent web-exploit`、`--i-own-this-target` 可以照常传入，但不再改变行为。

## GUI 标签页

一键分析 · 一键梭哈 · 编码/密码 · 密文加解密 · 实用小工具 · 专项工具 · 赛事专项 · RAC 自动化 · Web / Pwn · 📚 脚本库 · SSH 终端 · 工具中心 · 媒体中心 · 网页导航 · 使用说明。

## 目录结构

```
main.py                 启动入口（GUI / CLI 各模式统一先过责任说明闸门）
CTFToolbox.spec         PyInstaller 打包配置（输出名 CTFToolbox.exe）
build.bat               一键打包脚本
version_info.txt        Windows PE 版本资源（4.1.0.0）
_mirror_webtools.py     内置 Web 工具导航数据生成
ctfbox/                 核心包：dispatcher、identifier、各 modules_*、ui_*、toolsmgr、web*
ctfbox/autopilot/       一键梭哈编排：triage、workspace、scope、sandbox、audit、exploit/、tools/、orchestrator、wp
ctfbox/ai/              本地模型裁判：config（配置/探测）、backend（llama-server）、conductor（白名单调度）
models/                 本地模型目录（GGUF 不随源码仓库分发，成品目录内置）
runtime/llama/          llama.cpp 运行时（cuda/cpu 两套 llama-server）
ctfbox/competition/     赛事专项：memory/traffic/mobile/codeaudit/baseline/logtime/defense/util/cli
ctfbox/platforms/       平台闭环：CTFd/PolarCTF 登录、题目、实例与提交
ctfbox/rac/             RAC 自动化：识别、装配、执行、侦察、远程执行、Oracle 巡检、RPA
scripts/library/        分类脚本库（88 个脚本与速查表 / 69 个 Python 脚本）
tests/                  单测与本地靶站（含利用链、赛事专项、平台、责任闸门回归）
docs/                   当前架构与交付验证记录
samples/                示例输入占位
```

`tools/`（约 3.1 GB 便携工具链）与 `dist/`、`build/`、`workspace/`、`reports/` 为本地运行/构建产物，不入库。

## 依赖

GUI 基于 `customtkinter`。打包依赖见 `CTFToolbox.spec`：
`customtkinter`、`scapy`、`capstone`、`pyelftools`、`pefile`、`windnd`、`opencv-python`、`pillow`、`paramiko`、`pycryptodome`、`pycryptodomex`、`cryptography`、`numpy`、`requests`、`qrcode`、`gmssl`、`registry`、`evtx`。
内存取证另需 Volatility 3（随包 `tools/runtime/python/Scripts/vol.exe` 或 `pip install volatility3`）；APK 源码级审计可选 jadx（随包 `tools/portable/jadx`）与 apktool（未随包）。运行环境为 Windows + Python 3.13。

## 本地打包

1. 安装上述依赖与 `pyinstaller`（`build.bat` 默认使用 `D:\PY\python.exe`，按需修改解释器路径）。
2. 准备 `tools/portable` 与 `tools/runtime`（Ghidra、jadx、ffmpeg、JDK、Node、独立 Python 等）。
3. 执行 `build.bat`，产物在 `dist/CTFToolbox/CTFToolbox.exe`；脚本会把 `tools`、`samples`、`scripts`、`使用说明.md`、`卸载魔盒-CTF.bat` 整理到 exe 同级。分发时复制/重命名为 `魔盒-CTF.exe`。

## 未随仓库发布的内容

- 打包产物、`_internal` 运行时与 `tools/` 便携工具链（体积超出 GitHub 单文件 100 MB 限制）。
- `Polar 靶场题解.md`：含真实题目 flag、靶场地址与登录凭据，仅在本地保留，不公开分发。

## 免责说明

仅用于已获得授权的 CTF 赛事、靶场练习、取证学习与自有资产测试。软件不判断目标归属，未授权测试、入侵、干扰或窃取数据等行为由使用者承担全部法律责任。禁止将本工具用于任何未授权的攻击活动。
