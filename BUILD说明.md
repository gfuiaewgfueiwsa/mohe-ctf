# 源码包与打包说明（v4.1.0）

本目录是 `魔盒-CTF` v4.1.0 的源码，可直接运行、测试与重新打包。成品在上一级 `..\魔盒-CTF\`。

## 目录里有什么

| 路径 | 说明 |
| --- | --- |
| `ctfbox\` | 核心包：分发器、识别器、各 `modules_*`、界面层、工具管理、`web*` 引擎 |
| `ctfbox\autopilot\` | 一键梭哈编排：首层判型、工作区、scope、sandbox、审计、`exploit\`、确定性工具与 WP 输出 |
| `ctfbox\competition\` | 赛事专项：内存取证、流量深度、APK 审计、源码审计、安全基线、日志时间线、攻防验证、加固对比 |
| `ctfbox\platforms\` | 平台闭环：CTFd / PolarCTF 登录、题目、实例与 flag 提交 |
| `ctfbox\rac\` | RAC 自动化：题目流水线、侦察、SSH 批量执行、Oracle 巡检、RPA 会话 |
| `main.py` | 入口，负责 GUI / `--cli` / `--auto` / `--rac` / `--webauto` / `--webattack` / `--pwn` / `--platform` / `--comp` 分派 |
| `CTFToolbox.spec` | PyInstaller 打包配置（输出名 `CTFToolbox.exe`） |
| `build.bat` | 一键打包脚本，产物落到 `dist\CTFToolbox\` |
| `version_info.txt` | PE 版本资源（4.1.0.0，中英双 StringTable） |
| `_mirror_webtools.py` | 内置 Web 工具导航数据生成 |
| `scripts\library\` | 88 个脚本与速查表（69 个 Python 脚本），既是功能素材也是 RAC 装配源 |
| `tests\` | 单测与本地靶站；全量 110 项 |
| `docs\` | 当前架构与交付验证记录 |
| `samples\` | 示例输入占位，打包时随包进 `_internal` 再挪到 exe 同级 |
| `tools\` | **目录联接（Junction）**，指向 `..\魔盒-CTF\tools`，不是 3 GB 副本 |
| `卸载魔盒-CTF.bat` | 卸载脚本，打包时复制到 exe 同级 |

## 打包前要确认的三件事

1. **Python 解释器**：`build.bat` 默认使用 `D:\PY\python.exe`，换机器先改成自己的路径。依赖至少包括：
   `customtkinter scapy capstone pyelftools pefile windnd opencv-python pillow paramiko pycryptodome pycryptodomex cryptography numpy qrcode gmssl python-registry python-evtx pyinstaller`，运行环境为 Windows + Python 3.13。
2. **`tools\` 联接是否有效**：资源管理器能进就说明正常。成品改名、移动或删除会让联接失效，可重建：
   ```
   mklink /J "tools" "..\魔盒-CTF\tools"
   ```
   `tools\` 约 3.1 GB，包含 Ghidra、jadx、ffmpeg、JDK、Node、独立 Python、7z、nmap、sqlmap、hashcat、john、radare2、x64dbg、dnSpy 等 25 个便携工具。
3. **没有 exe 在运行**：`build.bat` 会先 `taskkill /F /IM CTFToolbox.exe`，但 `workspace\crash.log` 句柄仍可能占用 `dist`；打包前手动确认更稳。

## 打包命令

```
build.bat
```

等价于 `pyinstaller --noconfirm --clean CTFToolbox.spec`。完成后 `dist\CTFToolbox\` 内生成 `_internal`，脚本随后：

1. 把 `_internal\tools`、`_internal\samples`、`_internal\scripts` 移到 exe 同级；
2. `robocopy` 整个 `tools` 到产物目录（退出码 0–7 为成功，≥8 为失败）；
3. 复制 `使用说明.md` 与 `卸载魔盒-CTF.bat`；
4. 建立空的 `workspace`、`reports`、`exports` 目录。

分发时把 `dist\CTFToolbox\` 整体复制为 `魔盒-CTF\`，可执行文件为 `CTFToolbox.exe`；成品按版本命名为 `魔盒-CTFv4.1.0.exe`，并建立 `魔盒-CTF.exe` 硬链接（同一文件，零额外空间），兼容文档示例与旧快捷方式。

本地模型裁判的模型与运行时**不由 PyInstaller 打包**，直接放在成品根目录：

```
models/qwen2.5-3b-instruct-abliterated-q4_k_m.gguf   1.93GB，溯源见 models/README-provenance.md
runtime/llama/cuda/llama-server.exe + CUDA 13.5 依赖   NVIDIA 显卡加速
runtime/llama/cpu/llama-server.exe                     无显卡或驱动不匹配时回退
ai_config.json                                         开关、上下文、决策次数与端口
```

源码仓库不包含这三项（模型超出 GitHub 单文件限制）；运行时缺失时程序静默回退确定性流程。

## 从源码直接运行

```
D:\PY\python.exe main.py                 # GUI
D:\PY\python.exe main.py --cli 样本文件   # 批量分析
D:\PY\python.exe main.py --auto 样本文件  # 一键梭哈
```

GUI 每次启动展示《软件责任说明》，勾选同意后进入；CLI 首次使用加 `--accept-responsibility`，确认记录写入 `workspace\config\responsibility.json`。

## 运行测试

```
D:\PY\python.exe -m unittest discover -s tests -v
```

v4.1.0 全量回归 **132 tests OK**，另有 Web 全链路 15 个场景（A–O）ALL PASS。覆盖范围包括：责任闸门、首层判型、AutoPilot 文件/Web 链、Web 利用与审计、加密 ZIP 与密码型隐写、兽音变体解码、AI 裁判 11 项、异常曲线 HNP、赛事专项八个模式、平台适配、RAC 装配与脚本库预检。Web 相关用例只拉起 `127.0.0.1` 本地靶站，不访问外部目标。

## 已发布状态

- 成品 `魔盒-CTF.exe` / `CTFToolbox.exe`：PE 版本 **4.1.0.0**，2026-11-09 构建，25,152,080 字节（PE 版本资源由 spec 打包时按 `ctfbox.__version__` 生成，不再手写）。
- 全量单测 132 项通过；CLI 责任闸门、平台列表、打包产物冒烟均已实测（`--cli`、`--auto` 各跑一遍，`result.json` 版本号 4.1.0）。
- 源码、测试与文档同步到 GitHub `gfuiaewgfueiwsa/mohe-ctf`（`tools/`、`dist/`、`workspace/` 不入库）。

## 不要放进来的东西

- `Polar 靶场题解.md`：含真实题目 flag、靶场地址与账号，只留在工作目录根层，不进源码包、不进成品、不推公开仓库。
- `tools/`、`dist/`、`build/`、`workspace/`、`reports/`、`tests/_*.log` 等运行与构建产物。
- 平台登录态 `workspace/platform/*.json` 与责任确认记录。
