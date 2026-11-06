# CTFToolbox 万能 CTF 集合工具箱 v2.4

面向 **CTF 比赛 / 合法安全实验 / 电子数据取证练习** 的 Windows 桌面工具箱。
拖入任意后缀的文件，自动识别题目类型并把匹配的工具链全部跑一遍，递归分析压缩包、图片中嵌套的内容，直到找到 flag。

本仓库发布**源码与文档**；打包后的便携工具链（Ghidra、jadx、ffmpeg、JDK、Node、Python 等，约 3.1 GB）体积超出 GitHub 限制，不随仓库分发，需自行放入 `tools/` 后本地打包。

## 功能概览

- **一键分析**：文件类型识别 → 自动匹配并串行执行相关模块，递归下钻嵌套容器。
- **RAC 自动化（v2.4）**：五合一自动化中心（`ctfbox/rac/`）：
  - **题目流水线**（RAC = Recognize → Assemble → Command）：粘贴题目描述/参数 + 附件 →
    自动识别题型与参数（RSA n/e/c/p/q、host:port、哈希、密文、账号口令，p/q 自动推导 n）→
    从随包 69 个脚本静态解析评分匹配（argparse / PARAMS 双接口自动填参）→
    子进程静默执行 → 运行时强模式提取 flag，top-N 候选自动降级，全程落盘 `workspace/rac_runs/`。
  - **侦察自动化**：TCP 端口扫描（内置高频端口表）、HTTP 探测、目录探测（60+ 敏感路径）。
  - **远程执行**：SSH 主机清单批量执行命令（paramiko，多格式清单解析，并发可调）。
  - **Oracle RAC 巡检**：SSH 只读命令集（crsctl/srvctl/lsnrctl/asm/alertlog 等八类）汇总巡检报告。
  - **RPA 会话**：JSON 步骤表驱动 HTTP 会话（自动登录/CSRF 自动回填/自动提交 flag）。
- **分类模块**（`ctfbox/modules_*.py`）：杂项编码、密码学、取证、隐写、图片/音频/视频、流量包、Webshell、逆向、Python 反编译、归档、DNS、日志、文档、蓝牙、车辆/题目专项（Polar）、动态靶机利用等。
- **媒体中心**：语谱图、LSB 多位面提取、视频抽帧、GIF 导出、音频隐写链。
- **脚本库**（`scripts/library/`）：按类别整理的参数化通用 exp/解题脚本，可直接调用，也是 RAC 流水线的自动装配素材库。
- **动态容器利用**（v2.3）：ELF 保护位识别、后门定位、capstone 反汇编推断溢出偏移、ret2text/ret2libc 脚本生成、Web 多步重放，flag 一律运行时动态提取。
- **工具中心**：统一管理和静默调用随包便携工具，避免弹窗刷屏。
- **CLI 模式**：`CTFToolbox.exe --cli <文件> [文件...]` 批量分析；`CTFToolbox.exe --rac "题目描述" [附件...] --ctf-only` 一键自动解题，报告写入 `workspace/rac_cli_report.txt`。

完整变更与用法见 [使用说明.md](使用说明.md)，已知缺口见 [不足与bug记录.md](不足与bug记录.md)。

## 目录结构

```
main.py                 启动入口（GUI / --cli / --rac）
CTFToolbox.spec         PyInstaller 打包配置
build.bat               一键打包脚本
version_info.txt        Windows 版本资源信息
_mirror_webtools.py     内置 Web 工具导航数据生成
ctfbox/                 核心包：dispatcher、identifier、各 modules_*、ui_*、toolsmgr、rac/（RAC 自动化引擎）
scripts/library/        分类脚本库（RAC 自动装配素材库）
samples/                示例输入
```

## 依赖

GUI 基于 `customtkinter`。打包依赖见 `CTFToolbox.spec` 中显式收集列表：
`customtkinter`、`scapy`、`capstone`、`pyelftools`、`pefile`、`windnd`、`opencv-python`、`pillow`、`paramiko`、`pycryptodome`、`cryptography`、`numpy`、`qrcode`、`gmssl`、`registry`、`evtx`。
运行环境为 Windows + Python 3.13。

## 本地打包

1. 安装上述依赖与 `pyinstaller`（`build.bat` 默认使用 `D:\PY\python.exe`，按需改为你的解释器路径）。
2. 准备 `tools/portable` 与 `tools/runtime`（Ghidra、jadx、ffmpeg、JDK、Node、独立 Python 等）。
3. 执行 `build.bat`，产物在 `dist/CTFToolbox/CTFToolbox.exe`，同时把 `_internal` 下的数据目录与 `使用说明.md`、`卸载CTFToolbox.bat` 一并整理到 exe 同级。

## 未随仓库发布的内容

- 打包产物、`_internal` 运行时与 `tools/` 便携工具链（超出 GitHub 单文件 100 MB 限制）。
- `Polar 靶场题解.md`：其中含真实题目 flag、在用的靶场地址与登录凭据，仅在本地保留，不做公开分发。

## 免责说明

仅用于已获得授权的 CTF 赛事、靶场练习与取证学习。禁止将本工具用于未授权系统的渗透与攻击。
