# 源码包说明（v2.4）

这是 `CTFToolbox_v2.4` 成品的源码归档，保留下来是为了以后还能改代码、重新打包。成品本身在上一级目录 `..\CTFToolbox_v2.4\`。

## 目录里有什么

| 路径 | 说明 |
| --- | --- |
| `ctfbox\` | 核心包，51 个模块：分发器、识别器、22 个 `modules_*`、界面层、工具管理、`rac\` 自动化引擎 |
| `main.py` | 入口，负责 GUI / `--cli` / `--rac` 三种模式的分派 |
| `CTFToolbox.spec` | PyInstaller 打包配置，含 Tcl/Tk 版本锁定 |
| `build.bat` | 一键打包脚本，产物落到 `dist\CTFToolbox\` |
| `version_info.txt` | PE 版本资源（2.4.0.0） |
| `_mirror_webtools.py` | 离线网页镜像脚本，供界面上的「重新镜像」按钮调用 |
| `scripts\library\` | 69 个脚本 + 20 个词表与说明，既是功能素材也是 RAC 的装配源 |
| `samples\` | 空目录占位，打包时随包进 `_internal` 再被脚本挪到 exe 同级 |
| `.git` | 本地仓库，远端为 GitHub `gfuiaewgfueiwsa/CTFToolbox` |
| `tools\` | **目录联接（Junction）**，指向 `..\CTFToolbox_v2.4\tools`，不是真的 3 GB 副本 |

## 重新打包前要确认的三件事

1. **Python 解释器**：`build.bat` 里写死的是 `D:\PY\python.exe`，换机器前先改成自己的路径。依赖至少要装 `customtkinter scapy capstone pyelftools pefile windnd opencv-python pillow paramiko pycryptodome pycryptodomex cryptography numpy qrcode gmssl python-registry python-evtx pyinstaller`，运行环境是 Python 3.13。
2. **`tools\` 联接是否还有效**：在资源管理器里双击进得去就说明没断。成品文件夹改名、移动或删除后，联接会失效；此时先删掉这个断链，再把成品里的 `tools` 拷回来，或者重建联接：
   ```
   mklink /J "tools" "..\CTFToolbox_v2.4\tools"
   ```
3. **没有 exe 在跑**：`build.bat` 开头会 `taskkill` 掉 `CTFToolbox.exe`，但 `workspace\crash.log` 的句柄仍可能占用 `dist`，打包前手动确认一遍更稳。

## 打包命令

```
build.bat
```

等价于 `pyinstaller --noconfirm --clean CTFToolbox.spec`。打完包 `dist\CTFToolbox\` 里会出现 `_internal`，随后脚本把 `tools`、`samples`、`scripts` 从 `_internal` 挪到 exe 同级，再 `robocopy` 整个 `tools` 过去，最后补上 `使用说明.md` 与 `卸载CTFToolbox.bat`。`robocopy` 退出码 0–7 都算成功，只有 ≥8 才是失败。

## 已发布状态

- 成品 exe 版本 2.4.0.0，2026-11-06 构建并验证（CLI 与 GUI 均实跑通过，详见 `不足与bug记录.md` 第八节）。
- 源码改动**尚未推送到 GitHub**，远端最新仍停在 v2.3。要发布新版本，先 `git add` 再提交。

## 不要放进来的东西

`Polar 靶场题解.md` 含真实题目 flag、靶场地址与账号，只留在工作目录根层，不进源码包也不进成品，更不要推到公开仓库。
