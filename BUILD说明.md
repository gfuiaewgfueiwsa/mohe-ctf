# 源码包说明（v2.5）

这是 `魔盒-ctf` v2.5 成品的源码归档，保留下来是为了以后还能改代码、重新打包。成品本身在上一级目录 `..\魔盒-ctf\`。

## 目录里有什么

| 路径 | 说明 |
| --- | --- |
| `ctfbox\` | 核心包：分发器、识别器、各 `modules_*`、界面层、工具管理、`rac\` 自动化引擎 |
| `main.py` | 入口，负责 GUI / `--cli` / `--rac` / `--webauto` / `--webattack` 模式的分派 |
| `CTFToolbox.spec` | PyInstaller 打包配置，含 Tcl/Tk 版本锁定（输出名 `CTFToolbox.exe`） |
| `build.bat` | 一键打包脚本，产物落到 `dist\CTFToolbox\` |
| `version_info.txt` | PE 版本资源（2.5.0.0，中英双 StringTable） |
| `_mirror_webtools.py` | 离线网页镜像脚本，供界面上的「重新镜像」按钮调用 |
| `scripts\library\` | 分类脚本库，既是功能素材也是 RAC 的装配源 |
| `samples\` | 示例输入，打包时随包进 `_internal` 再被脚本挪到 exe 同级 |
| `.git` | 本地仓库，远端为 GitHub `gfuiaewgfueiwsa/mohe-ctf` |
| `tools\` | **目录联接（Junction）**，指向 `..\魔盒-ctf\tools`，不是真的 3 GB 副本 |
| `卸载魔盒-ctf.bat` | 卸载脚本，打包时复制到 exe 同级 |

## 重新打包前要确认的三件事

1. **Python 解释器**：`build.bat` 里写死的是 `D:\PY\python.exe`，换机器前先改成自己的路径。依赖至少要装 `customtkinter scapy capstone pyelftools pefile windnd opencv-python pillow paramiko pycryptodome pycryptodomex cryptography numpy qrcode gmssl python-registry python-evtx pyinstaller`，运行环境是 Python 3.13。
2. **`tools\` 联接是否还有效**：在资源管理器里双击进得去就说明没断。成品文件夹改名、移动或删除后，联接会失效；此时先删掉这个断链，再把成品里的 `tools` 拷回来，或者重建联接：
   ```
   mklink /J "tools" "..\魔盒-ctf\tools"
   ```
3. **没有 exe 在跑**：`build.bat` 开头会 `taskkill` 掉 `CTFToolbox.exe`，但 `workspace\crash.log` 的句柄仍可能占用 `dist`，打包前手动确认一遍更稳。

## 打包命令

```
build.bat
```

等价于 `pyinstaller --noconfirm --clean CTFToolbox.spec`。打完包 `dist\CTFToolbox\` 里会出现 `_internal`，随后脚本把 `tools`、`samples`、`scripts` 从 `_internal` 挪到 exe 同级，再 `robocopy` 整个 `tools` 过去，最后补上 `使用说明.md` 与 `卸载魔盒-ctf.bat`。`robocopy` 退出码 0–7 都算成功，只有 ≥8 才是失败。

## 已发布状态

- 成品 exe 版本 2.5.0.0（PE 资源），界面版本 `v2.5`，2026-11-07 构建并验证（Web 回归 21 PASS / 0 FAIL / 0 SKIP，Pwn 本地闭环 `PWN_SMOKE=PASS`）。
- 源码与成品均已同步到 GitHub `gfuiaewgfueiwsa/mohe-ctf`。

## 运行测试

```
D:\PY\python.exe tests\test_webattack.py    # 端到端 Web 深度测试（21 项断言）
D:\PY\python.exe tests\test_pwn_ret2win.py  # Pwn 本地闭环（PWN_SMOKE=PASS）
```

Web 测试会拉起 `tests\ctf_deeptarget.py` 监听 `127.0.0.1:18081`，只打本机回环，不涉及外部目标。

## 不要放进来的东西

`Polar 靶场题解.md` 含真实题目 flag、靶场地址与账号，只留在工作目录根层，不进源码包也不进成品，更不要推到公开仓库。
