# CTFToolbox v2.3 全功能测试 — 不足与 Bug 记录

测试时间：2026-10-09
测试对象：`CTFToolbox 万能 CTF 集合工具箱 v2.3`（Python 3.13.14 + customtkinter，PyInstaller onedir）
测试方式：后端模块单测 51 项 + GUI 自动化 40 项 + GUI 补充（一键分析流水线/媒体中心/网页导航/SSH/工具中心/报告导出）21 项 + 冻结 exe CLI 全样本实测 + 冻结 exe GUI 启动截图 + 冻结态脚本库路径模拟验证 + 便携 Python/ffmpeg 实测。

---

## 一、测试结果总览

| 测试套件 | 结果 | 说明 |
|---|---|---|
| 后端模块（test_backend.py，51 项） | 51 PASS / 0 FAIL | 编码、古典密码、对称/非对称、哈希爆破、NTLM、隐写、图片、压缩包、雕刻、取证、Web、Pwn 模板、分发器、脚本库 88 脚本 |
| GUI 主功能（test_gui.py，40 项） | 40 PASS / 0 FAIL | 编码/密码页、密文加解密页、实用小工具页、专项工具页、Web/Pwn 页、工具中心、脚本库 |
| GUI 补充（test_gui2.py，16 项） | 16 PASS / 0 FAIL | 一键分析 15 样本完整流水线、图片打开/反色/旋转/直方图/EXIF、网页导航、SSH 标签、工具中心卡片 |
| 报告导出（test_gui3.py，5 项） | 5 PASS / 0 FAIL | txt + html 双报告，内容含 flag、结构完整 |
| 冻结 exe CLI（15 个真实样本） | 全部分析成功 | 明文/base64/hex/三重 b64/正常 zip/7z 加密 zip（口令 123456 自动破解）/CRC zip/PNG/伪装 ELF/内嵌 zip 载体/MD5/零宽/空文件/坏 zip/wav |
| 冻结 exe GUI 启动 | 正常，无崩溃 | 标题 v2.3，11 个标签齐全（含「📚 脚本库」），crash.log 无异常 |
| 冻结态脚本库 | 88 条目全部加载 | 模拟 sys.frozen + exe 同级 scripts\library 布局，7 方向计数正确（crypto22/misc18/web15/pwn9/reverse8/forensics8/utils8） |
| 便携运行时 | 正常 | tools\runtime\python（Python 3.11.16）可跑脚本 --selftest；便携 ffmpeg/ffplay 存在且 ffmpeg 可正常探测 wav |

**结论：核心功能全部可用。共发现 7 个应修复问题 + 5 个体验问题，任务⑤已全部修复/复核（状态见下文，最终回归 112 项测试全绿）。**

> 任务⑤修复后状态更新（2026-10-09 晚）：BUG-1~BUG-7、ISSUE-1~ISSUE-3、ISSUE-5 全部修复并回归通过；ISSUE-4 经复核为测试脚本自身产生的警告，生产代码不使用 pyjwt.encode，无需改动。最终 exe 于 2026-10-09 晚重新构建。

---

## 二、Bug 清单（含精确位置）

### BUG-1【已修复】Python 3.13 / OpenSSL 3 下 MD4/NTLM 完全不可用
- 位置：`ctfbox/modules_text.py`
  - 原问题点：哈希计算与 NTLM 弱口令爆破直接调用 `hashlib.new("md4")`
  - 修复：第 485 行新增纯 Python MD4 实现 `_md4_pure()`（RFC 1320）；第 535 行新增 `md4_hex()`（先用 `usedforsecurity=False` 调 OpenSSL，失败再走纯 Python 兜底）；第 548、578 行两处调用点已替换。
- 现象：Python 3.13 的 OpenSSL 3 默认拒绝 MD4，`hashlib.new("md4")` 直接抛 `ValueError: unsupported hash type md4`，导致"计算哈希"的 NTLM 行报错、NTLM 弱口令爆破整体不可用（冻结 exe CLI 跑哈希样本时复现）。
- 验证：RFC 1320 向量（空串→31d6cfe0…、"a"→bde52cb3…）、NTLM("password")=8846f7eaee8fb117ad06bdd830b7586c、NTLM 字典爆破均通过。

### BUG-2【已修复】Web 端口扫描传 list 时崩溃
- 位置：`ctfbox/webtools.py` 第 121 行 `_parse_ports()`
- 现象：该函数只接受字符串，GUI/其他调用方传入 list/tuple 时抛 `AttributeError: 'list' object has no attribute 'split'`。
- 修复：改为支持 str/list/tuple，list/tuple 递归解析并合并端口集合。

### BUG-3【任务⑤已修复】媒体中心工作线程在窗口关闭/主循环未就绪时崩溃
- 位置：`ctfbox/ui_media.py`，工作线程内的 `self.after(0, ...)` 调用：第 776、780、786、823、900、983 行（983 行为图片分析结果回填，已实测复现）。
- 现象：分析任务在后台线程运行时关闭窗口（或主循环暂时不响应），线程回调 `self.after()` 抛 `RuntimeError: main thread is not in main loop`，stderr 打印线程级 Traceback。不杀主进程，但属于未捕获异常，且可能导致结果丢失。
- 复现：test_gui2.py 跑完销毁窗口时，图片分析线程仍在运行。
- 修复：已在 MediaFrame 新增 `_ui(fn)` 助手（after 注册与回调执行双层 try/except，窗口销毁/主循环未就绪时静默丢弃），上述 6 处工作线程回调全部改走 `_ui`；主线程内的 after 不动。回归：test_gui2 关闭窗口时不再出现任何线程 Traceback。

### BUG-4【任务⑤已修复】尾部残缺 ZIP 雕刻后误报"完整性正常"
- 位置：`ctfbox/modules_carve.py` 第 338-342 行
- 现象：从载体尾部雕刻出的 ZIP 只有中央目录+部分数据时，`ZipFile.testzip()` 返回 None（它不实际解压全部数据），软件提示"雕刻 ZIP 完整性正常"，但用户实际解压会报 `negative seek during extraction` 之类错误（10_zip_appended 样本实测：雕刻出的 177 字节尾部 ZIP 即如此），提示语误导。
- 修复：完整性校验改为 testzip() + 逐条 `z.open()` 实际流式读完全部数据，任一失败即报"雕刻 ZIP 数据不完整/可能被截断"并列出失败条目；全部成功才报"完整性正常（可正常解压）"。同时对 dispatcher 多次调用雕刻导致的重复结论/重复"雕刻出"条目做了去重。实测 10_carrier.bin：完整 zip 报"可正常解压"，190 字节尾部残缺 zip 正确报"可能被截断"。

### BUG-5【任务⑤已修复】同一 flag 在一键分析结果中重复上报
- 位置：`ctfbox/dispatcher.py` 第 99 行（原始内容强匹配先报一次）与 `_text_flow` 自动解码链（约 278/295/305/316/324/334/354 行，解码后又报一次）
- 现象：文本本身就含 `flag{...}` 时，报告里同一 flag 出现 2 条记录（CLI 与 GUI 报告树均如此）。
- 修复：已在 `ctfbox/common.py` 的 `Report.add()` 中对 `level=="flag"` 按 detail 去重（同一 Report 实例相同 flag 只留第一条），一处覆盖全部调用点。实测明文样本 flag 由 2 条降为 1 条。注：不同文件（如修复 zip 与雕刻 zip 是不同 Report）各自上报同一 flag 属正常的来源标注，不去重。

### BUG-6【任务⑤收尾阶段发现并修复】"重新镜像离线网页"按钮引用的脚本在工程中缺失
- 位置：`ctfbox/ui_main.py` `_remirror_web()`（约 1540 行）调用工程根 `_mirror_webtools.py`，但该文件在工程中根本不存在；且冻结态下按 `__file__` 上推两级会定位到 `_internal\` 目录，路径同样错误。
- 现象：网页导航页"重新镜像离线网页"按钮在开发态与冻结态都必然失败（脚本不存在/路径错误），用户无法自行刷新离线工具镜像。
- 修复：①新建工程根 `_mirror_webtools.py`（纯标准库：同站静态递归镜像 zero-width/qrazybox/兽音/熊曰/佛论禅，CyberChef 走 GitHub Releases 官方 zip；暂存目录成功才替换、失败保留旧版；自动重写 manifest）；②`ui_main.py` 冻结态改用 `common.APP_DIR` 拼路径，并增加脚本缺失/无 Python 解释器的明确提示；③`build.bat` 增加把该脚本复制到 exe 同级目录的步骤。实测 zero-width（3 文件）、qrazybox（95 文件）、CyberChef v11.5.0（79MB 官方包）镜像成功；pcmoe 三个站点在本机 DNS 解析失败时按设计保留旧目录并回退在线打开。

### BUG-7【任务⑤收尾阶段发现并修复】修复/雕刻两条路径对同一 ZIP 重复分析，flag 与结论重复刷屏
- 位置：`ctfbox/dispatcher.py` `_analyze()` 递归（visited 仅按 路径+大小+时间 去重）、`ctfbox/modules_carve.py` 完整性结论段。
- 现象：10_carrier.bin（13 字节垃圾头 + 完整 ZIP + 190 字节残缺 ZIP）经"文件头修复"得到 repaired zip、又经"ZIP 雕刻"得到 carved zip，两者是同一容器的两份副本（尾部差 13 字节，文件哈希不同），导致 readme/note 子树、flag、ZIP 列表、完整性结论全部重复两遍。
- 修复：①dispatcher 递归层新增内容级去重（递归层文件 SHA256 相同只分析一次）与压缩包成员指纹去重（成员名+CRC+大小一致的容器只分析一次，根级用户文件不去重）；②modules_carve 完整性结论按成员指纹去重（"完整性正常"只报一次），但截断/损坏告警始终逐条保留（残缺包指纹与完整包相同也必须报警）。实测 10 号样本：flag 仅 1 条、完整性正常仅 1 条、残缺 ZIP 截断告警保留。

---

## 三、不合理 / 体验问题（低优先级，任务⑤一并处理）

### ISSUE-1【任务⑤已修复】已含明文 flag 的文本仍刷大量无意义解码链
- 位置：`ctfbox/dispatcher.py` `_text_flow()`
- 现象：明文 flag 样本会继续尝试 Base91/ROT/进制等几十种弱解码，输出大量"看起来像结果但无意义"的解码行，报告噪音大。
- 修复（dispatcher `_text_flow` 自动链式解码展示层）：①恒等解码（输出=输入，如 ROT47→ROT47）一律丢弃；②本文件已拿到强 flag 时，只展示能解出【新】flag 的链；③无 flag 的链必须通过自然语言可读性校验（无控制字符、可打印率≥95%、长度≥8、中文占比≥30% 或 ≥60% 字母落在常见词上），扣除 `xxx{...}` 形状的 50 分加分，挡住 ROT13(flag{...}) 与 Base85/91 乱码假阳性。实测：明文样本解码链 15 行→0 行，普通英文样本乱码链→0，base64/三重 base64 隐写样本仍精确给出唯一解码链与 flag。

### ISSUE-2【任务⑤已修复】"重新镜像离线网页"硬编码 `py -3.13`
- 位置：`ctfbox/ui_main.py` 第 1542 行 `subprocess.run(["py", "-3.13", script], ...)`
- 现象：冻结发布给用户后，用户机器不一定装了 Python 启动器 `py`，该按钮会直接失败；且软件自带便携 Python（tools\runtime\python）却没用上。
- 修复：已改用 `common.external_python()`（冻结态优先 tools/runtime/python 便携解释器，其次系统 Python/py 启动器），找不到解释器时在工具中心日志给出明确提示而不是直接抛异常。

### ISSUE-3【任务⑤已修复】CLI 模式在 PowerShell 重定向时控制台中文乱码
- 现象：`CTFToolbox.exe --cli 文件` 在 PowerShell 管道/重定向场景下中文显示为乱码（控制台代码页 936/UTF-8 不匹配）；**报告文件本身为 UTF-8 完全正常，GUI 完全正常**，仅控制台显示层问题。
- 修复：CLI 入口在 Windows 先 `chcp 65001`，再对 stdout/stderr `reconfigure(encoding="utf-8", errors="replace")`（不支持时 try/except 跳过）；报告文件本就为 UTF-8。

### ISSUE-4【复核：非问题，无需修复】JWT 弱密钥检查时 PyJWT 向 stderr 打印 InsecureKeyLengthWarning
- 复核结论：软件自身的 JWT 检查（`modules_codes.jwt_inspect`、`modules_text.jwt_decode`）使用 hmac/base64 手工实现，**不调用 pyjwt.encode**，生产运行不会产生该警告；测试时看到的警告来自测试脚本自己 `jwt.encode` 造 token，与软件无关，不改。

### ISSUE-5【任务⑤收尾阶段修复】离线网页 manifest 使用绝对路径，程序文件夹改名/搬迁后离线入口失效
- 位置：`tools/portable/webtools/manifest.json`、`ctfbox/webnav.py` `load_offline_manifest()`
- 现象：manifest 中记录的是构建机绝对路径（如 `D:/工具合集软件/CTFToolbox/tools/...`），最终程序文件夹改名为 `CTFToolbox_v2.3` 后路径全部失效，只能靠目录名猜测兜底（CyberChef 入口名不在猜测列表内，必然离线打不开）。
- 修复：`_mirror_webtools.py` 改写 manifest 时统一存相对 webtools 目录的相对路径；`webnav.load_offline_manifest()` 读取时相对路径基于 WEB_DIR 还原为绝对路径，同时兼容旧版绝对路径 manifest。实测改名后 CyberChef/zero-width/qrazybox 三个离线入口均能正确解析。

---

## 四、任务①（上次构建失败）结论（已闭环）

- 根因：`ctfbox/crashguard.py` 的 `install()` 以 append 模式全程持有 `workspace/crash.log` 文件句柄；旧 CTFToolbox.exe 仍在运行时执行 PyInstaller `--clean` 删除 dist 目录，触发 `PermissionError [WinError 5/32]`。
- 修复：`build.bat` 开头增加 `taskkill /F /IM CTFToolbox.exe`（容错），构建前确保句柄释放。本次任务⑤重新构建前会再次确认无 exe 占用。

## 五、任务③遗留说明（非错误）

- exe 的 PE 版本资源已补齐：新增 `version_info.txt`（FileVersion/ProductVersion 2.3.0.0，中英双 StringTable），spec 的 EXE() 已加 `version="version_info.txt"`，右键属性可见「CTFToolbox 万能 CTF 集合工具箱」与 2.3.0.0。
- `ctfbox/__init__.py` 的 `__version__` 已由旧的 1.0.0 更新为 2.3.0。
- robocopy 退出码 1 在其语义中为"成功复制了文件"（0-7 均成功，≥8 才失败），shell 包装层显示 failed exit code 1 属误报，源/目标文件数与字节数核对一致。

## 六、未做自动化覆盖的范围（如实声明，建议人工抽查）

以下功能依赖真实网络/外设/交互式窗口，自动化环境不具备，未做端到端实测，代码路径已走读且按钮实例化无异常：
1. SSH 终端真实连接（需可用的 SSH 目标与凭据）；
2. 媒体中心视频播放、音频播放（ffplay 弹窗）、GIF 逐帧播放的实际画面（ffmpeg/ffplay 二进制已验证存在且 ffmpeg 探测正常）；
3. 工具中心的 winget 在线安装（Nmap/Wireshark）、"补全便携运行时"在线下载、"一键补齐 Kali 套件"；
4. sqlmap 对真实靶场的注入跑批；
5. "重新镜像离线网页"联网流程（且该按钮存在 ISSUE-2，任务⑤修复）；
6. 资源管理器拖文件入窗的拖放动作；
7. 外部工具按钮实际拉起 Ghidra/x64dbg/dnSpy/DIE/radare2/ExifTool（路径检测均显示"已就绪"）。

## 七、任务⑤修复与回归结果（已完成）

1. BUG-3（ui_media 线程安全回填 `_ui`）、BUG-4（雕刻 ZIP 真实试解压校验 + 重复结论去重）、BUG-5（Report 级 flag 去重）全部修复；
2. ISSUE-1（解码链降噪，含恒等链/形状加分/可读性门槛三重过滤）、ISSUE-2（镜像按钮改用 external_python 便携解释器）、ISSUE-3（CLI chcp 65001 + UTF-8 reconfigure）修复；ISSUE-4 复核为非问题；
3. 收尾阶段又发现并修复 BUG-6（重新镜像按钮引用的 `_mirror_webtools.py` 工程中缺失 + 冻结态路径错误，已补脚本并修正路径与 build.bat）、BUG-7（修复/雕刻双路径重复分析同一 ZIP，已加 SHA256 内容去重 + 压缩包成员指纹去重）、ISSUE-5（manifest 改相对路径，程序文件夹可整体搬迁）；
4. 最终回归（全部修复后代码）：后端 51/51、GUI 40/40、GUI 补充 16/16、报告导出 5/5、冻结态脚本库 89 文件，全部 PASS，无线程异常；
5. 最终 PyInstaller 重新构建（2026-10-09 18:20 后，PE 版本 2.3.0.0），部署后 scripts 89 文件、_mirror_webtools.py 位于 exe 同级、tools 离线镜像刷新（CyberChef v11.5.0 / zero-width / qrazybox，manifest 相对路径）；
6. 冻结 exe 复验：CLI 明文样本仅 1 条 flag 且零解码噪音、base64 样本唯一解码链命中、MD5 样本爆破 password、加密 zip 口令 123456、10 号载体 flag 仅 1 条且残缺 zip 正确提示截断；GUI 启动正常无崩溃；
7. 随后清理 build/、__pycache__、workspace 测试产物、测试脚本与样本，最终工作目录只保留：最新源码文件夹、最新源码 zip、程序文件夹（exe+_internal+tools）、题解（Polar 靶场题解.md，未改动）。

---

## 八、v2.4 成品整理与验证（2026-11-06）

整理目标：工作目录只留三项——`CTFToolbox_v2.4` 成品、`_源码_v2.4` 源码归档、`Polar 靶场题解.md`。

### 8.1 保留 / 删除清单

| 处理 | 对象 | 体积 | 依据 |
|---|---|---|---|
| 保留 | `CTFToolbox_v2.4`（exe 2.4.0.0 + `_internal` + tools + scripts + samples + 三个产物目录 + 使用说明.md/html + 卸载脚本） | 3.32 GB | 唯一成品 |
| 归档 | `ctfbox/`、main.py、build.bat、CTFToolbox.spec、version_info.txt、_mirror_webtools.py、.gitignore、README.md、scripts/、samples/、使用说明.md、卸载脚本、`.git` | 约 2 MB | 保留可继续改代码重打包的能力；`.git` 里是尚未推送的 v2.4 提交内容 |
| 保留 | `Polar 靶场题解.md` | 433 KB | 含真实 flag 与靶场凭据，按要求单独留在工作目录根层，不进成品 |
| 删除 | 根目录 `tools/`（只有 6 个 webtools 的旧半成品，113 个文件全部与成品重复） | 47.51 MB | 前期版本残留 |
| 删除 | 根目录 `scripts/`、`samples/`、`使用说明.md`、`卸载CTFToolbox.bat` | 0.4 MB | 与成品逐文件哈希一致 |
| 删除 | 根目录 `exports/`、`reports/`、`workspace/` | 0 | 空目录 |
| 删除 | `tools/portable/_dl/mobaxterm_portable.zip` | 42.17 MB | 已解压完成的一次性下载缓冲，工具本体还在 |
| 删除 | `scripts/library/crypto/__pycache__`（成品与源码各一处） | 9 KB | 跑脚本留下的字节码缓存 |
| 删除 | 4 个 `.DS_Store`（customtkinter 资源目录） | 24 KB | macOS 元数据，Windows 下无用 |

合计删除约 90 MB，成品由 3.43 GB 降为 3.32 GB（30,696 个文件）。

### 8.2 验证记录

1. **副本核对**：根目录 `scripts/` 与成品 `scripts/` 91 个文件逐个 SHA256 比对，0 差异，确认删掉的是纯副本。
2. **版本资源**：exe 的 FileVersion / ProductVersion 均为 2.4.0.0，FileDescription「CTFToolbox 万能 CTF 集合工具箱」。
3. **CLI 实跑**（清理后用临时文本样本，非题目文件）：`CTFToolbox.exe --cli <样本> --ctf-only` 退出码 0，报告正常写入 `workspace\cli_report.txt`，哈希识别与 SHA256 弱口令爆破均命中，说明冻结态的调度链、多进程与字典模块可用。
4. **GUI 实跑**：进程存活，窗口标题「CTFToolbox · CTF 使用确认」，`workspace\crash.log` 只有会话头、无堆栈，说明启动确认流程与主窗口初始化正常。验证后已结束进程并清空 workspace。
5. **目录契约复核**：`ctfbox/common.py` 的 WORKSPACE / REPORTS_DIR / EXPORTS_DIR、`rac/matcher.py` 与 `ui_scripts.py` 的 scripts_root 都以 APP_DIR 为基准，因此成品目录层级未做任何重排。

### 8.3 本次顺手修正的文档错误

1. `使用说明.md` 原写「`samples/` 目录有 23 个覆盖各类题型的测试样例（s1–s23）」，但成品 samples 只剩 `说明.txt`，样例早在发布前清空。已改为空目录占位说明，并指向图文版。
2. `使用说明.md`「目录结构」一节仍标 v2.2，缺 `_internal`，tools 清单漏了 dirsearch / ffuf / xsstrike / jwt_tool / ssrfmap / githack，还把已清空的 `scripts/polarctf` 当作实存目录。已按当前成品重写，并补入 `使用说明.html`。
3. 新增 `使用说明.html`：离线单文件图文手册，不引用外部字体与 CDN，共 12 节，含 RAC 三段式流程图。

### 8.4 未处理项（如实记录）

1. `tools/runtime/python` 下 `__pycache__` 共 1604 个条目、约 21 MB，**保留未删**：它属于随包 Portable Python 的依赖目录，删除通常不影响功能但会让首次导入变慢，且难以逐一排除「只有 .pyc 没有 .py」的包；三万多文件里省这点空间不值得冒这个风险。
2. exiftool 自带的 `exiftool_files\t\images\*.log`（3 个，共 1.5 KB）与 ssrfmap 的 0 字节 `SSRFmap.log` 是上游发行包内容，保留。
3. `_源码_v2.4\tools` 是目录联接（Junction），指向 `..\CTFToolbox_v2.4\tools`，源码包内不含 3 GB 工具链副本。成品文件夹若改名或删除，重新打包前需重建联接或拷入 tools。
4. 源码包的 `.git` 仍是本地仓库，v2.4 改动未推送到 GitHub origin（远端最新仍为 v2.3）。

## 九、v2.4 增强与全功能测试（2026-11-06 第二轮）

本轮在原 v2.4 成品上做三件事：把能拿到的工具全部内置、跑一遍全功能实测、增强 Web 自动化解题。以下只记录实际发生的事。

### 9.1 工具内置

| 工具 | 落点 | 结果 |
|---|---|---|
| nmap 7.92 | `tools\portable\nmap\nmap-7.92\nmap.exe` | `--version` 正常输出；提示缺 Npcap 函数，降级为 connect() 模式 |
| John the Ripper 1.9.0 jumbo | `tools\portable\john\john-1.9.0-jumbo-1-win64\run\john.exe` | `--help` 正常；`detect_one("john")` 命中 |
| uncompyle6 3.9.3 / decompyle3 3.9.3 | 装进 `tools\runtime\python` | 补 pycdc 缺口，`py_compile` 生成的 pyc 可反编译 |

下载过程里的坑，记录在此以免下次重复踩：

1. **nmap**：官网 `dist/` 只有 7.92 及更老的 win32 包（7.95/7.94 均 404）。直连下载会在 6.9 MB 处被服务端提前断开，按猜测的总字节数续传得到的 zip 校验不过（`BadZipFile`）。正确做法是 HEAD 取真实 `Content-Length=22,892,266`，再用 Range 补最后的 36,586 字节，838 个成员校验通过。
2. **john**：openwall 单流限速约 60 KB/s，12 连接并行不提速；只有「4 连接 × 每段 1 MB」能稳定跑满，1365 秒下完 62.3 MB。
3. **steghide**（未落地）：官网下载链接指向 SourceForge，`downloads.sourceforge.net` 与各 `*.dl.sourceforge.net` 镜像一律返回 121 KB 的 HTML 中间页（带 `ts=` 令牌，拿令牌再取仍是 HTML）；SourceForge 页面本身 403；浏览器打开会撞 Cloudflare 人机校验；`web.archive.org` 两次连接超时；GitHub 上 StegCracker / StegHigh、R4yGM 等仓库均不托管 exe；MSYS2 仓库索引里没有 steghide 包。官方只发布源码，本机编译器又不完整，因此拿不到可运行的 Windows 二进制。
4. **pycdc**（未落地）：`zrax/pycdc` 无 release 资产，clone 下来的 12 个 .cpp 需要 C++ 编译器；本机 `D:\mingw64\bin\g++.exe` 连 hello.cpp 都编不出来（缺 `cc1plus.exe`，rc=1 且无错误输出），无法自编。
5. **RouterPassView**（未落地）：`www.nirsoft.net` / `nirsoft.net` 的 http、https 四种组合全部连接超时，整域不可达。

本轮顺手修掉的三个真实缺陷：

1. pip 类工具（`volatility3`、`binwalk`）原来只查系统 Python；改为先查随包 `tools\runtime\python\python.exe`，再查系统 Python。这样没装 Python 的机器也能判定这两个工具可用（实测随包 Python 里有 binwalk，Scripts 下有 `vol.exe`）。
2. `PATH_TOOLS` 里的工具只查系统 PATH。nmap 放进 `tools\portable` 之后 `detect_one("nmap")` 仍返回 None——包里放了等于没放。已在 `toolsmgr.detect_one` 增加「先查 `tools\portable\<名称>` 递归，再查 PATH」。修好后返回 portable 路径，功能区测试的 nmap 项也从 SKIP 转为 PASS。
3. `crash.log` 每次启动写一行会话分隔，正常退出也不清理，`workspace` 里长期挂着空日志。改为两段收口：正常退出（atexit）时若除分隔头外没有任何内容就删除；被强杀留下的空日志在下一次启动时先识别并清掉。真崩过的文件（含堆栈）始终保留。

### 9.2 Web 自动化解题增强

新增 `ctfbox/webauto.py`（约 560 行）并接入 Web 工作流（步骤名 `auto`）与 CLI（`--webauto`）：

- `Budget`：160 次请求上限、240 秒截止、0.5 秒最小间隔；`_safe_url` 只放行 http/https 且拒绝带凭据的 URL；`_same_origin` 强制同源；`_NoRedirect` 不跟随 3xx。
- 软 404 基线：先请求两个随机不存在路径，状态码与长度相近即视为未命中。
- 27 条敏感路径，每条带内容签名（`.git/HEAD` 需 `ref:` 或 40 位 sha、`.env` 需键值行、zip 需 `PK\x03\x04`、`flag.php/txt` 需正文含 flag）。
- 参数弱点：SQL 报错、路径穿越/LFI（含 `php://filter` base64 源码）、SSTI 双发交叉确认（`{{7*7}}` 与 `{{7*8}}`，49/56）、命令注入先判回显再试拼接。
- 26 个目录词、robots.txt 解析并跟进 Disallow；结论落 `reports\web_auto_*.json`，输出 summary 与下一步建议。

五轮迭代里修掉的五个真实 bug：

1. 基线请求把相对名传给 `fetch()`，被判跨源拒绝 → 改拼绝对根路径。
2. 敏感文件与目录探测把查询串拼进路径（`/sqli?id=1/flag.php`），导致整表误命中 → 新增 `_base_root()` 去掉 query。
3. robots 跟进条件写反（`if "/" in rel: continue`）把 `/secret_dir/` 跳过 → 改为去首尾斜杠并拒绝 `..`。
4. SSTI 只发 `{{7*7}}`，靶站页面本就含 "49" 造成误判 → 改双发 49/56 交叉确认。
5. 命令注入把「页面回显输入」当成「命令执行」→ 先发纯标记确认是否仅回显，是回显则记 `reflected` 并标注「不等于命令执行」。

### 9.3 全功能测试

| 套件 | 覆盖 | 结果 |
|---|---|---|
| `ctf_fulltest.py` | 22 个现场生成的样本：base64/hex/摩斯文本、PNG(tEXt)、GIF(comment)、BMP(尾附)、SVG、WAV(LSB)、ZIP、DOCX(手写 OOXML)、PDF(手写最小 PDF)、SQLite、PCAP(TCP/HTTP)、PYC、ELF、JS/JSON/LOG/CSV/XML、btsnoop、成品 exe 当 PE 样本 | 22/22 通过，0 失败 |
| `ctf_test_webauto.py` | 自建靶站 17 项断言：`.git`、`.env`、源码包、robots 与隐藏目录、flag 提取、建议输出、LFI、SSTI、命令注入、SQL 报错，以及 file:// 拒绝、带凭据 URL 拒绝、跨源拒绝、请求预算共 4 条安全边界 | 17/17 通过 |
| `ctf_surface_test.py` | Web 工作流五步、JWT 解析、哈希识别与爆破、链式解码、正文内联编码扫描、工具清单、7z/hashcat/ffmpeg/upx/radare2/sqlmap/john 实际拉起、wav→mp3、GUI 启动 | 18 PASS / 0 FAIL / 5 SKIP |

5 个 SKIP 的具体原因：GUI 按钮与拖放交互需人工点选；SSH 真实连接无可用服务器；RAC 真实 APK 流水线无真实 APK 样本；工具中心在线安装本机无 winget；nmap 项在本轮修复前因检测缺陷先记 SKIP，修复后已转 PASS。

测试脚本自身也踩了几个坑，一并记下：JWT 样本原先签名段不是合法 base64url，改为用 `hmac` 现场签发 HS256；`sqlmap --version` 会等 stdin 回车卡 90 秒，加 `stdin=subprocess.DEVNULL` 后降到 0.9 秒；`tools\portable` 下是两级目录（`hashcat\hashcat-7.1.2\hashcat.exe` 这类），第一版按扁平路径写导致 5 项假失败；工具路径应统一走 `toolsmgr.detect_one`，不要硬编码。

### 9.4 本轮确认的限制

1. nmap 未装 Npcap 时只能 connect() 扫描，SYN 等原始包扫描不可用（属环境限制，非软件缺陷）。
2. GUI 交互、SSH 真实连接、RAC 真实 APK 流水线、winget 在线安装无法在本机自动化验证，只能做启动烟测与代码路径核查。
3. Web 自动取证的预算（160 次 / 240 秒）对目录规模大的靶场偏紧，需要人工接着跑 dirsearch/ffuf；这是有意的保守设定，避免对靶机造成压力。
4. 正文内嵌编码扫描对「无 padding 的超长 base64 串」会产出多个候选片段，靠可打印率与 flag 命中双重过滤，极端情况下可能漏掉非标准编码的 flag。

### 9.5 本轮清理

再次清空成品与源码的 `workspace`（成品 13 项、源码 327 项）与 `reports`（25 项），删除 `tools\portable\_dl` 下三个下载缓冲（john.zip 62.3 MB、john.zip.part2 2 MB、nmap.zip 21.8 MB）、源码 `dist`（4127 项）与 `build`（18 项）后再删空目录。成品当前 32,452 个文件 / 3.48 GB（tool 增加 nmap 与 john 后体积上升，文件数增加约 1.7 千）。
## 十、深度全自动 Web 测试（2026-11-06 第三轮）

### 10.1 做了什么

新增 `ctfbox/webattack.py`（约 640 行），把「一个网址 → 点开始 → 自动跑完」做成一条链：

1. `analyze()`：读标题、Server / X-Powered-By、技术线索，解析全部表单（跳过跨源 action）与带参链接，记录 Cookie 名。
2. `build_targets()`：最多 8 个可注入参数——URL 查询参数 + 带参链接参数 + 表单字段。
3. 六类矩阵逐参数全组合：`test_sqli`（报错 6 种 + 布尔成对 + 时间盲 2 种）、`test_xss`（6 种，区分反射与被实体编码）、`test_lfi`（6 种穿越 + php://filter 读 5 个脚本 + 命中后按 11 条 FLAG 路径定向读）、`test_ssti`（5 种引擎语法 + 第二组乘积交叉确认）、`test_cmdi`（先判回显，再用算术判真执行）、`test_ssrf`（只测 url/file/path 类参数，file:// 归 lfi-wrapper）。
4. `test_upload()`：三种载荷形态（普通 `.php`、PNG 头 + PHP 的图片马 `.png.php`、双扩展 `.php.png`），内容统一只回显 `CTFBOXUPLOAD9137`；上传后按响应链接 + 8 个常见目录 + 根目录探测，区分可执行与只存不解析。
5. `flag_hunt()`：直读 6 个常见 flag 路径，再看 robots / sitemap。
6. `campaign()` / `render()` / `save_report()`：落 `workspace\webattack_report.txt` 与 `reports\webattack_*.json`。

接入点：`webworkflow.ALLOWED_STEPS` 增加 `deep`、新增 `_deep()`（跑完矩阵后按时间余额接力 sqlmap 与目录词表）；`main.py` 增加 `--webattack/--deep` 分支（强制 `--ctf-only`）；`ui_web.py` 把「★ 深度全自动」置顶且默认勾选，单步限时改为 420 秒。

### 10.2 自建靶站与测试

靶站 `%TEMP%\ctf_deeptarget.py`（127.0.0.1:18081）：反射 XSS、SQL 报错 + 布尔（`1=1` 返回六条、`1=2` 返回空）、LFI `/view?file=`、SSTI `/page?name=`（能算 5 种语法）、命令注入 `/ping?host=`、上传后可执行、直读 `/flag.txt`、`.git/HEAD`、`robots.txt`、登录表单 POST 注入。

测试 `%TEMP%\ctf_test_webattack.py` 共 21 项断言，最终 **21 PASS / 0 FAIL / 0 SKIP**：

| 项 | 结果 |
|---|---|
| 反射 XSS / SQL 报错 / SQL 布尔 / LFI / SSTI / 命令注入 / 上传可执行 | 全部命中（16 条发现） |
| 取得 flag | `flag{deep_hunt_9137}` |
| 请求与时长 | 226 次 / 112.6 秒（预算 380 次 / 420 秒） |
| 报告 | JSON 可读、文本三段齐全、外部命令 5 条 |
| 上传形态 | 普通脚本、图片马、双扩展名三种都实际投放，multipart 共 3 次 |
| 安全边界 | `file://` 拒绝、带凭据 URL 拒绝、无破坏性 SQL、无 eval 型载荷 |
| POST 表单 | 登录表单进入测试 |

成品 exe 复跑：`CTFToolbox.exe --webattack http://127.0.0.1:18081/ --ctf-only` 退出码 0，检出 14 条以上发现、取得 flag，报告写入成品 `workspace\webattack_report.txt`。

### 10.3 本轮改掉的真实缺陷

1. **SQL 布尔恒不成立**：靶站对含单引号的请求一律先回报错页，真假两条响应完全相同。改法是靶站侧把 `1=2` / `1=1` 判定前置（模拟真实可注入点），引擎侧保持"按响应实质差异比对"不变；顺带确认引擎在两条都报错的场景下不会误报。
2. **回显即判死命令注入**：旧逻辑一旦看到中性标记被回显就记 `reflected-only` 并 `return`，但真实 shell 注入点常同时回显命令与输出。改为"回显也继续测算术 payload"，只有 `$((9137+1))` 被求值成 9138 才判 `cmdi`；回显但未求值仍记 `reflected-only`（低置信度）。
3. **上传表单字段被当普通注入参数**：`note`、`pass` 这类随文件提交的文本框原先也进矩阵，导致 `POST /upload` 被反复打 38 次、留一堆空文件。改为上传表单的非文件字段一律不进参数矩阵，multipart 只由上传测试发（实测降到 3 次）。
4. **`file://` 成功被记成 SSRF**：`file:///etc/passwd` 读成功本质是本地文件包含。改为按协议分流：`file://` → `lfi-wrapper`，只有 http(s) 出网成功才算 `ssrf`。
5. **ffuf 建议命令 URL 拼错**：原先把带查询串的原地址再拼 `?FUZZ=1`，得到 `?q=1?FUZZ=1`。改为取根路径后拼 `?FUZZ=1`。
6. **XSS 证据被截断成上下文前缀**：证据窗口从 payload 前 60 字符起算、只留 90 字符，长 payload 时看不到 payload 本身。改为以 payload 位置居中取 160 字符。
7. **成品 exe 的 `--webattack` 首次验证"看起来没反应"**：`CTFToolbox.exe` 是 `console=False` 的窗口程序，PowerShell 用 `&` 调用不会等待，日志文件 0 字节、误判成没进分支。改用 `Start-Process -Wait` 后确认退出码 0、报告正常落盘；同时把 guard 报错文案的编码在主入口最前面统一成 UTF-8（此前未走分支内的 reconfigure，中文报错在 GBK 下乱码）。

### 10.4 仍然没做到的

1. **冰蝎 / 菜刀 / AntSword 不做自动交互**：软件只提供手动启动入口与只读流量取证；上传测试投放的标记文件不含会话管理、命令执行、反弹连接能力，也不与任何客户端通信。这是有意收敛，不是没写完。
2. **外部工具只接力 sqlmap 与内置目录词表**：xsstrike 官方 CLI 没有可强制的禁跳转开关，dirsearch/ffuf 只在用户手动勾选对应步骤时执行，不做无授权的自动串联。
3. **时间盲 SQL 只发 2 种 payload**，单条 3 秒等待；靶机限流严格时可能被提前掐断。
4. **上传后的路径探测依赖 8 个常见目录 + 响应里的链接**，自定义命名规则的上传点仍需人工从响应里找。
5. GUI 的「★ 深度全自动」勾选框、日志高亮与停止按钮仍需人工点选验证（自动化只能验证 import 与启动烟测）。

## 十一、真实靶场复验（2026-11-06 第四轮，CTFHub）

第四轮不再用自建靶站，直接登录 CTFHub 技能树开题，用本工具原样跑，按现场表现改代码。

### 11.1 已通过的题：文件上传·无验证

环境 `http://challenge-6d55d9f87731f010.sandbox.ctfhub.com:10800/`。工具 17 次请求 / 11.2 秒，
自动上传普通 PHP 脚本 → 探测到 `/upload/shell<标记>.php` 可执行 → 补投取 flag 脚本 → 拿到
`ctfhub{2eb93c7b87a3fcf24c1f7eb2}`；把 flag 提交到题目，页面回“flag正确，你已获得5点经验及50个金币”，判对。

### 11.2 现场发现的缺陷与改法

1. **连接被重置被当成“没找到”**：靶场对“PNG 文件头 + PHP”组合直接 `ConnectionResetError WinError 10054`，原逻辑只看访问结果，于是记成“8 个候选路径均未回显标记”，看起来像上传失败没找到路径，实际是被内容检查拦下。
   - 改：`_request` 统一加 `Connection: close`；上传 `status == 0` 时隔 2 秒重试一次；
   - 仍为 0 则新增发现类型 `upload-blocked`，证据里带原始错误，日志写“被拦截，跳过探测”。
   - 隔离验证：纯 PHP 200、纯 PNG 200、纯 PNG 无 PHP 200、`PNG+PHP` 必被重置——确认是靶场侧内容检查，不是网络偶发。
2. **flag 放在随机文件名**：容器里是 `/var/www/html/flag_1712123341.php`，原固定路径清单读不到，工具只能报“可执行”却拿不到 flag。
   - 改：取 flag 脚本改为扫 `getcwd()`、Web 根目录、其上一级与 `/tmp`，只读文件名含 `flag` 且内容命中 flag 格式的文件；上传点确认可执行后自动补投并取回。
   - 结果：同一题仍 17 次请求 / 11.2 秒拿到 flag，新增发现类型 `flag-read`。
3. **GET 表单被当成 POST**：SQL 整数型注入题的搜索表单是 `method="GET"`，解析器读了 method 但构造目标时一律写 `kind="post"`，于是对 `POST /` 打了 46 次、0 命中。
   - 改：按表单真实 method 分 `post` / `get`；GET 表单把其余字段按默认值一起拼进查询串，只替换被测参数。
4. **布尔注入差异阈值过大**：该题真假条件只差一行 `ID: 1 / Data: ctfhub`，去标签后相差 22 字节；原阈值 `≥40 字节且 ≥15%` 判成“无差异”。
   - 改：阈值降为 `≥15 字节且 ≥1.5%`，并补一组数字型布尔 payload `1 AND 1=1` / `1 AND 1=2`（原来只有带单引号的字符串型）。
   - 结果：复跑即检出 `sqli-boolean`，真/假 1147 vs 1125 字节。
5. **XSS 反射与“只是回显参数”混在一起**：反射型 XSS 题里，参数被原样回显但不是 HTML 上下文时，工具会同时给 `xss-reflected` 与 `reflected-only`。这条不是错误（两件事都成立），但报告里要能看出区别，文档已写明。
6. **回归测试的 multipart 上限过期**：加了“取 flag 脚本”这一次上传后，原断言 `multipart ≤ 4` 变红（实际 5 次）。改断言为 `≤5` 并注明构成：三种形态 + 取 flag 脚本 + 被拦重试。

### 11.3 复验结果

- 本机自建靶站：21 项断言 **PASS 21 / FAIL 0 / SKIP 0**，237 次请求 / 118.1 秒，18 条发现，拿到 `flag{deep_hunt_9137}`。
- 成品 exe（用含上述修改的源码重新打包后）：同样跑本机靶站，237 次请求 / 118.1 秒，18 条发现，flag 1 个，报告落盘正常。
- CTFHub：文件上传题解出并判对；SQL 整数型检出布尔注入；反射型 XSS 检出反射。

### 11.4 仍然没做到的（与真实靶场有关）

1. **SQL 注入只到“检出”不通“取数”**：布尔/报错能判定，但不做 `UNION` 取库表、不 dump、不跑 sqlmap 的数据提取，因此注入类题目的 flag 仍要人工用 sqlmap 或手写 payload 取。这是有意保留的边界（只探测不取数）。
2. **XSS 题目无法自动完成“打管理端拿 flag”**：反射/存储判定后需要外部接收端与外带通道，工具不提供。
3. **上传题只适用于“上传即可执行”的题型**：`.htaccess`、MIME、00 截断、二次渲染等需要构造特定文件内容或特定解析链的题，当前只有三种形态，未逐一覆盖。
4. **CTFHub 每题 50 金币开启、每分钟 1 金币续期**，工具本身不感知金币与倒计时，环境过期后请求会全部失败。
## 十二、真实靶场第二轮修正（2026-11-07，CTFHub 六个新题型）

本轮在 CTFHub 继续刷题型，按“发现一处缺陷改一处”处理，全部改动都留在源码并通过本机回归（21 项断言全过）。

### 12.1 目录遍历题 0 命中：链接解析把目录过滤掉了
现象：题目首页只有一个 `<a href="flag_in_here/">`，`parse_links()` 只收“带 `?` 或脚本后缀”的链接，目录链接全被丢，一轮 9 次请求 0 发现。
改法：新增只读 `dir_crawl()`：从根开始跟“以 `/` 结尾”的链接 BFS，默认 3 层、最多 60 页；目录可列出即记 `dir-listing`，文件名含 `flag` 的一律取回。改后 29 次请求 / 14.1 秒，在 `/flag_in_here/4/1/flag.txt` 取到 flag，提交判对。

### 12.2 网站源码泄露：备份包里的 flag 文件是幌子
现象：`www.zip` 能下（1085 字节），包内 `flag_2647618785.txt` 内容却是 `where is flag ??`，直接读包拿不到。
改法：新增 `backup_hunt()`：拉 `www.zip`/`www.tar.gz`/`backup.zip`/`web.zip` 等常见备份，zip 在内存里展开；**包内文件名含 flag 的，再到服务器同名路径直读**。改后 12 次请求 / 5.7 秒拿到真 flag。

### 12.3 bak 文件题：残缺命中混进 flag 列表
现象：`index.php.bak` 里既有 `FLAG: ctfhub` 这种残缺串，也有真 `ctfhub{...}`，旧逻辑会把两者都入库。
改法：`_add_flag()` 增加花括号校验，`{`/`}` 不齐的命中直接丢弃并记日志。改后只报真 flag，22 次请求 / 10.7 秒。

### 12.4 MIME 绕过题：取 flag 脚本用了错的 Content-Type
现象：上传 `mime<标记>.php` + `Content-Type: image/png` 能执行（`upload-exec`），但取 flag 脚本一直“已执行却没有 flag”。
根因：取 flag 脚本固定用 `application/x-php` 上传，MIME 校验题只认图片类型，脚本根本没落地（HTTP 200 但文件不存在）。
改法：`test_upload` 把成功形态的 `ctype` 记进结果，`_read_flag_via_upload()` 沿用同样的 Content-Type，并在取回 404 时明确打印原因而不是笼统说“没有 flag”。改后 26 次请求 / 15.7 秒拿到 flag。

### 12.5 字符型注入：UNION 取数三处坑
现象 1：UNION 列数永远判成 0。根因是字符串上下文没闭合引号，payload 拼成 `0 union select ...` 落在引号里。改法：`test_sqli` 记录布尔命中用的是字符串组还是数字组，透传 `quote` 给 `union_extract()`，字符串上下文改拼 `0' union/**/select ...-- -`。
现象 2：闭合后仍只显示真实记录。该题页面 `mysqli_fetch_row()` 只取第一行，用 `1'` 打头时第一行永远是 `ID:1 / Data:ctfhub`。改法：字符串上下文统一用不存在的 `0'` 打头。
现象 3：`union select` 字面量被 WAF 断连。沿用 `union/**/select` 注释切割写法。
改后 46 次请求 / 25.3 秒，从 `flag` 表取到 flag，提交判对。

### 12.6 上传“200 但不落地”：少提交了表单按钮字段
现象：手工诊断时上传返回 200，但 `/upload/<name>.php` 一律 404；用工具自己跑却能拿到 `upload-exec`。
根因：表单里有 `<input type="submit" name="submit" value="Submit">`，漏掉 `submit` 字段时后端不进入保存分支，只回显表单。
结论：这不是软件 bug（软件一直按表单默认值把 `submit` 一起提交），但记录在此，避免以后手工复现时被 200 误导。

### 12.7 仍然没做到的
- XSS 反射型只能检出与区分“只回显”，拿不到需要浏览器端交互验证的 flag；
- 存储型 XSS、DOM 型 XSS 没有自动验证链；
- 弱口令/口令爆破、JWT 伪造、SSRF 打内网等题型还没有自动取 flag 的闭环；
- 文件上传的 `.htaccess` 解析劫持、00 截断、二次渲染等形态尚未实现（受靶场 PHP 版本与 WAF 限制，需逐题确认）。
