# CHANGELOG

## v3.7.0 — 2026-11-08

### 更新公告

取消工具内的逐功能/逐目标边界，改为**唯一一道《软件责任说明》闸门**：GUI 每次启动必须勾选同意才能进入，拒绝或关闭窗口直接退出；CLI 首次使用加 `--accept-responsibility`，确认持久化后直接运行。责任说明写明授权与合法使用、能力与风险、数据与隐私、无担保与责任限制。逐工具声明、域名白名单、私网限制与 `--ctf-only` 强制参数全部移除；所有功能与随包工具进入后直接可用。PE 版本号 `3.7.0.0`。

### 新增

- **唯一责任闸门** `ctfbox/responsibility.py`：版本化说明文本 + SHA-256，确认记录写入 `workspace/config/responsibility.json`；版本变化后旧确认自动失效；`ensure_cli()` 在 CLI 入口统一拦截。
- **启动责任说明窗** `ctfbox/ui_consent.py`：780×620 深色说明窗，必须勾选「我已逐条阅读并同意」才能启用「同意并进入」；拒绝/关闭窗口退出；内置「阅读使用说明」。
- **测试** `tests/test_responsibility_v37.py`：CLI 未同意拦截、`--accept-responsibility` 放行与落盘、版本失效、撤销、条款关键字。

### 修复

- 责任说明窗文本区默认 24 行请求高度把勾选框与「同意并进入」挤出 620 高窗口，用户实际无法同意进入；改为显式 `height=12`，并新增布局回归测试，断言勾选框与同意按钮均可见且在窗口内。

### 变更

- `scope.py`：只校验 http/https 与拒绝 URL 内凭据；`authorized`/`allow_hosts`/`allow_private` 保留为兼容参数，不再拦截；主机类型仅作标注。
- `consent.py`：降级为历史记录兼容层，`require()` 恒放行；`ConsentError` 保留类型但不再抛出。
- `exploit/client.py`、`exploit/engine.py`、`webattack.py`、`orchestrator.py`：移除逐请求/逐阶段声明检查与拒绝分支。
- `autopilot/cli.py`、`platforms/cli.py`、`main.py`：移除 `--ctf-only`、`--consent`、`--i-own-this-target` 强制要求；保留为兼容参数；`main.py` 八个 CLI 分支统一先过 `responsibility.ensure_cli()`。
- GUI：一键梭哈页删除授权/私网勾选与域名白名单行；Web 页删除授权复选框与深度利用声明弹窗。
- 版本号与文案升级到 3.7.0（代码、UI、赛事专项、`version_info.txt`）。

### 验证

- 全量单测 **95 tests OK**（含新增责任闸门测试、责任说明窗布局回归与更新后的 scope/consent 回归）。
- CLI 实测：未同意时 `--comp` 退出 2 并打印责任说明；加 `--accept-responsibility` 后退出 0，`workspace/config/responsibility.json` 写入确认记录。
- 无逐工具声明时 AutoPilot 直接进入 Web 利用链（本机靶站 48 次请求、5 项发现、5 个验证样本），审计与限速正常。
- 构建与分发包实测数据见本节末尾（打包后补记）。

### 安全边界

- 授权判断统一前移到进入软件前的责任说明；软件不判断目标归属。
- 保留工程约束：Web 只接受 http/https、拒绝 URL 内凭据；每次利用请求写审计；限速与请求预算不变；未知二进制默认只做静态分析；不做公网批量扫描。

## v3.6.0 — 2026-11-08

### 更新公告

一键梭哈增加**首层判型（主考点路由）**：入口先判断题目主考点并输出证据与置信度，只执行被证据选中的阶段与脚本，不再对每题遍历全部工具与阶段；脚本库按判型自动调用并自动填参，缺依赖/无参数的脚本预检跳过、不占编排步。文件与 Web 的 `mohe-wp-v1` WP 均新增「首层判型（主考点路由）」章节。PE 版本号 `3.6.0.0`。

### 新增

- **首层判型** `ctfbox/autopilot/triage.py`：输出 `kind/category/subtype/confidence/evidence/stages/scripts/skipped/notes`（Web 另有 `web_phases`）；文本识别 PHP 源码、哈希、无空白 XOR/编码密文、像素矩阵、零宽字符；二进制识别 PNG/JPEG/GIF、PCAP、pyc、ELF（按保护位/符号区分 PWN 与 REVERSE）、文档/取证镜像、未知高熵；并给出要执行的阶段与脚本清单。
- **Web 证据评分** `web_triage`：按表单/上传点、参数名语义、序列化线索、PHP 源码、技术栈、题面关键字与 URL 路径分段累计评分；登录/上传阈值 2.0 且优先，常规阶段阈值 1.5，上限 8 阶段；无证据回退 SQLi + XSS/JWT/IDOR；反序列化阶段只在确有序列化/源码/Java/PHP 证据时执行，并记录「无证据跳过」原因。
- **脚本库自动调用**：`scriptlib.REGISTRY` 白名单约 28 个脚本按判型自动选择并生成参数（如 `zero_width_stego -f`、`registry_hive_parse --ntuser/--software`、`pcap_dns_exfil <pcap>`）；`scriptrun.prepare` 执行前预检解释器、脚本文件、依赖模块与参数，不可用时跳过并记录原因，不消耗编排步数；`ScriptSpec.args` 支持 builder 返回空参数。
- **文件 WP 判型章节**：`build_file_wp` 在信息收集后输出「首层判型（主考点路由）」（类型、置信度、证据、执行阶段、自动脚本）；Web WP 同样在解题过程前输出判型小节。
- **报告同步**：`report.md` 标题使用 `VERSION`，文件/Web 均插入判型小节。

### 修复/加固

- 零宽字符判型正则补入 `U+FEFF`（本软件 `zero_width_stego` 编码器以 FEFF 作分隔符，短样本此前会漏检）。
- 文件 WP 构造 `wp_result` 时补传 `triage`，避免 WP 缺少判型章节。
- `scriptrun` 弱模式 flag 置信度改为 0.55/0.5，仅强模式（`flag{}`/已知前缀）记 0.9/0.88，避免弱匹配直接判定成功。

### 验证

- 零宽隐写样本：自动跑 `encode_decode_hub` + `zero_width_stego`，得到 `flag{zw_auto_script}`，WP 含判型章节。
- ELF REVERSE 样本（Ghidra `sleigh`）：`elf_reverse → deep.executable → binary.parse → Ghidra`，5 步。
- PWN ELF 样本：`elf_pwn → binary.parse + pwn.static + checksec_binary`，5 步，未进入 Ghidra。
- PNG LSB / WAV LSB / PCAP HTTP 样本：分别由 `stego.image` / `deep.media` / `deep.capture` 直接命中，未浪费无关脚本。
- Web 本机靶站：判型选出 7 个有证据阶段（upload/login/xss_jwt_idor/ssrf_xxe/sqli/cmdi/ssti_lfi），deser 无证据被跳过。
- 单测：新增 `tests/test_triage_v36.py`（28 项，含文件/Web WP 判型章节与 AutoPilot 端到端字段断言）；全量 **90 tests OK**。
- 成品：PyInstaller 构建 PE `3.6.0.0`（文件版本/产品版本均已核对）；交付目录 3,891,852,609 字节（3.62 GB）；ZIP `魔盒-ctf-v3.6.0-win64.zip` 1,895,781,568 字节（1.77 GB，33,294 个文件/4,127 个目录），SHA256 `0c2f5f7178c2fda17f08632f360aee65499619eaf85aa0dad413ef26f394a683`。
- 分发包复测：`7z t` 全量测试 13.6 秒、Exit 0（Everything is Ok）；解压 31.6 秒；解压后的 `魔盒-ctf.exe --auto 202012MISC_PolarDN_CTF_.zip --ctf-only` 自动命中 `flag{ae7e960d8e7ce40e2157285680e2a5e4}` 并生成 `mohe-wp-v1` WP。包内 `workspace` 条目 0，无平台登录态；`credential-like` 命中均为随包工具/库自身的 `cookies.py`、nmap NSE 脚本等，非登录凭据。
- 交付目录冒烟：零宽样本自动调用 `encode_decode_hub` + `zero_width_stego` 命中 `flag{zw_auto_script}`，`wp.md` 含「首层判型（主考点路由）」与「自动脚本」；`--comp defense --ctf-only` 退出 0；干净包内 `--platform polarctf --list --ctf-only` 正确返回「未登录」（退出 2），不携带登录态。

### 安全边界

- 判型与脚本调用均在本地任务工作区内完成；未知二进制只做静态分析、不执行样本；脚本仅来自随包白名单。Web 利用边界未变化（声明闸门 + scope 双校验 + 审计 + 限速）。

## v3.5.2 — 2026-11-07

### 更新公告

补齐「加密 ZIP → 图片密码隐写」自动化链条。PolarCTF 120「菜狗」由 `--solve` 全自动完成：识别嵌套压缩包、破解 ZipCrypto 口令 `zaqqaz`、按同一口令解出 cloacked-pixel 隐写的 `flag{ae7e960d8e7ce40e2157285680e2a5e4}`，并生成 `mohe-wp-v1` WP。PE 版本号 `3.5.2.0`。

### 新增

- **ZipCrypto 口令恢复** `ctfbox/modules_zipcrack.py`：候选来源含题名/文件名/内层成员名/日期/数字前缀/键盘行与列走位及镜像（`zaq` → `zaqqaz`）/常见弱口令/大小写与 leet/后缀；先用 12 字节加密头快速筛选，命中后必须完整解密并通过 CRC32 复核，单次错误口令不能伪造结果。实测 478 次尝试、0.26 秒命中。
- **john 深度回退**：`--deep` 时调用随包 `zip2john.exe` + `john --format=PKZIP --wordlist=password.lst --rules`，带超时、独立 pot/session；命中后同样 CRC 复核。
- **cloacked-pixel 提取** `ctfbox/modules_stego.py`：识别 AES-CBC(SHA-256 密钥、32 字节分组) + RGB LSB(MSB 序) 格式，支持 UTF-8/GBK/UTF-16LE 口令，校验 PKCS#7 与内容类型（flag/文件头/可打印文本），产物只写任务工作区。
- **AutoPilot 图片隐写阶段** `ctfbox/autopilot/tools/stego.py`：压缩包成员与独立图片自动跑 EXIF/PNG 块/LSB 多比特/尾部数据/FFT/cloacked-pixel；压缩包恢复出的口令优先复用。
- **GUI/CLI 同步**：图片分析入口自动尝试 cloacked-pixel，弱口令/题名/文件名候选命中即报 flag。

### 修复/加固

- 加密 ZIP 解包不再只试内置弱口令；候选命中路径使用原始字节口令解包，避免中文/非 ASCII 口令被 7z 命令行编码破坏。
- 头校验假阳性隔离：只有完整解密 + CRC32 一致才记为「口令命中」。

### 验证

- 120 平台闭环：`main.py --platform polarctf --solve 120 --force --i-own-this-target --ctf-only` → ZipCrypto 命中 `zaqqaz`（478 次/0.26s）→ `stego.image` 命中 0.99 → 生成 WP 并提交（首次为 `correct`，复跑为 `already_solved`）。
- 离线：`main.py --auto caigou.zip --ctf-only --hint 菜狗` 命中同一 flag；`--cli` 分析解密后的 PNG 也自动得到同一 flag。
- john 回退：独立用例 `letmein` 经 zip2john + john 命中并通过 CRC 复核。
- 单测：新增 6 项（口令派生/键盘镜像/ZipCrypto 破解与解包/cloacked 正反例）；随包运行时全量 **62 tests OK**。
- 成品：PyInstaller 构建 PE `3.5.2.0`（文件版本/产品版本均已核对）；交付目录 3,890,816,840 字节（3.62 GB）；ZIP `魔盒-ctf-v3.5.2-win64.zip` 1,895,260,900 字节（1.77 GB，33,191 个文件/4,114 个目录），SHA256 `b79f8ca270a320eee740c5c564ea9ffe300735957af7bcb569e7b3e3f23a1dc1`。
- 分发包复测：`7z t` 全量测试退出 0（13.4 秒，Everything is Ok）；解压耗时 30.0 秒；解压后的 `魔盒-ctf.exe --auto 202012MISC_PolarDN_CTF_.zip --ctf-only` 自动命中 `flag{ae7e960d8e7ce40e2157285680e2a5e4}` 并生成 `mohe-wp-v1` WP。包内关键文件齐全、`workspace` 为空、无平台登录态文件。
- GUI：启动确认页与主界面截图均显示 `v3.5.2`；交付目录 `--comp defense` 与平台 `--list` 冒烟退出 0。

### 安全边界

- 口令恢复与隐写分析均为本地只读计算，不联网、不执行附件；john 只在 `--deep` 下本地运行。Web 利用边界未变化（声明闸门 + scope 双校验 + 审计）。

## v3.5.1 — 2026-11-07

### 更新公告

新增「异常椭圆曲线 + 多维 HNP」自动攻击（纯 Python，不依赖 Sage），并把占位符 flag 误报、异或噪声候选一并根治。PolarCTF 1472 的附件由 `--auto` 在约 1 分钟内自动解出 `flag{893d041e-c0a2-3145-5320-cdee7d3c87fb}`；文件类任务现在也会输出 `mohe-wp-v1` 固定格式 WP。PE 版本号 `3.5.1.0`。

### 新增

- **异常曲线 HNP 攻击** `ctfbox/modules_ecc.py`：大量坐标点隐去 p/a/b 时，用三点行列式 GCD 恢复 p，代回 a/b 确认 `#E=p`；Qp 相对精度 2 的 Hensel 提升 + HNP 线性化，构造 73×73 正交格，Fraction LLL → 右核 → SNF 饱和 → 再 LLL，还原明文。全程纯 Python（自实现 LLL 与 3×73 SNF），约 42 秒，不依赖 sympy/fpylll/Sage。
- **AutoPilot 接入** `ctfbox/autopilot/tools/ecc.py`：顶层文本与压缩包成员文本都会触发；`dispatcher` 一键分析在无 flag 时同样调用。
- **文件类 WP**：`--auto` 离线任务也生成 `mohe-wp-v1` 六章节 WP（题信息/信息收集/解题过程/Flag/修复建议/证据审计），写任务 `wp.md` 并归档 `workspace/wp/`。
- **回归测试**：`tests/test_ecc_v351.py`（格饱和 + 73 点端到端 + 识别）与 `tests/fixtures/ecc_points_1472.txt`。

### 修复

- **占位符 flag 误报**：`flag{??????????????}` 等模板值曾被 strings 以 0.97 报为强候选。新增 `common.is_placeholder_flag`，在 `scan_flags`、exploit 脚本输出、RAC、Web 利用、平台提交与候选汇总处统一过滤；平台提交直接拒绝占位符。
- **异或噪声候选**：XOR 对源码做无意义变换产生的 `flag{??v???????v???}` 不再计入强候选（拒绝 `?`/`*`，要求字母数字下划线占比 ≥ 0.6）。

### 验证

- 1472：`main.py --auto workspace/platform/files/1472/6.rar --ctf-only` → `crypto.ecc` 命中 0.97，WP 归档 `workspace/wp/6.rar_<时间>.md`。
- 单测：`tests.test_ecc_v351` **4 tests OK**（端到端约 42s）；全量 `unittest discover -s tests` **Ran 56 tests, OK**。
- 成品：PyInstaller 构建 PE `3.5.1.0`；交付目录 3.62 GB，ZIP `魔盒-ctf-v3.5.1-win64.zip` 1,895,019,269 字节；`7z t` 全量测试退出 0。
- 解压即用：ZIP 解压到临时目录后，内层 `魔盒-ctf.exe --auto <1472 坐标.txt> --ctf-only` 退出 0，命中同一 flag 并生成 `mohe-wp-v1` WP；占位符样例（`flag{??????????????}`、`flag{your_flag_here}`）候选数为 0、`success=false`。
- GUI：启动确认页与主界面均显示 `v3.5.1`；交付目录 `--comp defense` 与平台 `--list` 冒烟退出 0。

### 安全边界

- ECC 与文件类 WP 均为离线纯计算/静态分析，不联网、不执行附件代码；Web 利用仍受声明闸门 + scope 双校验 + 审计约束，边界未放宽。

## v3.5.0 — 2026-11-07

### 更新公告

平台闭环落地：`魔盒-ctf --platform --solve <题号>` 可自动登录 PolarCTF、开启动态实例、跑完 Web 利用、提交 flag，并按固定格式 `mohe-wp-v1` 输出 Writeup。同时修掉上传利用链的三个真实缺陷（真实落盘路径、包含执行、源码回显误判），在 336/774 两题上完成端到端验证。PE 版本号 `3.5.0.0`。

### 新增

- **平台闭环** `ctfbox/platforms/`：读取保存的登录态 → CTFd 题目/实例 API → 拉起动态容器 → 调用一键梭哈 → 自动提交 → 记录 `correct`/`already_solved`；凭据只存 `workspace/platform/*.json`，不进交付包。
- **固定格式 WP** `ctfbox/autopilot/wp.py`：`mohe-wp-v1` 六章节（题目信息/信息收集/解题过程/Flag/修复建议/证据审计），写任务 `wp.md` 并归档到 `workspace/wp/<题号>_<时间>.md`；只写本次真实证据，未命中阶段明确标注。
- **上传利用链**：
  - 从上传响应解析服务器真实落盘路径（随机改名靶场不再按原文件名瞎猜）；
  - 上传文件不解析时，自动尝试 `file/page/path` 等包含入口，用标记确认是否真正执行；
  - PHP5 `<script language="php">` 载荷，适配把 `?` 替换成 `!` 的上传点；
  - 一次性只读 flag 读取器（固定目录、文件名匹配、无参数、无命令执行、执行后自删）。
- **WP 质量**：上传类章节中文化；Cookie/CSRF 归入补充观察；无登录链路时不再输出无意义的账号候选；中文页面按 UTF-8 解码，标题不再乱码。

### 修复

- 上传校验把「源码里出现标记」误判为「PHP 已执行」：改为先识别源码回显（含 `?`→`!` 变体），只有响应里没有源码标记且出现执行结果才算 exec。
- 表单隐藏字段 `MAX_FILE_SIZE=1000` 会把稍大的读取器直接拒收：上传请求不再发送该客户端提示字段。
- PHP5 读取器里的三元 `?` 被服务端替换成 `!` 导致 500：改为无 `?` 的 `if/else`，并修正 `MOHEREAD` 前缀重复。
- **利用阶段按参数语义排序**：SQLi/SSTI/LFI/SSRF/XSS/IDOR 先测参数名匹配的入口（如 `file`/`url`/`q`/`id`），再测其余参数；修复无关参数先耗尽请求预算、真正入口未被测到的问题。
- **反序列化阶段常驻探测**：页面有表单或参数时即安排 `deser` 阶段（不再只依赖显式序列化线索），仍受预算与声明闸门约束。
- **WP 资料字段过滤**：「选择文件」「上传文件」「返回主页」等控件文案与 `Designed By ...` 页脚不再写入资料页字段。
- **平台 CLI 凭据与动作组合**：`--cookie`/`--user --password` 与 `--list`/`--show`/`--boot`/`--solve`/`--submit` 同时出现时先登录再执行动作；首次使用可一条命令「登录 + 开实例 + 解题」。

### 验证

- **336 自由的文件上传系统**：工具自动发现 `upload.php` → 识别 `?`→`!` 过滤 → 上传 PHP5 载荷 → 经 `sectet_include.php?file=` 包含执行 → 读取 `/f1ag_1s_h3R3_And_You_W1LL_n3v3R_F1nd` → `flag{425fd7f0cdc2b8fc9299869facd3c088}` → 平台返回 `correct`；请求 42/120。
- **774 任务cmd**：工具自动发现命令执行入口 → `cat ../../../../fla?` → `flag{75a121dbb82083c9ec797c39d9b9effe}` → `correct`；登录链（xiaoming/123123 → xiaohei 资料页 → admin/flower）另行验证成功。
- WP 归档：`workspace/wp/336_20261107_203352.md`（最新代码复跑）、`workspace/wp/336_20261107_201910.md`、`workspace/wp/774_20261107_195912.md`（均为 `mohe-wp-v1` 六章节）。
- 回归：`D:\PY\python.exe -m unittest tests.test_competition_v34 tests.test_autopilot_v3 tests.test_autopilot_v33 tests.test_pwn_ret2win` → **Ran 50 tests, OK**；`tests/test_webattack.py` → **26 PASS / 0 FAIL**；`tests.test_autopilot_v33` 单模块 **Ran 10 tests, OK**（含全阶段本地靶站利用链）。

### 安全边界

- 平台闭环与 Web 利用仍受「授权声明 + 域名/子域白名单」双闸门约束；未声明或越界一律拒绝并写审计。
- 上传载荷只做标记回显与只读 flag 读取，不含交互式 WebShell、不提供免杀/持久化；生成物只落任务 `artifacts/`。
- 提交仅对当前题目实例执行一次，不扫其他题目、不扩散目标。

## v3.4.0 — 2026-11-07

### 更新公告

新增「赛事专项」：内存取证（Volatility 3）、流量深度分析、APK 反编译与凭据审计、PHP/Java/Python 源码审计、Windows/Linux 安全基线、日志时间线与攻击面验证清单。全部为**离线只读分析**；加固脚本与 WAF/NGFW 用例**只生成、不执行、不发送**。PE 版本号 `3.4.0.0`。

### 新增

- **内存取证** `ctfbox/competition/memory.py`：Volatility 3 自动探测（`vol.exe`/`vol.py`/Python 模块三种形态），Windows 插件 pslist/pstree/cmdline/netscan/hives/printkey/hashdump/cachedump/lsadump/malfind/dumpfiles，Linux 插件 pslist/bash/sockstat/lsmod；明文 strings 兜底、可疑进程/外联/凭据分析、flag 扫描；未安装 Volatility 时明确给出安装方式与体积，不伪装成功。
- **流量深度分析** `ctfbox/competition/traffic.py`：协议统计、TCP 乱序重组、HTTP 请求/响应配对与对象还原（gzip/chunked 解码）、表单/Basic/Cookie 凭据线索、DNS 隧道评分与 Base32/Base64/Hex 解码、TXT 重组、文件雕刻。
- **移动端** `ctfbox/competition/mobile.py`：内置二进制 AXML 清单解析（包名/版本/权限/导出组件）、DEX 字符串表、META-INF 证书解析（含 debug 证书告警）、硬编码 URL/IP/JWT/云 Key/私钥扫描；随包 jadx 可用时自动反编译 Java/Kotlin 并复扫。
- **代码审计** `ctfbox/competition/codeaudit.py`：PHP/Java/Python 危险函数、可控输入汇聚点、反序列化入口、SQL 拼接、命令执行、文件包含/读写、模板注入；同文件简单污点传播，证据落到 `文件:行号` 与上下文。
- **安全基线** `ctfbox/competition/baseline.py`：Windows 只读采集（账户/口令策略/共享/服务/防护/防火墙/补丁等 15 项）与 Linux rootfs 离线检查（UID0/空口令/弱哈希/SSH/sudo/服务/防火墙/SELinux 等）；生成 `harden_*.ps1`/`harden_*.sh` 与对应回滚脚本，并用 PowerShell 解析器/`bash -n` 做语法校验，**绝不执行**。
- **日志时间线** `ctfbox/competition/logtime.py`：Windows EVTX（python-evtx）与 PowerShell 在线收集、Linux auth.log/syslog/secure 解析；登录失败暴破、失败后成功、root 直登、可疑 sudo、账户/口令变更、防火墙拦截；输出 `timeline.csv`（UTF-8-SIG）与事件 JSON。
- **攻防验证** `ctfbox/competition/defense.py`：WAF 24 项、NGFW 16 项检查清单；14 条无害 HTTP 检测用例（canary、不存在的路径、回环关闭端口）与 5 条 NGFW 人工用例；加固前后报告模板；`compare` 按检查项 id 对比两次基线，输出改善/退化/持平。
- **CLI**：`--comp memory|traffic|mobile|codeaudit|baseline|logtime|defense|compare`，统一要求 `--ctf-only`。
- **GUI**：「赛事专项」标签页（懒加载），文件/目录选择、平台/反编译/清单选项、任务日志与输出目录直达。
- **一键分析接线**：源码文件自动触发代码审计；`.apk` 自动触发移动端深度分析；`.evtx` 自动触发日志时间线；pcap 深度分析沿用 v3.3 接线。

### 安全边界

- 所有 v3.4 模块**不发起网络请求**；流量/日志/镜像只读本地文件。
- 加固脚本、回滚脚本、WAF/NGFW 用例和 `.http` 模板只写入任务 `artifacts/`，需人工在授权环境执行/发送。
- 不提供免杀、持久化、绕过杀软、公网批量扫描或目标发现。
- APK 只解包/反编译，不安装、不运行；加固脚本生成后只做语法校验。

### 验证

- `D:\PY\python.exe -m unittest tests.test_competition_v34 -v` → **Ran 18 tests, OK**。
- 全量回归（v3.4 + v3.3 + v3.2 + Pwn）→ **Ran 50 tests, OK**。
- CLI 端到端：`--comp` 的 logtime/mobile/codeaudit/baseline/compare/defense 六个子命令均返回 0 并落盘 `report.md`/`result.json`；traffic 与 memory 由单测覆盖；`TestIntegration` 覆盖 `main.py --comp` 路由。
- 旧 Web 深度回归 `tests/test_webattack.py`：**26 PASS / 0 FAIL**（会话级声明只授权 127.0.0.1 自建靶站，scope 校验保留）。
- 真实样本：`Test-debug.apk`（包名 `org.t0t0.androguard.test`、导出 `.TestActivity`、Android Debug 证书）内置解析通过；随包 jadx 反编译 1.7 秒生成 4 个 Java 文件；本机 Windows 基线 15 项（6 pass / 5 info / 2 warn / 2 unverified），并生成 4 个加固/回滚脚本；Windows 在线日志收集 81 条事件（2026-10-31 ~ 2026-11-07）。
- 流量：scapy 自建 pcap 覆盖乱序 TCP 重组、gzip/chunked HTTP 对象、DNS 隧道与文件雕刻；代码审计用自建 PHP/Java/Python 漏洞源码验证 `文件:行号` 与污点链。
- GUI：同版本源码实例化并渲染「赛事专项」页通过（工具状态与任务卡片正常）；成品 exe 启动，确认页徽标 `v3.4.0`，主窗口标签栏含「赛事专项」。
- 打包：`build.bat` 构建成功（`ctfbox submodules: 97`）；PE `3.4.0.0`，**24,808,121 字节**，SHA-256 `1e94133b99e884614e2d6ee802dfc806335428a7498c7489c19bf6e20dae3def`；交付目录 `魔盒-ctf/CTFToolbox.exe` 与 `魔盒-ctf/魔盒-ctf.exe` 哈希一致；成品 `--comp defense --profile waf` 冒烟返回 0 并落盘 `report.md`/`result.json`。自动化点击受当前桌面输入限制，截图与边界见 `docs/v3.4.0-交付与验证.md`。

### 已知限制

- 本机没有真实内存镜像，Volatility 插件解析用可控 JSONL 输出做单测；明文扫描用自建数据验证。真实镜像取证仍需在比赛环境复验。
- 标准用户无法读取系统 EVTX（复制 `C:\Windows\System32\winevt\Logs` 返回 Access denied），因此 EVTX 二进制解析只验证了 XML 解析层与 magic 识别；在线收集走 PowerShell，Security 通道需管理员。
- 加固脚本与 WAF 用例按设计不执行、不发送，**没有**真实设备拦截率数据；需在授权 staging 人工验证。
- 代码审计为启发式行匹配 + 同文件简单污点，存在误报/漏报。
- APK 的 apktool 未随包；缺失时仅内置 AXML/DEX/资源解析，jadx 可用时补源码级复扫。

## v3.3.0 — 2026-11-07

### 更新公告

Web 能力从「只读探测」升级为「**声明闸门下的全量利用链**」：PHP/Java/Python 反序列化、文件上传、SQLi/命令注入/SSTI/SSRF/XXE/LFI、XSS/CSRF/Cookie、JWT/IDOR/弱口令，并由 AutoPilot 编排多步链；所有利用请求统一经过声明、scope、审计与限速。7z 接入 **RAR5** 并递归分析。PE 版本号 `3.3.0.0`。

### 新增

- **声明闸门** `ctfbox/autopilot/consent.py`：声明版本 2；GUI 首次启用利用模块弹出《Web 利用授权声明》，逐条阅读 + 勾选后持久化到 `workspace/config/consent.json`；CLI 支持 `--i-own-this-target`（仅本次）与 `--consent web-exploit`（持久化）。未声明时 `--exploit`/`--webattack` 在发请求前拒绝。
- **审计** `ctfbox/autopilot/audit.py`：任务级 `audit.jsonl` + 全局 `workspace/audit/audit-YYYYMMDD.jsonl`；记录目标、工具、payload SHA-256/前 200 字符预览、响应状态、时间与来源。
- **利用客户端** `exploit/client.py`：每个请求重新检查声明；`ScopeGuard` 每请求校验；限速与请求预算；Cookie/重定向/超时统一处理。
- **利用引擎** `exploit/engine.py`：入口/表单/参数/JWT/序列化线索发现、soft-404、上传矩阵、SQLi（报错/布尔/时间/UNION）、命令注入、SSTI/LFI（含日志/Session/`file://` 包装器）、SSRF/XXE、XSS/CSRF/Cookie、JWT none/HS256、IDOR、弱口令；`plan()` 多阶段 + `finish()` 落盘。
- **Payload 生成** `exploit/payloads.py`：PHP POP/序列化、phar 规范（尾部 SHA1 + 4 字节类型，无长度字段）与自校验、Java URLDNS/ysoserial、JWT none/HS256 弱密钥、XXE/LFI/SSRF/XSS/CSRF 模板。
- **AutoPilot 接线**：`--auto <URL> --exploit`；逐 phase 计步，默认 120 请求/0.55s 间隔、外层 14 步/240 秒；报告新增「Web 利用结果」「利用审计」，结果写 `artifacts/exploit_result.json`。
- **GUI 接线**：`ui_autopilot` 新增「启用 Web 利用模块」复选框与声明弹窗；`ui_web` 选择深度全自动时先弹声明；取消则不运行。`webattack.campaign()` 入口也强制声明。
- **RAR5/7z 归档** `tools/archive.py`：自动探测 `7z.exe`，`7z l -slt` 解析 RAR5/RAR4/7z/ZIP/TAR，拒绝路径穿越，加密包小字典，成员 strings/flag 扫描，嵌套包递归；ZIP/TAR 标准库回退。
- **测试与样本**：`tests/v33_target.py` 自建本地靶站（127.0.0.1 随机端口），覆盖 SQLi/命令注入/SSTI/LFI/上传/弱口令/CSRF/XSS/JWT/IDOR/SSRF/XXE/PHP+Pickle 反序列化/弱 Cookie；`tests/test_autopilot_v33.py` 9 项；真实 RAR5 样本 `tests/fixtures/testfile.rar5.rar`。

### 修复

- PHP 序列化类名长度按实际字符数生成（`MoheProbe` 为 `O:9`），避免测试/利用载荷长度错误。
- JWT 候选顺序改为 HS256 弱密钥优先、`none` 变体其次，避免被 `candidates[:8]` 截断掉可用 HS256。
- SQLi 命中后立即停止后续目标；IDOR/SSRF 低置信线索继续检查其它入口，不提前 return。
- SSRF 同一入口命中 `http://` 后继续探测 `file://`，使 SSRF 与 `lfi-wrapper` 都能被记录。
- phar 生成器修正为规范结构：尾部仅 `SHA1 signature + 4 字节 type`，无长度字段；`phar_self_check` 同时校验结构与签名。
- `exploit_result.json` 的审计摘要改为任务级 `entries/task_path/global_pattern`，与 GUI/CLI/报告读取口径一致。
- 保留旧 `webattack.py` 作为 legacy 深度引擎，但 `campaign()` 内部强制声明，任何调用方未声明都会被拒绝。

### 验证

- `D:\PY\python.exe -m unittest tests.test_autopilot_v33 -v` → **Ran 9 tests, OK**。
- `D:\PY\python.exe -m unittest tests.test_autopilot_v3 -v` → **Ran 22 tests, OK**（无回归）。
- 自建本地靶站完整链实测命中：`sqli-error`、`cmdi`、`ssti`、`lfi`、`upload-exec`、`weak-login`、`csrf-poc`、`xss-reflected`、`jwt-weak-key`、`jwt-hs256`、`idor`、`ssrf`、`lfi-wrapper`、`xxe`、`deser-php`、`cookie-weak`；请求数超过 20，任务 `audit.jsonl` 与 `artifacts/exploit_result.json` 均落盘，并取到 `flag{...}`。
- 无声明时 `--exploit` 退出码 1 并打印拒绝原因；加 `--i-own-this-target` 后闸门放行（目标不可达时按正常失败处理，不再报声明错误）。
- 真实 RAR5 样本解包成功（`testfile.txt`），嵌套 ZIP 递归扫描命中 `flag{archive_nested_ok}`。
- 本轮为**自建仿真靶站**集成验证，未使用外部真实靶场；Java 命令执行型 gadget 与 phar 本地触发因缺少 `ysoserial`/PHP 运行时未做端到端验证，报告已如实标注。

### 已知限制

- 未内置 `ysoserial`，Java 仅原生生成 URLDNS 探测流；未安装 PHP 时 phar 只做结构与签名校验。
- 上传/反序列化回显依赖目标实际解析环境；自建靶站仅模拟固定标记，不代表真实漏洞环境。
- 利用链仍为单目标、限速、有限预算；不做目标发现、批量扫描、持久化、免杀或绕过杀软。

## v3.2.0 — 2026-11-07

### 更新公告

本轮做真实使用验收：以普通用户身份用魔盒自身功能在 PolarCTF（Vue SPA + hash 路由，需登录）实战做题，把暴露的缺陷当场修掉。核心变化：**SPA 空壳自动浏览器渲染**、**登录门槛识别与登录态复用（`--user-data` / `--cdp`）**、**白名单支持显式子域通配**、**新增 RSA 攻击模块**（共模/残缺密文修复/小指数/Fermat），并修掉 `flag:before` 误报、`urlencode` 未导入崩溃、`next_steps` 被覆盖为 `None` 等问题。PE 版本号 `3.2.0.0`。

### 新增

- **RSA 攻击** `ctfbox/autopilot/tools/rsa.py`：从文本解析 `n/e/e1/e2/c/c1/c2/p/q/d`（支持 `key = 0x..` 与十进制），实现
  共模攻击（贝祖系数 + 负指数模逆）、残缺密文补位（高 16 位被置零时按 `2^(bits-16)` 枚举）、小公钥指数整数开方、
  已知 p/q/d 解密、Fermat 分解；命中 flag 置信度 0.95，无结果只报结构化参数与攻击次数。
- **SPA 自适应渲染** `webprobe._is_spa` / `render_snapshot`：首屏仅 `#app`/`#root` 空壳时自动 Playwright 渲染
  （兼容 `<div id=app>` 无引号写法），抓取 XHR/fetch 响应，输出 `fingerprint.api_endpoints`、`network_count`、
  渲染后 DOM 链接与截图；SPA/需登录时**跳过目录与参数探测**，避免对平台本体做无意义请求。
- **登录态复用**：`--user-data <目录>`（Playwright 持久化用户目录）与 `--cdp <地址>`（附加已开远程调试浏览器）；
  渲染后把同域 Cookie 注入 requests 会话，供后续探测复用；GUI「一键梭哈」新增「登录目录」「CDP」输入框。
- **登录门槛识别** `_login_required`：最终地址跳 `/login`、DOM 出现密码框、XHR 302/401 到登录页均判定为需登录，
  下一步直接给出「软件不代登录、不试密码」的使用指引。

### 修复

- **D2 SPA 空壳无解析**：修前 v3.1.0 成品对 SPA 只做静态 HTML 正则，标题空、23 次请求全打在 18 个目录路径上、结论「未发现明显入口」；修后自动渲染、请求 2/40、跳过目录探测（本地 SPA 复现靶实测）。
- **D3 登录门槛不识别**：修前只报「login 返回 200」并建议「试认证绕过」；修后输出 `login_required=true` 与 API 清单。
- **D4 子域名白名单**：`--allow-host '*.example.com'` 显式通配（含裸域），`evil-example.com`、`example.com.evil.net` 仍被拦截（已实测）。
- **D5 工具缺失（RSA）**：修前 `--auto 1.txt` 9 步 0 命中；修后 `[9] crypto.rsa: RSA 参数 5 个，攻击 1 次，命中 flag 1 个`。
- **D6 flag 误报**：`FLAG_KV` 会把 CSS `flag:before` 判成强 flag；改为要求值带花括号或 ≥8 个 token 字符。
- **D7 webprobe 崩溃**：参数探测分支缺 `urlencode` 导入，抛异常导致整轮结果为 `ok=False`。
- **D8 next_steps 被覆盖**：`extra["next_steps"]=None` 在 `**extra` 展开时覆盖了已生成的步骤；改为先 `pop` 再合并。
- **D9 冻结版 Playwright 浏览器路径错**：打包后 `sys.frozen` 使 Playwright 强制 `PLAYWRIGHT_BROWSERS_PATH=0`，只找 `playwright/driver/package/.local-browsers`（随包不含浏览器），SPA 渲染降级为 Chrome headless、拿不到 XHR，登录门槛误判为「不需要」。修前日志：`[web] 渲染降级原因: Executable doesn't exist at ...\driver\package\.local-browsers\chromium_headless_shell-1243\...`、`api=[] login=False`；修后（`common.ensure_playwright_browsers()` 指向随包或 `%LOCALAPPDATA%\ms-playwright`）：`渲染: api=['/api/v1/challenges'] login=True`、引擎 `playwright`。同时对降级场景强制输出原因与「登录门槛判定不完整」提示，不再静默误判。

### 验证

- 单测：`python -m unittest tests.test_autopilot_v3` → **Ran 22 tests OK**（新增 RSA 共模、通配白名单、CSS 伪类误报 3 项）。
- 真实解题：PolarCTF 1850「广播攻击」，附件 `1.txt`（n/e1/e2/c1/c2）→ 软件输出 `FLAG 0.95 flag{5up3r_53cr3t_k3y_2026} | 共模攻击 e1*a+e2*b=1`；平台提交返回 `{"status":"correct"}`。
- 真实实例：PolarCTF 1830「php反序列」创建容器 `http://<uuid>.www.polarctf.com:8090/`，软件识别 `PHP/Apache` 登录页、发现 `server-status` 403、无 flag 误报；未解出（缺 PHP 反序列化利用链，已记能力缺口）。
- 真实站点（仅一次页面加载）：`SPA=是 | 登录=需要 | api=['/api/v1/challenges','/api/v1/users/me','/api/v1/notifications']`。
- 成品 exe（3.2.0.0）闭环：文件模式 `1.txt` → `success=true`、`flags=[flag{5up3r_53cr3t_k3y_2026}]`；Web 模式本地 SPA 靶 → `SPA=是 | 登录=需要 | api=['/api/v1/challenges'] | 请求 2/40`；真实站点带 `--user-data` → 标题 `PolarD&N`、复用 Cookie 2 条、`请求 2/40`；GUI 启动存活验证通过。分发目录 `魔盒-ctf\魔盒-ctf.exe` 已同步为 3.2.0.0 并跑通同一文件闭环。

### 已知限制

- 仍无「平台适配层」：登录、开实例、提交 flag 需人工完成，软件只做识别与提示（本轮已记为能力缺口）。
- Web 只做只读指纹/入口探测与参数可疑标记，不具备漏洞利用与 payload 生成能力（PHP 反序列化、SSTI 利用等）。
- 未接入 RAR/7z 解包与流量/镜像取证；未知二进制仍不执行，本机无 Docker/WSL/Windows Sandbox。

## v3.1.0 — 2026-11-07

### 更新公告

一键梭哈补上两块硬能力：**PE/ELF 走 Ghidra headless 真反编译**，伪代码落盘并作为 binary 主证据（r2 降为回退）；**对称密码密钥候选自动试解**（RC4 / AES-ECB/CBC / DES / 3DES），密钥从 strings、hex 常量、硬编码串、文件名、弱口令字典与 XOR 反推结果交叉生成，命中 flag 直接写入证据链。exe 重打包为 `3.1.0.0`，不再以旧版本冒充新版本。

### 新增

- **Ghidra headless 接入** `ctfbox/autopilot/tools/ghidra.py`：
  - 自动定位 `tools/portable/ghidra/support/analyzeHeadless.bat` 与 `tools/runtime` 下 JDK21，设置 `JAVA_HOME`/`PATH`；
  - 内嵌 Java 脚本 `DecompileAllToC`：`DecompInterface` 逐函数反编译，导出 C 伪代码，函数数可配（默认 300）、`-analysisTimeoutPerFile` 可配；
  - 中文路径规避：样本与脚本复制到纯 ASCII 临时目录再导入，结束后把 `decompiled.c` 复制回任务 `artifacts/`；
  - 伪代码做强 flag 正则扫描，命中即生成置信度 0.95 候选；
  - 缺 Ghidra/Java 时返回 `ok=False` 与安装说明（Ghidra 12.x 约 400MB + JRE21 约 190MB），报告标注「未接入」，不伪造能力。
- **对称密码密钥候选试解** `ctfbox/autopilot/tools/crypto.py`：
  - 密钥候选：文件名/分词、8~64 位 hex 常量（字节 + ASCII 双解）、strings 按非字母数字切分（覆盖 `key=MySecretKey12345`）、常见弱口令字典、XOR 工具反推密钥；去重后上限 240；
  - 密文候选：hex、base64（严格校验）、高熵或低可打印原始数据、提示行后的正文（`raw-after-header`）；上限 8，试解样本 16KB；
  - 算法：RC4（1~32 字节密钥）、AES-ECB/CBC（零 IV 与密文首块作 IV）、DES-ECB/CBC、3DES-ECB/CBC；PKCS#7 去填充；
  - 判据：`0.60*可打印率 + 0.25*字母率 + 0.15*熵下降`，叠加弱 flag 结构与强 flag 正则；命中后用完整密文复核，候选置信度 0.93。
- **编排接入** `orchestrator.py`：PE/ELF 分支改为 Ghidra 主证据（预算内限时）→ 失败回退 r2；XOR 之后执行对称密码试解，XOR 反推密钥作为 hint 传入；`extra` 增加 `ghidra_output`、`crypto_attempts`，报告新增「反编译伪代码」段落。
- **测试**：`tests/test_autopilot_v3.py` 新增 5 项（AES-ECB / AES-CBC / DES-ECB / 3DES-ECB / RC4 文件名密钥），合计 17 项。

### 变更

- 版本号统一 `v3.1.0` / `3.1.0.0`（`__init__.py`、`workspace.py`、`orchestrator.py`、`sandbox.py`、`cli.py`、`main.py`、`ui_theme.py`、`ui_consent.py`、`ui_autopilot.py`、`version_info.txt`、`README.md`、`使用说明.md`）。
- `binary.py` 的 Ghidra 提示改为区分「可用/不可用」，并说明反编译由编排层落盘。

### 验证

- `python -m unittest tests.test_autopilot_v3` → **Ran 17 tests OK**；
- Ghidra：`C:\Windows\System32\where.exe` → `Ghidra 反编译 104 个函数，伪代码 155957 字符`，耗时约 24~32 秒；
- 端到端（`aes_ecb.bin`）：日志 `[6] crypto.symmetric: 2 个密文 × 51 个密钥，共 156 次试解，命中 flag 1 次`，命中 `flag{crypto_auto_solve}`（AES-ECB，密钥 `MySecretKey12345`，可打印率 1.00）。

### 已知限制

- Ghidra 依赖随包 JDK，首次分析有 20~60 秒开销；超大二进制按 `deep`/预算削减函数上限。
- 试解不做密钥派生（PBKDF/哈希派生）与流式分组模式（CFB/OFB/CTR），仅覆盖题目常见直接密钥场景。
- 本机仍无 Docker/WSL/Windows Sandbox，未知二进制只做静态分析。

## v3.0.0 — 2026-11-07

### 更新公告

新增「一键梭哈」双模式自动解题闭环：文件 → 类型识别 → strings/熵 → 单字节与重复密钥异或 → 编码套娃解码 → 哈希/PE/ELF/r2 静态分析 → 候选 flag（带置信度与依据）；URL → 指纹 → 只读入口探测 → 可疑点与下一步。每题独立工作区，证据链全程落盘。版本号同步到 `v3.0.0`。

### 新增

- **编排层** `ctfbox/autopilot/orchestrator.py`：
  - 题型分类 → 工具选择 → 执行 → 观察 → 下一轮；
  - 预算 `max_steps=14`、`timeout=240s`，单工具异常降级不中断；
  - 候选 flag 按置信度排序，≥0.80 判定为命中；
  - 自动生成 `report.md`（结论 / 候选表 / 下一步 / 限制 / Web 可疑点 / 证据链路径）。
- **工具层** `ctfbox/autopilot/tools/`：
  - `recon.py`：文件识别、哈希、strings + flag 扫描、分块熵、文本统计、工具状态；
  - `xor.py`：单字节 XOR 全密钥扫描、重复密钥 XOR（列频率法）、crib 已知明文反推（偏移 0）；
  - `codes.py`：Base64/Base32/Base16/Hex/URL/ROT 递归解码链（默认 3 层）；
  - `hash.py`：哈希识别 + 弱字典爆破；
  - `binary.py`：PE（段熵/导入导出/overlay/加壳提示）、ELF（结构/符号/RELRO）、r2 反汇编摘录、Ghidra 可用性探测；
  - `pwnstatic.py`：复用 `pwnrun` 静态分析；
  - `z3tool.py`：线性约束求解入口，未安装时明确失败；
  - `webprobe.py`：指纹、软 404 基线、只读路径探测、SQLi/LFI/SSTI/XSS 反射标记、浏览器渲染（Playwright 优先，缺失降级 Chrome headless）。
- **边界层**：
  - `scope.py`：显式授权 + 仅 http/https + 拒绝 URL 内凭据 + 回环默认允许 + 私网需 `--allow-private` + 域名白名单；
  - `sandbox.py`：探测 Docker / WSL / Windows Sandbox，无后端时未知二进制只做静态分析；
  - `workspace.py`：每题一目录（`input/ artifacts/ logs/ evidence.jsonl result.json report.md`）。
- **入口**：
  - CLI `main.py --auto <文件|URL> --ctf-only [--allow-private] [--allow-host H] [--deep] [--render] [--json]`；
  - GUI 新增「一键梭哈」页 `ctfbox/ui_autopilot.py`，支持选文件/填 URL、授权勾选、白名单、后台线程、结论/日志双区。
- **文档**：`docs/v3.0.0-架构.md`（现状能力、Polar 分布、三层架构、工具可用性矩阵、验证、差距清单）。
- **测试**：`tests/test_autopilot_v3.py`，12 项（XOR 三类、编码链、工作区去重、scope 四条、文件闭环两条）。

### 变更

- `APP_VERSION` → `v3.0.0`（`ctfbox/ui_theme.py`）；
- `version_info.txt` 全部改为 3.0.0.0；
- 授权确认文案新增「一键梭哈」条目；
- `README.md`、`使用说明.md` 标题与功能概览同步 v3.0.0。

### 修复

- `workspace.add_candidates` 缺 `typing.List` 导致的 NameError；
- `codes.decode_chain` 误传路径字符串（改为先读字节再解码）；
- `hash.crack_hash` 返回值解包错误（实际为 `(plain, algo)` 或 `None`）；
- XOR 假阳性：增加 flag 结构校验、逐列可打印率、crib 完整密钥周期、仅偏移 0 假设、原始已命中时跳过 XOR；
- `sandbox` 探测 WSL 时子进程解码线程崩溃（加 `errors="replace"`）。

### 验证

- `python -m unittest tests.test_autopilot_v3` → **Ran 12 tests OK**（随包 3.11.16 与 D:\PY 3.13.14 均通过）；
- 文件闭环：`plain.txt` / `b64.txt` / `xor_single.bin` / `xor_repeat.bin` 全部命中正确 flag；
- PE 闭环：`7z.exe` 走完 PE + r2 静态路径，未执行；
- Web 闭环：本地靶站命中首页 flag 与 `.git/HEAD`，浏览器渲染成功；
- `z3tool.available()` 在 D:\PY 下为 `True`，随包 runtime 下为 `False`（报告如实标注）。

### 已知限制

- 随包 runtime 无 z3 / pwntools / playwright，成品内相关能力缺失并标注安装命令；
- 无 Docker / WSL 发行版 / Windows Sandbox → 未知二进制只做静态分析；
- 反编译仅 r2 摘录，Ghidra headless 未接入伪代码导出；angr 未安装；
- 自定义 VM、RC4/AES/DES 自动识别解密未实现；
- Pwn 仅静态，Windows 宿主不能运行 ELF；
- `魔盒-ctf.exe` 仍为 v2.5.0.0，需 `build.bat` 重建才能包含 v3 新 UI/CLI。

## v2.5 — 2026-11-07

- RAC 自动化五合一（题目流水线 / 侦察 / 远程执行 / Oracle RAC 巡检 / RPA 会话）；
- Web 深度全自动：六类漏洞矩阵、文件上传 8 种形态、UNION 只读取数、目录爬取、备份探测、sqlmap 复核；
- 布尔盲注二分取数、XSS 浏览器确证、命令注入过滤绕过；
- 真实靶场 15 题判对。

## v2.4 — 2026-11-06

- 新增 RAC 自动化页与 `ctfbox/rac/` 引擎包；
- 一键 Web 取证（`--webauto`）、文本内嵌编码二次解码（`textscan.py`）；
- 内置 nmap / john / uncompyle6 / decompyle3。
