# 魔盒-CTF v4.1.0 已知不足与边界

更新时间：2026-11-09
对应版本：`魔盒-CTF` v4.1.0（PE 4.1.0.0，版本号由 `ctfbox.__version__` 统一派生）
验证基线：全量单测 **132 项通过**（新增 `tests/test_architecture_v41.py` 22 项）；Web 全链路 15 个场景（A–O）ALL PASS；CLI 责任闸门、平台列表、打包产物冒烟实测通过。

截至本版本，没有已知的阻塞性缺陷。以下为已确认的能力边界、待改进项与测试未覆盖范围，用于说明软件能做到什么、做不到什么，避免把自动化结果当成确定结论。

---

## 一、能力边界

### 1.1 Web 自动化

| 项目 | 当前能力 | 边界 |
|---|---|---|
| SQL 注入 | 报错注入、布尔盲注（`ascii(substr())` 二分取数）、联合/整数/字符型探测 | **时间盲注只判断是否成立，不自动逐字符取数**；二次注入、ORDER BY / UPDATE / INSERT / Cookie / UA / Referer 注入未逐类覆盖 |
| 命令注入 | 分隔符与常见过滤绕过，`cat/base64/tac/sort/nl/grep` 读取器，目录内 `flag_*.php` 回读 | 空格、目录分隔符、运算符的综合过滤未穷举 |
| XSS | 反射检测 + Playwright 浏览器确证（捕获 dialog 记 `xss-exec`） | 存储型 / DOM 型未自动构造完整触发链；无 Playwright 时只做静态判断 |
| 上传 | 真实落盘路径解析、源码回显与执行结果区分、包含执行、PHP5 载荷 | 依赖响应中可解析路径或可发现的包含参数；强 WAF/重命名 + 无回显场景需人工 |
| 反序列化 | PHP / Java / Python 常见链与 payload 生成 | 依赖题面或源码证据；无证据时判型会跳过该阶段 |
| 逻辑漏洞 | JWT、IDOR、CSRF PoC、Cookie 属性、弱口令试登 | 业务型多步逻辑（支付、越权审批等）未建模 |
| 扫描范围 | 单目标、同源、限速、请求预算、逐请求审计 | 不做公网批量扫描、目标发现、爬虫扩散；不做免杀与持久化 |

### 1.2 Pwn / 逆向

- **Pwn**：只自动覆盖 **ret2win**；ret2libc、格式化字符串、堆题提供模板与思路，偏移与 ROP 链仍需人工确认。Windows 不能执行 ELF，动态验证需 Linux / WSL / 远程靶机。
- **逆向**：以静态分析、Ghidra headless 反编译、r2 摘录、pyc/UPX 处理为主；z3 / angr 未内置全自动约束求解，安装后仅提供简单线性约束接口。
- **未知二进制**：无 Docker / WSL / Windows Sandbox 后端时只做静态分析，不执行样本代码。

### 1.3 密码学与隐写

- 异常椭圆曲线 + 多维 HNP 针对“大量坐标点且未给出 p/a/b”的题型，依赖三点行列式 GCD 与格约减，其他曲线形态不保证适用。
- 加密 ZIP 口令恢复以候选生成（题名/文件名/日期/键盘走位/弱口令）为主；失败后 `--deep` 才回退随包 john，强口令不保证破解。
- 密码型图片隐写（cloacked-pixel）按 AES-CBC + RGB LSB 特征识别；其他工具或自定义参数需人工。

### 1.4 赛事专项

- **内存取证**：依赖 Volatility 3 与可读内存镜像；本地缺少真实内存镜像样本，功能以合成/公开样本验证为主。
- **流量 / APK / 源码审计**：启发式规则存在误报与漏报，证据定位到文件:行号，但结论需人工复核。
- **安全基线**：只读检查 + **生成**加固/回滚脚本；脚本与 WAF/NGFW 检测用例只生成、不执行、不发送。
- **日志时间线**：EVTX 深度解析依赖 `python-evtx`；可读 EVTX 样本有限，复杂转发日志需人工。

### 1.5 平台与运行环境

- 平台适配仅覆盖 **CTFd / PolarCTF**；题目实例、提交接口变化或平台维护时，功能会如实报错而不保证自动恢复。
- 依赖有效登录态（`workspace/platform/*.json`），登录态过期需重新登录。
- GUI 仅支持 Windows；源码运行需要 Python 3.13 与完整依赖，便携工具链约 3.1 GB，不随仓库分发。
- SPA 渲染需 Playwright / Chrome；网页导航镜像需要联网。第三方工具（Volatility、jadx、ysoserial、Playwright 等）缺失时报告会明确标注，不伪造能力。

---

## 二、待改进项

| 优先级 | 项目 | 现状 / 影响 |
|---|---|---|
| 中 | 时间盲注取数 | 只判断成立，需 `sqlmap --technique=T` 或人工脚本 |
| 中 | 存储型 / DOM 型 XSS | 未自动触发与回读后台结果 |
| 中 | 二次注入与多位置注入 | Cookie/UA/Referer/ORDER BY 等未逐类覆盖 |
| 中 | Pwn 利用链 | ret2libc / 格式化串 / 堆题需人工确认偏移与链 |
| 中 | 符号执行 | 未集成 z3 / angr 全自动求解 |
| 低 | 判型误报 | Web 判型与源码审计为启发式评分，可能选错主考点 |
| 低 | 平台适配 | 仅 CTFd / PolarCTF，接口变动需适配 |
| 低 | 测试样本 | 缺少真实内存镜像与可读 EVTX 样本，取证仅有限实测 |

---

## 三、测试未覆盖范围

- 真实公网目标的稳定性与误报率（按边界不做公网批量扫描）。
- 时间盲注逐字符提取、存储型 / DOM 型 XSS 触发链、二次注入。
- ret2libc / 格式化字符串 / 堆利用的自动闭环。
- macOS / Linux 桌面环境（GUI 仅 Windows）。
- 极端大文件（数 GB 镜像、超大 PCAP）的性能与内存占用。
- 第三方工具全部缺失时的完整体验（仅验证了降级与如实标注）。

---

## 四、使用建议

1. 自动化输出只作为线索：判型、利用结果与 flag 候选都附带证据与置信度，提交前人工复核。
2. 先在本地靶站或授权环境验证利用链，再用于比赛目标。
3. 外部工具缺失时查看报告中“未接入 / 已跳过 / 依赖缺失”的标注，按提示补齐。
4. 遇到疑似缺陷，保留任务目录下的 `run.log`、`evidence.jsonl`、`result.json` 与 `audit.jsonl`，便于定位。

---

## 五、v4.1.0 已修复的隐藏缺陷

以下缺陷在 v4.0.0 及更早版本中长期存在，且不报错、只在特定条件下放大，属“静默劣化”，本版本逐项修复并补了回归用例。

| # | 缺陷 | 触发条件 | 实际影响 | 修复 |
|---|---|---|---|---|
| 1 | `dispatcher` 用 `abs(hash(path))` 生成产物目录 | 每次进程启动（`PYTHONHASHSEED` 随机化） | 同一文件每次生成不同 `out_*` 目录，工作区无限膨胀（曾累计 41 万文件） | 改 `hashlib.md5(abspath)[:6]` 稳定命名 + `common.new_run_dir()` 滚动保留最近 12 次 |
| 2 | RAC 脚本用 `subprocess.run(timeout=)` | CRC 爆破等长时间脚本超时 | 只杀直接子进程，孙进程成为孤儿继续吃 CPU，整批任务被拖死 | 统一走 `process_runner.run_command`（Windows Job Object / POSIX killpg），超时杀整棵进程树并保留已产生的输出 |
| 3 | RAC 脚本输出按系统默认编码解码 | 脚本打印中文（Windows 默认 GBK） | `UnicodeEncodeError` 崩栈，或输出变乱码导致 flag 匹配失败 | 子进程环境强制 `PYTHONIOENCODING=utf-8` + 文本模式 UTF-8 解码 |
| 4 | 平台接口直接 `resp.json()` | 登录态过期，服务端 302 回登录页 HTML | 抛 `JSONDecodeError` 崩栈，而非可读的“登录态失效” | 新增 `_json_body()`，非 JSON 统一抛 `PlatformError('…返回非 JSON…')`；`submit` 额外校验 cid 为整数 |
| 5 | 一键梭哈只用第一个附件 | 一题多附件（如 `task.zip` + `hint.png`） | 剩下附件完全不分析，直接判“未解出” | `platforms/cli.py` 依次尝试最多 3 个附件，命中 flag 即停 |
| 6 | 编排阶段顺序“贵的先跑” | 每次自动解题 | 120–180 s 的深度子进程排在毫秒级的确定性步骤之前，预算被吃光后便宜步骤根本没机会跑 | 重排为成本阶梯：识别 → triage → 指纹 → strings → 古典密码 → 归档链 → 图片隐写 → 编码/RSA/ECC/Hash → xor/对称 → 白名单脚本 → 深度模块 → 二进制/Pwn → 脚本产物跟进 |
| 7 | 强 flag 命中后仍跑重模块 | 第一层就拿到 `flag{…}` | 每题白烧 1–3 分钟，且重模块可能产出更弱的假候选干扰结论 | 新增 `_has_strong()`（置信度 ≥0.9）+ `_skip_phase()`，命中后跳过深度模块、二进制/Pwn、脚本库、古典密码、产物跟进 |
| 8 | AI 只有一个总开关 | 打开 AI 裁判 | 每题都拉起 llama-server（首调 +1~7 s），rerank 分支 0 增益 | 拆成 `conductor` / `rerank` 两个开关，默认都关；`rerank._available_cfg()` 改判 `rerank_enabled()` |
| 9 | 版本号三处硬编码 | 每次发版 | 源码 4.0.0 / `result.json` 3.7.0 / PE 属性 3.7.0.0 三方漂移 | 唯一来源 `ctfbox.__version__`，UI/报告/result.json 派生；PE 版本资源由 `ctfbox/versioning.py` 在打包时生成 |
| 10 | `scriptrun._expand_multitap` 硬编码 `from ctfbox.modules_codes import` | 包被重命名/冻结打包 | 函数体内 import 失败，multitap 解码静默失效 | 改相对导入 `from ...modules_codes import` |
| 11 | `wp._narrative` 用 `id(item)` 去重 | 对象被回收后 id 复用 | 两段不同内容被误判为重复，题解漏段 | 改用下标 `pos` |
| 12 | `main.py` 八个 CLI 分支各 11 行重复的编码/控制台初始化 | 维护 | 修改一处易漏改七处 | 提取 `_bootstrap_console()` / `_reconfig_utf8()`，约 90 行重复降为 8 行调用 |
| 13 | `classical.analyze` 把整段原文当候选 | 多行文本/文章型题目 | 12 条候选全是同一段原文的变体，占满候选表、掩盖真线索 | 跳过与原文一致的变换、线索压单行并截断 160 字、flag 形态优先占位、线索上限 5 条 |
| 14 | 正文内嵌编码片段漏解 | 「提示语 + 一串 base64」形态 | 整段 `auto_decode` 解不出即 0 命中，明明能解的 flag 被判未解出 | `codes.decode_chain` 增加 token 级解码（base64/base64url/base32/hex，可打印率 ≥92%），置信 0.93 |

