# CHANGELOG

## v4.0.0 — 2026-11-08

### 重构

- **七模块一键梭哈**：杂项 / 密码学 / 逆向 / Web / Pwn / 电子取证 / AI 投毒，页内可选题型提示（留空自动判型）。
- **顶部全局 AI 开关**：默认关闭，用户主动开启才加载本地小模型；无 NVIDIA 自动走 CPU；状态写入 `ai_config.json`。
- **砍掉「赛事专项」页签**：内存/流量/APK/代码审计等能力保留在代码层，按需由自动流程触发。
- **合并页签**：原「编码/密码」+「密文加解密」合并为「密码学」；原「实用小工具」+「专项工具」合并为「杂项工具」。
- **主界面净化**：警告/说明/免责统一收敛到「使用说明」页，主界面只留工具名与必要输入。

### 新增

- **AI 模型投毒/后门静态检测** `ctfbox/ai_poison.py`：对 `.pkl/.pt/.pth/.ckpt/.safetensors/.onnx/.h5/.pb` 做 pickle GLOBAL op 危险 token 扫描、safetensors JSON 头检查、PyTorch zip 内 pickle 递归扫描；绝不加载/执行模型。GUI 新增「AI 投毒分析」页。
- **WP 自动落盘到软件根目录**：一键梭哈命中 flag 后，在 `魔盒-ctf.exe` 同级目录自动生成 `WP_<题型>_<时间>.md`，完整专业模板（题目信息/信息收集/解题过程/Flag/修复建议/证据附录）。
- **离线网页新增**：JWT 解码器、进制/Base64 转换器，均为本地 HTML，断网可用。

### AI 裁判修复（对照 v3.7.0 实测缺陷）

- `already_tried` 并入确定性流程已完成步骤（读 `evidence.jsonl`），杜绝重复执行 codes.chain / binary.parse / deep.text。
- 新增 `caesar_brute` 动作：凯撒 0-25 位移 + 仿射 a=3/5/7/11/15 自动枚举。
- Web 链路真正接入（去掉 `if kind != "file": return` 短路），新增 `web_deep` 动作做敏感路径探测。
- 新增 `c_audit` 动作：C/C++ 源码危险函数与硬编码 flag 审计。
- prompt 硬约束「已完成动作/禁用动作」，URL 带 `user:pass@` 自动脱敏。

## v3.7.0 — 2026-11-08

### 更新公告

取消工具内的逐功能/逐目标边界，改为**唯一一道《软件责任说明》闸门**：GUI 每次启动必须勾选同意才能进入，拒绝或关闭窗口直接退出；CLI 首次使用加 `--accept-responsibility`，确认持久化后直接运行。责任说明写明授权与合法使用、能力与风险、数据与隐私、无担保与责任限制。逐工具声明、域名白名单、私网限制与 `--ctf-only` 强制参数全部移除；所有功能与随包工具进入后直接可用。PE 版本号 `3.7.0.0`。

### 新增

- **唯一责任闸门** `ctfbox/responsibility.py`：版本化说明文本 + SHA-256，确认记录写入 `workspace/config/responsibility.json`；版本变化后旧确认自动失效；`ensure_cli()` 在 CLI 入口统一拦截。
- **启动责任说明窗** `ctfbox/ui_consent.py`：780×620 深色说明窗，必须勾选「我已逐条阅读并同意」才能启用「同意并进入」；拒绝/关闭窗口退出；内置「阅读使用说明」。
- **测试** `tests/test_responsibility_v37.py`：CLI 未同意拦截、`--accept-responsibility` 放行与落盘、版本失效、撤销、条款关键字。
- **本地模型裁判** `ctfbox/ai/`：内置 `Qwen2.5-3B-Instruct-abliterated` Q4_K_M（1.93 GB，魔搭 `huihui-ai`，apache-2.0）与 llama.cpp 运行时（CUDA 13.5 / CPU）。AutoPilot 收尾后按工作区状态在固定动作白名单内选择下一步与深度，GBNF 强制 JSON、白名单二次校验、按目标类型限制可选动作（zip 只解压、图片才隐写、PE/ELF 才反编译），重复/越界/不匹配决策跳过，最多 3 次；模型不可用时静默回退。GUI 新增「本地模型裁判」勾选，CLI 新增 `--ai`，配置见 `ai_config.json` 与 `MOHE_AI_*` 环境变量。
- **测试** `tests/test_ai_conductor_v37.py`：语法枚举、合法 JSON、未知动作与非 JSON 拒绝、depth 钳制、stop、状态入提示词、目标收集、默认关闭。

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

- 全量单测 **110 tests OK**（含新增责任闸门测试、责任说明窗布局回归、兽音变体解码回归、AI 裁判 11 项与更新后的 scope/consent 回归）。
- 修复兽音变体解码：改用真实兽音算法（码点→hex→位置偏移→四进制符号），CJK 符号集不再被 `isalnum` 误过滤，并按 ASCII 优先评分避免随机 CJK 抢占。
- CLI 实测：未同意时 `--comp` 退出 2 并打印责任说明；加 `--accept-responsibility` 后退出 0，`workspace/config/responsibility.json` 写入确认记录。
- 无逐工具声明时 AutoPilot 直接进入 Web 利用链（本机靶站 48 次请求、5 项发现、5 个验证样本），审计与限速正常。
- 构建：PyInstaller onedir 成功，成品 PE 版本 3.7.0.0（约 24.9 MB）；责任说明页与主界面截图见 `docs/交付与验证.md`。

### 安全边界

- 授权判断统一前移到进入软件前的责任说明；软件不判断目标归属。
- 保留工程约束：Web 只接受 http/https、拒绝 URL 内凭据；每次利用请求写审计；限速与请求预算不变；未知二进制默认只做静态分析；不做公网批量扫描。
