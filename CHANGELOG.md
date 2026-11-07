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
- 构建：PyInstaller onedir 成功，成品 PE 版本 3.7.0.0（约 24.9 MB）；责任说明页与主界面截图见 `docs/交付与验证.md`。

### 安全边界

- 授权判断统一前移到进入软件前的责任说明；软件不判断目标归属。
- 保留工程约束：Web 只接受 http/https、拒绝 URL 内凭据；每次利用请求写审计；限速与请求预算不变；未知二进制默认只做静态分析；不做公网批量扫描。
