# 测试说明

全量离线回归（不访问外部网络，Web 用例只拉起 `127.0.0.1` 本地靶站）：

```
python -m unittest discover -s tests -v
```

单独跑某个文件：

```
python -m unittest tests.test_architecture_v41 -v
```

## 文件对照

| 文件 | 覆盖范围 |
|---|---|
| `test_architecture_v41.py` | 版本号单一来源、命名规范（大写 CTF）、PE 资源、运行目录滚动清理、脚本库成本排序、编排阶段顺序、RAC 进程树终止与 UTF-8、平台非 JSON 容错、内嵌 base64 解码 |
| `test_ai_conductor_v37.py` | AI conductor：GBNF 约束、动作白名单、参数校验、默认关闭 |
| `test_autopilot_v3.py` | 一键梭哈编排层与工具层单元测试 |
| `test_autopilot_v33.py` | 责任闸门、scope、Web 利用链、RAR5 递归、审计 |
| `test_competition_v34.py` | 赛事专项：内存/流量/移动/代码审计/基线/日志/攻防验证 |
| `test_ecc_v351.py` | 异常椭圆曲线与多维 HNP（纯 Python LLL/SNF） |
| `test_polar_roar_v37.py` | 兽音变体解码（hex 算法、CJK 符号集、引导语杂散符号） |
| `test_pwn_ret2win.py` | 本地 TCP 闭环：ret2win 发送与 flag 抓取 |
| `test_responsibility_v37.py` | 唯一《软件责任说明》闸门（CLI 拦截/确认/撤销） |
| `test_triage_v36.py` | 首层判型、白名单脚本自动调用 |
| `test_webattack.py` | Web 全量战役：完整模式 + 快速收手模式两轮 |
| `test_webattack_v41.py` | v4.1 Web 场景 A–O：302 跟随、隐藏参数、off-by-slash、源码链、soft-404 负样本、上传预算 |
| `test_zipcrack_stego_v352.py` | ZipCrypto 口令恢复 + cloacked-pixel 图片隐写 |
| `ctf_deeptarget.py` | 深度 Web 本地靶站，供 `test_webattack.py` 使用，不是单测 |
| `v33_target.py` | v3.3 本地漏洞靶站，供 `test_autopilot_v33.py` 使用，不是单测 |
| `fixtures/` | 测试样本：APK、RAR5、ECC 点集、PHP 源码 |

文件名中的 `v3x` / `v4x` 是引入该回归时的版本标记，用于对应 `CHANGELOG.md`；所有用例仍在维护，全量执行以 `unittest discover` 为准。

`_uploads_v33/`、`deeptarget_requests.log` 为运行时产物，已被 `.gitignore` 忽略。
