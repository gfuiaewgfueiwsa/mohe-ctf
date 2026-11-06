# -*- coding: utf-8 -*-
"""RAC 自动化引擎包（v2.4 新增）。

RAC = Recognize → Assemble → Command 三段式题目自动化流水线：
  1. Recognize 识别（recognizer.py）：题目描述 + 附件 → 题型分类 + 参数自动提取
  2. Assemble  装配（matcher.py / assembler.py）：脚本库评分匹配 → 参数自动填入 → 生成可执行命令
  3. Command   执行（runner.py）：子进程静默运行 → 运行时提取 flag → top-N 候选自动降级重试

同一包内的附属自动化能力（统一打进一个 exe，无需另装）：
  - recon.py       侦察自动化（端口扫描 / HTTP 指纹 / 目录探测批量收集）
  - remoteexec.py  远程访问控制自动化（SSH 主机清单批量执行命令）
  - oracle_rac.py  Oracle RAC 集群巡检自动化（SSH 只读巡检命令集 → 汇总报告）
  - rpa.py         RPA 会话自动化（步骤表驱动 HTTP 会话：自动登录 / 自动提交 flag）

设计原则与 modules_exploit 一致：只产出"方法/骨架/自动填参"，
flag 一律在运行时从脚本输出中用强模式提取，不写死任何答案。
仅用于 CTF 比赛、靶场与已授权环境。
"""
from .pipeline import RacPipeline, RacResult
from .recognizer import recognize, TaskCard
from .matcher import ScriptIndex
from .runner import run_script_entry

__all__ = [
    "RacPipeline", "RacResult", "recognize", "TaskCard",
    "ScriptIndex", "run_script_entry",
]
