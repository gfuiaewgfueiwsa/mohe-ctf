# -*- coding: utf-8 -*-
"""RAC 第二步（后半）—— Assemble：参数自动填入与命令装配。

按脚本静态解析出的接口自动选择填参方式：
  方式 P：脚本支持 --params 文件（PARAMS 字典风格，如 rsa_all_in_one.py）
          → 生成 params.txt（每行 `key = value`），命令行传 --params
  方式 A：脚本用 argparse（--n/--host/--path ...）
          → 直接组装命令行参数；位置参数若为"文件路径"则自动传附件
  方式 D：脚本无可识别参数接口 → 原样执行（自动探测型脚本），
          仅在有 --selftest 时注明可自测

输出装配结果 AssembleResult：cmd 参数列表（不带解释器前缀，由 runner 拼）、
工作目录、说明、缺失参数警告。所有产物落在 workspace/rac_runs/<run>/。
"""
import os
import re
import json
import shutil
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from ..common import WORKSPACE

# argparse 参数名 → 任务参数键的别名表（把题目参数映射到脚本参数）
ARG_ALIASES = {
    "ciphertext": ("ciphertext", "data", "ct", "text", "enc", "input", "s"),
    "host": ("host", "server", "ip", "target", "host"),
    "port": ("port", "p"),
    "url": ("url", "base", "baseurl", "target", "u"),
    "md5": ("md5", "hash", "h"),
    "sha1": ("sha1", "hash", "h"),
    "sha256": ("sha256", "hash", "h"),
    "user": ("user", "username", "login"),
    "pass": ("pass", "password", "pwd"),
}

# 路径型参数（优先传附件）
PATH_ARG_HINTS = ("path", "file", "image", "img", "input", "pcap", "doc", "audio", "video")
RE_PATHY = re.compile(r"(path|file|image|img|pcap|audio|video|doc|input|bin|elf|apk)", re.I)

RAC_RUNS_DIR = os.path.join(WORKSPACE, "rac_runs")


def new_run_dir(slug: str = "rac") -> str:
    ts = time.strftime("%Y%m%d_%H%M%S")
    safe = re.sub(r"[^\w.-]", "_", slug)[:40] or "rac"
    d = os.path.join(RAC_RUNS_DIR, f"{ts}_{safe}")
    os.makedirs(d, exist_ok=True)
    return d


@dataclass
class AssembleResult:
    script_path: str = ""
    arglist: List[str] = field(default_factory=list)   # 解释器之后的参数
    mode: str = ""                                     # params-file / argv / plain
    notes: List[str] = field(default_factory=list)     # 装配说明（日志用）
    missing: List[str] = field(default_factory=list)   # 必填但未提供的参数


def _fmt_val(v) -> str:
    if isinstance(v, bool):
        return "1" if v else "0"
    return str(v)


def _write_params_file(task_params: Dict, keys: List[str], path: str) -> int:
    """写 PARAMS 风格参数文件：每行 `key = value`。返回写入条数。"""
    n = 0
    with open(path, "w", encoding="utf-8") as f:
        for k in keys:
            v = task_params.get(k.lower())
            if v is None:
                continue
            if isinstance(v, int):
                f.write(f"{k} = {v}\n")
            else:
                f.write(f"{k} = {_fmt_val(v)}\n")
            n += 1
    return n


def assemble(entry, task, run_dir: str) -> AssembleResult:
    """把任务卡参数装配进脚本。entry: matcher.ScriptEntry。"""
    res = AssembleResult(script_path=entry.path)
    tparams = task.params
    attachments = task.attachments

    # 复制脚本到运行目录（自包含执行，产物与脚本同处便于溯源）
    try:
        local_script = os.path.join(run_dir, os.path.basename(entry.path))
        shutil.copy2(entry.path, local_script)
        res.script_path = local_script
    except Exception:
        res.script_path = entry.path
        res.notes.append("[!] 脚本复制失败，直接引用原路径执行")

    # 方式 P：--params 文件
    if "--params" in entry.args and entry.params_keys:
        pf = os.path.join(run_dir, "params.txt")
        n = _write_params_file(tparams, entry.params_keys, pf)
        if n > 0:
            res.mode = "params-file"
            res.arglist = ["--params", pf]
            overlap = {k.lower() for k in entry.params_keys} & set(
                k.lower() for k in tparams)
            res.notes.append(f"[+] PARAMS 字典风格：已写入 {n} 项参数到 params.txt")
            if not overlap:
                res.missing = ["(脚本参数字典与题目参数无交集)"]
            return res
        res.notes.append("[*] 参数字典全空，退回命令行/原样执行")

    # 方式 A：argparse 命令行
    argv: List[str] = []
    used = set()
    tparams_lower = {k.lower(): k for k in tparams}
    for argname, info in entry.args.items():
        short = argname.strip("-").lower()
        if short == "selftest":
            continue
        # 1) 直接同名
        val = None
        if short in tparams_lower:
            val = tparams[tparams_lower[short]]
            used.add(short)
        else:
            # 2) 别名表
            for tkey, aliases in ARG_ALIASES.items():
                if tkey in tparams_lower and short in aliases:
                    val = tparams[tparams_lower[tkey]]
                    used.add(tkey)
                    break
        if val is None and RE_PATHY.search(argname) and attachments:
            # 3) 路径型参数 → 自动传首个附件
            val = attachments[0]
            used.add(f"@attach:{short}")
        if val is not None:
            if argname.startswith("-"):
                argv += [argname, _fmt_val(val)]
            else:
                argv.append(_fmt_val(val))
        elif info.get("required") and not argname.startswith("-"):
            res.missing.append(short)
    if argv or (entry.args and any(a.strip("-").lower() not in ("selftest", "verbose", "debug", "quiet") for a in entry.args)):
        res.mode = "argv"
        res.arglist = argv
        if argv:
            res.notes.append(f"[+] argparse 风格：已填入 {len(argv) // 2 or len(argv)} 个参数")
        if res.missing:
            res.notes.append("[!] 缺少必填参数: " + ", ".join(res.missing))
        return res

    # 方式 D：无接口，原样执行
    res.mode = "plain"
    res.notes.append("[*] 脚本无可识别参数接口，原样执行（自动探测型）")
    return res


def write_meta(run_dir: str, task, matches, runs) -> str:
    """把一次 RAC 运行的完整过程写入 meta.json（便于复盘）。"""
    meta = {
        "time": time.strftime("%Y-%m-%d %H:%M:%S"),
        "task": task.as_dict(),
        "matches": [
            {"score": round(s, 2), **e.as_dict()} for s, e in matches
        ],
        "runs": [
            {"script": r.script, "cmd": r.cmd, "exit": r.exit_code, "ok": r.ok,
             "flags": r.flags, "elapsed": round(r.elapsed, 2),
             "output_head": r.output[:4000]} for r in runs
        ],
        "final_flags": list(dict.fromkeys(
            [f for r in runs for f in r.flags] + task.direct_flags)),
    }
    path = os.path.join(run_dir, "meta.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(meta, f, ensure_ascii=False, indent=2)
    return path
