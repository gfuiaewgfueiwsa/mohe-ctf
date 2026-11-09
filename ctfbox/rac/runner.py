# -*- coding: utf-8 -*-
"""RAC 第三步 —— Command：静默执行脚本并运行时提取 flag。

执行策略：
  - 解释器：打包后用随包便携 Python（tools/runtime/python），源码模式用当前解释器
    （与 common.external_python / 工具中心口径一致，干净电脑无 Python 也能跑）
  - 执行内核统一走 process_runner.run_command：
      * Windows 用 kill-on-close Job 托管，超时/取消会连同孙进程一起终止；
        旧实现用 subprocess.run(timeout=)，只杀直接子进程，脚本自己起的
        多进程（CRC 爆破、并行扫描）会变成孤儿继续吃 CPU，把整批任务拖死。
      * 强制 UTF-8 输出，避免中文脚本在 GBK 控制台下 UnicodeEncodeError。
      * stdout/stderr 有上限，长输出不会打爆内存。
  - 超时时保留已产生的输出（部分脚本在超时前已打印 flag）。
  - flag 提取：modules_exploit.FLAG_RE（强）+ common.scan_flags(strong) 双路合并去重
"""
import os
import time
from dataclasses import dataclass, field
from typing import List, Optional

from ..common import external_python, is_placeholder_flag, scan_flags
from ..modules_exploit import FLAG_RE
from ..process_runner import TaskTimeout, run_command

DEFAULT_TIMEOUT = 180
OUTPUT_HEAD = 6000
OUTPUT_TAIL = 4000


@dataclass
class RunResult:
    script: str = ""
    cmd: List[str] = field(default_factory=list)
    exit_code: Optional[int] = None
    ok: bool = False
    timed_out: bool = False
    output: str = ""
    flags: List[str] = field(default_factory=list)
    elapsed: float = 0.0
    error: str = ""

    def summary(self) -> str:
        head = self.output[:OUTPUT_HEAD]
        tail = "" if len(self.output) <= OUTPUT_HEAD + OUTPUT_TAIL else \
            "\n...(省略 %d 字节)...\n" % (len(self.output) - OUTPUT_HEAD - OUTPUT_TAIL) + \
            self.output[-OUTPUT_TAIL:]
        return head + tail


def extract_flags(output: str) -> List[str]:
    """强模式双路提取 flag 并保序去重。"""
    found: List[str] = []
    for m in FLAG_RE.finditer(output or ""):
        s = m.group(0)
        if s not in found and "?" not in s and "..." not in s and not is_placeholder_flag(s):
            found.append(s)
    for f in scan_flags((output or "").encode("utf-8", "ignore"), strong_only=True):
        if f not in found and "?" not in f and "..." not in f and not is_placeholder_flag(f):
            found.append(f)
    return found


def _script_env():
    env = os.environ.copy()
    env.update(PYTHONIOENCODING="utf-8:replace", PYTHONUTF8="1", PYTHONUNBUFFERED="1")
    return env


def run_script_entry(script_path: str, arglist: List[str], cwd: str,
                     timeout: int = DEFAULT_TIMEOUT,
                     python_exe: Optional[str] = None) -> RunResult:
    """在子进程中静默运行脚本，返回 RunResult（永不抛异常）。"""
    py = python_exe or external_python() or "python"
    cmd = [py, script_path] + [a for a in (arglist or [])]
    r = RunResult(script=script_path, cmd=cmd)
    t0 = time.time()
    try:
        proc = run_command(cmd, log=None, timeout=timeout, cwd=cwd or None,
                           env=_script_env())
        r.exit_code = proc.returncode
        r.output = (proc.stdout or "") + (proc.stderr or "")
        r.ok = proc.returncode == 0
        if not r.output.strip() and r.ok:
            r.output = "(无输出，退出码 0)"
    except TaskTimeout as exc:
        # 超时也保留已产生的输出：部分脚本先打印 flag 再继续跑长任务
        r.timed_out = True
        r.exit_code = -1
        r.output = "%s\n%s" % (exc.stdout or "", exc.stderr or "")
        r.error = f"超时（>{timeout}s），已终止（含子进程）"
        if not r.output.strip():
            r.output = "(超时无输出)"
    except FileNotFoundError:
        r.error = f"解释器不存在: {py}（打包环境请确认 tools/runtime/python）"
    except OSError as e:
        r.error = f"执行环境不可用: {e}"
    except Exception as e:
        r.error = f"执行异常: {e}"
    r.elapsed = time.time() - t0
    r.flags = extract_flags(r.output)
    # 退出码非 0 但输出里有 flag，也算命中（部分脚本用 stderr 打结果）
    if r.flags:
        r.ok = True
    return r
