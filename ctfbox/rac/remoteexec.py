# -*- coding: utf-8 -*-
"""RAC 附属自动化 —— 远程访问控制自动化（SSH 批量执行）。

主机清单格式（每行一台，支持注释 #）：
  host,port,user,password        ← 口令登录（port 可省，默认 22 → host,user,password）
  host,port,user,key=C:\\path\\id_rsa   ← 私钥登录
  host,port,user,key=C:\\path\\id_rsa,passphrase=xxx

能力：并发批量执行命令、单机超时、结果汇总。依赖 paramiko（随包）。
仅用于已授权主机（CTF 靶机 / 自有设备）。
"""
import re
import threading
import concurrent.futures as cf
from dataclasses import dataclass, field
from typing import Callable, List, Optional


@dataclass
class HostSpec:
    host: str = ""
    port: int = 22
    user: str = ""
    password: str = ""
    key_path: str = ""
    passphrase: str = ""

    def masked(self) -> str:
        """展示用（隐藏口令）。"""
        auth = f"key={self.key_path}" if self.key_path else "password=***"
        return f"{self.user}@{self.host}:{self.port} ({auth})"


@dataclass
class ExecResult:
    spec: HostSpec = None
    ok: bool = False
    connected: bool = False
    output: str = ""
    error: str = ""
    elapsed: float = 0.0


def parse_host_list(text: str) -> List[HostSpec]:
    """解析主机清单文本。"""
    hosts = []
    for raw in re.split(r"[\r\n]+", text or ""):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = [p.strip() for p in re.split(r"[,，]", line) if p.strip()]
        if not parts:
            continue
        h = HostSpec()
        h.host = parts[0]
        idx = 1
        if idx < len(parts) and parts[idx].isdigit():
            h.port = int(parts[idx]); idx += 1
        if idx < len(parts):
            h.user = parts[idx]; idx += 1
        while idx < len(parts):
            kv = parts[idx]
            if kv.lower().startswith("key="):
                h.key_path = kv[4:]
            elif kv.lower().startswith("passphrase="):
                h.passphrase = kv[11:]
            elif not h.password:
                h.password = kv
            idx += 1
        if h.host and h.user:
            hosts.append(h)
    return hosts


def exec_one(spec: HostSpec, command: str, timeout: float = 30.0) -> ExecResult:
    """单机 SSH 执行（永不抛异常）。"""
    import time
    r = ExecResult(spec=spec)
    t0 = time.time()
    try:
        import paramiko
    except Exception as e:
        r.error = f"paramiko 未安装: {e}"
        r.elapsed = time.time() - t0
        return r
    client = paramiko.SSHClient()
    try:
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        kwargs = dict(hostname=spec.host, port=spec.port, username=spec.user,
                      timeout=min(timeout, 15.0), allow_agent=False,
                      look_for_keys=False)
        if spec.key_path:
            kwargs["key_filename"] = spec.key_path
            kwargs["passphrase"] = spec.passphrase or None
            kwargs["password"] = spec.password or None
        else:
            kwargs["password"] = spec.password
        client.connect(**kwargs)
        r.connected = True
        stdin, stdout, stderr = client.exec_command(command, timeout=timeout)
        out = stdout.read().decode("utf-8", "replace")
        err = stderr.read().decode("utf-8", "replace")
        rc = stdout.channel.recv_exit_status()
        r.output = (out + ("\n" + err if err.strip() else "")).strip()
        r.ok = rc == 0
        if not r.output:
            r.output = f"(无输出, 退出码 {rc})"
    except Exception as e:
        r.error = f"{type(e).__name__}: {e}"
    finally:
        try:
            client.close()
        except Exception:
            pass
    r.elapsed = time.time() - t0
    return r


def run_batch(hosts: List[HostSpec], command: str, timeout: float = 30.0,
              concurrency: int = 5, log: Callable = print,
              cancel_check: Optional[Callable] = None) -> List[ExecResult]:
    """并发批量执行。返回与 hosts 顺序一致的 ExecResult 列表。"""
    results: List[Optional[ExecResult]] = [None] * len(hosts)
    lock = threading.Lock()
    idx_counter = {"i": 0}

    def work(i, h):
        if cancel_check and cancel_check():
            return
        log(f"[{i + 1}/{len(hosts)}] {h.masked()} 执行中 ...")
        r = exec_one(h, command, timeout)
        with lock:
            results[i] = r
        state = "✔" if r.ok else "✖"
        log(f"    {state} {h.user}@{h.host} ({r.elapsed:.1f}s) "
            f"{('输出 ' + str(len(r.output)) + 'B') if r.connected else r.error}")

    with cf.ThreadPoolExecutor(max_workers=max(1, min(concurrency, 32))) as ex:
        futs = [ex.submit(work, i, h) for i, h in enumerate(hosts)]
        for f in futs:
            f.result()
    # 被取消的槽位补占位
    for i, r in enumerate(results):
        if r is None:
            results[i] = ExecResult(spec=hosts[i], error="(已取消)")
    return results


def batch_report(results: List[ExecResult]) -> str:
    lines = ["RAC SSH 批量执行报告", "=" * 56]
    for r in results:
        lines.append(f"--- {r.spec.masked()} ---")
        lines.append(f"  连接: {'成功' if r.connected else '失败'}   "
                     f"退出: {'OK' if r.ok else '失败'}   耗时: {r.elapsed:.1f}s")
        if r.error:
            lines.append(f"  错误: {r.error}")
        if r.output:
            lines.append("  输出:")
            for ln in r.output.splitlines()[:60]:
                lines.append("    " + ln)
        lines.append("")
    return "\n".join(lines)
