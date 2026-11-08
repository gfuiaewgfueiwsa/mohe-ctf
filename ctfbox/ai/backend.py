# -*- coding: utf-8 -*-
"""llama.cpp llama-server 本地推理后端（CPU/GPU 自动回退，GBNF 约束 JSON）。"""
import os
import socket
import subprocess
import time

import requests

_CREATE_NO_WINDOW = 0x08000000 if os.name == "nt" else 0


def _free_port(start=18080, tries=20):
    for port in range(start, start + tries):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            if s.connect_ex(("127.0.0.1", port)) != 0:
                return port
    return start


class LlamaServer:
    def __init__(self, exe, model, ngl="auto", ctx=4096, port=18080,
                 timeout=120, log=None, reserve_mb=4096, fallback_exe=""):
        self.exe = exe
        self.model = model
        self.ngl = ngl
        self.ctx = int(ctx)
        self.timeout = int(timeout)
        self.port = _free_port(int(port))
        self.log = log or (lambda m: None)
        self.reserve_mb = max(512, int(reserve_mb))
        self.fallback_exe = fallback_exe if fallback_exe != exe else ""
        self.proc = None
        self._log_fp = None
        self.active_ngl = None
        self.active_exe = exe

    @property
    def base(self):
        return f"http://127.0.0.1:{self.port}"

    def _ngl_arg(self):
        val = str(self.ngl).lower()
        if val in ("auto", "all"):
            return val
        try:
            return max(0, int(val))
        except ValueError:
            return "auto"

    def _launch(self, ngl, exe=None):
        exe = exe or self.exe
        cmd = [exe, "--model", self.model, "--host", "127.0.0.1",
               "--port", str(self.port), "--ctx-size", str(self.ctx),
               "--n-gpu-layers", str(ngl), "--parallel", "1"]
        if ngl != 0:
            cmd += ["--fit-target", str(self.reserve_mb)]
        log_path = os.path.join(os.path.dirname(self.model) or ".",
                                "llama-server.log")
        self._log_fp = open(log_path, "w", encoding="utf-8", errors="replace")
        self.proc = subprocess.Popen(cmd, stdout=self._log_fp, stderr=subprocess.STDOUT,
                                     creationflags=_CREATE_NO_WINDOW)
        self.active_ngl = ngl
        self.active_exe = exe

    def start(self):
        ngl = self._ngl_arg()
        for attempt_ngl in ([ngl] if ngl == 0 else [ngl, 0]):
            self._launch(attempt_ngl)
            if self._wait_ready():
                self.log(f"[ai] llama-server 就绪 | ngl={attempt_ngl} "
                         f"reserve={self.reserve_mb}MB ctx={self.ctx} port={self.port}")
                return True
            self.stop()
            self.log(f"[ai] llama-server 启动失败（ngl={attempt_ngl}），回退重试")
        if self.fallback_exe and os.path.exists(self.fallback_exe):
            self._launch(0, self.fallback_exe)
            if self._wait_ready():
                self.log("[ai] 已回退 CPU 运行时 | ngl=0")
                return True
            self.stop()
        return False

    def _wait_ready(self):
        deadline = time.time() + self.timeout
        while time.time() < deadline:
            if self.proc.poll() is not None:
                return False
            try:
                r = requests.get(self.base + "/health", timeout=2)
                if r.status_code == 200:
                    return True
            except Exception:
                pass
            time.sleep(1.0)
        return False

    def complete(self, prompt, grammar=None, max_tokens=160, temperature=0.2):
        body = {"prompt": prompt, "n_predict": max_tokens, "temperature": temperature,
                "top_p": 0.9, "stream": False, "cache_prompt": True,
                "stop": ["<|im_end|>", "</s>"]}
        if grammar:
            body["grammar"] = grammar
        r = requests.post(self.base + "/completion", json=body, timeout=self.timeout)
        r.raise_for_status()
        return (r.json() or {}).get("content", "")

    def stop(self):
        try:
            if self.proc and self.proc.poll() is None:
                self.proc.terminate()
                try:
                    self.proc.wait(timeout=8)
                except subprocess.TimeoutExpired:
                    self.proc.kill()
        except Exception:
            pass
        try:
            if self._log_fp:
                self._log_fp.close()
        except Exception:
            pass
        self.proc = None
        self._log_fp = None

    def __enter__(self):
        if not self.start():
            raise RuntimeError("llama-server 未就绪")
        return self

    def __exit__(self, *exc):
        self.stop()
