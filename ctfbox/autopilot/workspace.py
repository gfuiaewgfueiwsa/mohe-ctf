# -*- coding: utf-8 -*-
"""统一任务工作区：每题一个目录，保存输入、产物、日志、证据链、结论。

目录结构：
  workspace/tasks/<YYYYMMDD_HHMMSS>_<slug>/
    input/        原始输入副本
    artifacts/    解码结果 / 反编译片段 / 页面快照
    logs/run.log  全量运行日志
    evidence.jsonl 逐步证据（一行一个 JSON）
    result.json   机器可读结论
    report.md     人工可读报告
"""
import json
import os
import shutil
import threading
import time
from typing import List

from ..common import WORKSPACE, safe_name
from .models import Candidate, jsonable


class TaskWorkspace:
    def __init__(self, kind: str, name: str, root: str = None):
        root = root or os.path.join(WORKSPACE, "tasks")
        os.makedirs(root, exist_ok=True)
        slug = safe_name(name)[:48] or "task"
        stamp = time.strftime("%Y%m%d_%H%M%S")
        self.dir = os.path.join(root, f"{stamp}_{kind}_{slug}")
        self.input_dir = os.path.join(self.dir, "input")
        self.artifacts_dir = os.path.join(self.dir, "artifacts")
        self.logs_dir = os.path.join(self.dir, "logs")
        for d in (self.input_dir, self.artifacts_dir, self.logs_dir):
            os.makedirs(d, exist_ok=True)
        self.evidence_path = os.path.join(self.dir, "evidence.jsonl")
        self.result_path = os.path.join(self.dir, "result.json")
        self.report_path = os.path.join(self.dir, "report.md")
        self.log_path = os.path.join(self.logs_dir, "run.log")
        self.kind = kind
        self.name = name
        self.started = time.strftime("%Y-%m-%d %H:%M:%S")
        self.finished = ""
        self.candidates = []
        self.notes = []
        self._lock = threading.Lock()
        self._log_fp = open(self.log_path, "a", encoding="utf-8", errors="replace")

    # ------------------------------------------------------------------
    def log(self, message: str, level: str = "info"):
        stamp = time.strftime("%H:%M:%S")
        line = f"[{stamp}][{level}] {message}"
        try:
            print(line)
        except Exception:
            pass
        with self._lock:
            try:
                self._log_fp.write(line + "\n")
                self._log_fp.flush()
            except Exception:
                pass

    def record(self, step: int, tool: str, action: str, result=None):
        """写一条证据链记录。result 可以是 ToolResult 或任意 dict。"""
        item = {
            "ts": time.strftime("%Y-%m-%d %H:%M:%S"),
            "step": step,
            "tool": tool,
            "action": action,
            "result": result.to_dict() if hasattr(result, "to_dict") else jsonable(result),
        }
        with self._lock:
            with open(self.evidence_path, "a", encoding="utf-8") as fp:
                fp.write(json.dumps(item, ensure_ascii=False) + "\n")

    def add_candidates(self, candidates: List[Candidate]):
        """按 value 去重，保留最高置信度并合并来源。"""
        for cand in candidates or []:
            if not cand or not cand.value:
                continue
            hit = next((c for c in self.candidates if c.value == cand.value), None)
            if hit:
                if cand.confidence > hit.confidence:
                    hit.confidence = cand.confidence
                    hit.reason = cand.reason
                    hit.chain = cand.chain
                if cand.source and cand.source not in hit.source:
                    hit.source = (hit.source + "; " + cand.source).strip("; ")
            else:
                self.candidates.append(cand)

    def ranked_candidates(self) -> List[Candidate]:
        return sorted(self.candidates, key=lambda c: -c.confidence)

    def save_artifact(self, name: str, data, binary: bool = False) -> str:
        path = os.path.join(self.artifacts_dir, safe_name(name))
        os.makedirs(os.path.dirname(path), exist_ok=True)
        try:
            if binary or isinstance(data, (bytes, bytearray)):
                with open(path, "wb") as fp:
                    fp.write(bytes(data))
            else:
                with open(path, "w", encoding="utf-8", errors="replace") as fp:
                    fp.write(str(data))
            return path
        except Exception:
            return ""

    def copy_input(self, path: str) -> str:
        dst = os.path.join(self.input_dir, safe_name(os.path.basename(path)))
        try:
            if os.path.abspath(path) != os.path.abspath(dst):
                shutil.copy2(path, dst)
            return dst
        except Exception:
            return path

    # ------------------------------------------------------------------
    def finalize(self, extra: dict = None) -> dict:
        self.finished = time.strftime("%Y-%m-%d %H:%M:%S")
        result = {
            "version": "3.7.0",
            "kind": self.kind,
            "name": self.name,
            "workdir": self.dir,
            "started": self.started,
            "finished": self.finished,
            "flags": [c.value for c in self.ranked_candidates() if c.confidence >= 0.8],
            "candidates": [c.to_dict() for c in self.ranked_candidates()],
            "notes": list(self.notes),
            "evidence_path": self.evidence_path,
            "log_path": self.log_path,
        }
        if extra:
            result.update(jsonable(extra))
        try:
            with open(self.result_path, "w", encoding="utf-8") as fp:
                json.dump(result, fp, ensure_ascii=False, indent=2)
        except Exception:
            pass
        return result

    def close(self):
        try:
            self._log_fp.close()
        except Exception:
            pass
