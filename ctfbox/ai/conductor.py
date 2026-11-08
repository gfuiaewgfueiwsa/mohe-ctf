# -*- coding: utf-8 -*-
"""AI 裁判：读 AutoPilot 结构化报告，在固定白名单里选下一步动作与深度。

模型只做“选动作 + 填参数”，不直接生成结论；所有执行仍走编排层工具，
责任闸门 / scope 白名单 / 审计不变。
"""
import json
import os

from .backend import LlamaServer
from .config import ai_config

ACTIONS = {
    "deep_misc": "对目标做深度 MISC 分析（音频/图片/文档/取证等）",
    "stego_image": "图片隐写分析（LSB/频域/附加数据）",
    "archive_extract": "解压目标压缩包并递归扫描成员",
    "binary_deep": "二进制结构深度分析（PE/ELF/保护/导入表）",
    "decompile": "Ghidra 无头反编译（伪代码落盘）",
    "decode_chain": "编码/解码链尝试（base64/hex/url/rot 等）",
    "xor_analyze": "异或暴力与密钥推断",
    "stop": "信息已足够或无法继续，停止",
}

GRAMMAR = r'''
root   ::= "{" sp "\"action\"" sp ":" sp action sp "," sp "\"target\"" sp ":" sp target sp "," sp "\"depth\"" sp ":" sp depth sp "," sp "\"reason\"" sp ":" sp str sp "}"
action ::= "\"deep_misc\"" | "\"stego_image\"" | "\"archive_extract\"" | "\"binary_deep\"" | "\"decompile\"" | "\"decode_chain\"" | "\"xor_analyze\"" | "\"stop\""
target ::= "\"T" [0-9]+ "\""
depth  ::= [1-3]
str    ::= "\"" ([^"\\\x00-\x1f] | "\\" ["\\/bfnrt])* "\""
sp     ::= [ \t\n]*
'''.strip()

_IMAGE_EXT = {".png", ".jpg", ".jpeg", ".gif", ".bmp", ".webp", ".tif", ".tiff"}
_ARCHIVE_EXT = {".zip", ".rar", ".7z", ".tar", ".gz", ".bz2", ".xz"}
_BINARY_EXT = {".exe", ".elf", ".dll", ".so", ".bin", ".sys", ".o", ".scr"}

_EXT_CATEGORY = {
    ".mp3": "audio", ".wav": "audio", ".flac": "audio", ".ogg": "audio",
    ".m4a": "audio", ".aac": "audio", ".wma": "audio", ".amr": "audio",
    ".png": "image", ".jpg": "image", ".jpeg": "image", ".gif": "image",
    ".bmp": "image", ".webp": "image", ".tif": "image", ".tiff": "image",
    ".zip": "archive", ".rar": "archive", ".7z": "archive", ".tar": "archive",
    ".gz": "archive", ".bz2": "archive", ".xz": "archive",
    ".exe": "binary", ".elf": "binary", ".dll": "binary", ".so": "binary",
    ".py": "misc", ".txt": "misc",
}

MAX_TARGET_BYTES = 64 * 1024 * 1024


class Conductor:
    def __init__(self, log=None):
        self.log = log or (lambda m: None)

    # ------------------------------------------------------------------
    @staticmethod
    def _file_kind(path):
        ext = os.path.splitext(path)[1].lower()
        if ext in _IMAGE_EXT:
            return "image"
        if ext in _ARCHIVE_EXT:
            return "archive"
        if ext in _BINARY_EXT:
            return "binary"
        try:
            with open(path, "rb") as fp:
                head = fp.read(4)
            if head[:2] == b"MZ" or head == b"\x7fELF":
                return "binary"
        except OSError:
            pass
        return "other"

    def _allowed_actions(self, path):
        kind = self._file_kind(path)
        allowed = ["deep_misc", "decode_chain", "xor_analyze"]
        if kind == "image":
            allowed.append("stego_image")
        elif kind == "archive":
            allowed.append("archive_extract")
        elif kind == "binary":
            allowed += ["binary_deep", "decompile"]
        return allowed

    # ------------------------------------------------------------------
    def _targets(self, ws, saved):
        items = []
        if saved and os.path.isfile(saved):
            items.append(saved)
        root = getattr(ws, "artifacts_dir", "")
        if root and os.path.isdir(root):
            for dirpath, _dirs, files in os.walk(root):
                for name in files:
                    path = os.path.join(dirpath, name)
                    try:
                        if os.path.getsize(path) > MAX_TARGET_BYTES:
                            continue
                    except OSError:
                        continue
                    if path not in items:
                        items.append(path)
                    if len(items) >= 24:
                        break
                if len(items) >= 24:
                    break
        return items

    def _state(self, ws, category, targets, tried):
        cands = []
        for c in ws.ranked_candidates()[:5]:
            cands.append({"value": str(c.value)[:80], "confidence": round(c.confidence, 2),
                          "reason": str(c.reason)[:80]})
        tlist = []
        for idx, path in enumerate(targets):
            try:
                size = os.path.getsize(path)
            except OSError:
                size = -1
            done = {a for a, p in tried if p == os.path.realpath(path)}
            allowed = [a for a in self._allowed_actions(path) if a not in done]
            tlist.append({"id": "T%d" % idx, "name": os.path.basename(path),
                          "size": size, "allowed": allowed})
        return {
            "category": category,
            "targets": tlist,
            "candidates": cands,
            "already_tried": sorted("%s:%s" % (a, os.path.basename(p)) for a, p in tried),
            "notes": [str(n)[:120] for n in ws.notes[-6:]],
        }

    def _prompt(self, state):
        action_table = "\n".join("- %s: %s" % (k, v) for k, v in ACTIONS.items())
        sys_prompt = (
            "你是 CTF 工具箱的调度裁判，只做一件事：根据任务状态，在给定动作白名单里"
            "选择下一步动作与参数。严格只输出 JSON，不要解释。仅限已授权 CTF/靶场。\n"
            "动作表：\n%s\n"
            "规则：target 只能是给定 target id（T0 为原始输入）；"
            "每个 target 的 allowed 是唯一可选动作集合，动作不在其中一律无效；"
            "depth 取 1-3；没有合适的下一步必须输出 stop。\n"
            '输出示例：{"action":"deep_misc","target":"T1","depth":2,"reason":"成员是音频需深挖"}'
            % action_table
        )
        user = json.dumps(state, ensure_ascii=False)
        return ("<|im_start|>system\n%s<|im_end|>\n"
                "<|im_start|>user\n%s<|im_end|>\n"
                "<|im_start|>assistant\n" % (sys_prompt, user))

    # ------------------------------------------------------------------
    def decide(self, backend, state):
        text = backend.complete(self._prompt(state), grammar=GRAMMAR,
                                max_tokens=160, temperature=0.2)
        text = (text or "").strip()
        try:
            data = json.loads(text)
        except Exception:
            self.log("[ai] 模型输出非 JSON，忽略: %r" % text[:120])
            return None
        action = str(data.get("action", ""))
        if action not in ACTIONS:
            self.log("[ai] 动作不在白名单，忽略: %r" % action)
            return None
        if action == "stop":
            return {"action": "stop", "target": "", "depth": 0,
                    "reason": str(data.get("reason", ""))[:160]}
        target = str(data.get("target", ""))
        try:
            depth = max(1, min(3, int(data.get("depth", 1))))
        except (TypeError, ValueError):
            depth = 1
        return {"action": action, "target": target, "depth": depth,
                "reason": str(data.get("reason", ""))[:160]}

    def _dispatch(self, action, target_path, ws, raw, category):
        from ..autopilot.tools import archive, binary, codes, deepmisc, ghidra, stego

        name = action["action"]
        depth = action["depth"]
        outdir = os.path.join(ws.artifacts_dir, "ai")
        os.makedirs(outdir, exist_ok=True)
        if name == "deep_misc":
            return deepmisc.analyze(target_path, _EXT_CATEGORY.get(
                os.path.splitext(target_path)[1].lower(), category),
                timeout=120, max_depth=depth)
        if name == "stego_image":
            return stego.analyze(target_path, outdir)
        if name == "archive_extract":
            return archive.extract(target_path, outdir, depth=0, log=self.log, deep=True)
        if name == "binary_deep":
            return binary.analyze(target_path, deep=True)
        if name == "decompile":
            return ghidra.decompile(target_path, outdir)
        if name in ("decode_chain", "xor_analyze"):
            data = raw
            if target_path != getattr(self, "_saved", None):
                with open(target_path, "rb") as fp:
                    data = fp.read()
            if not data:
                from ..autopilot.models import ToolResult
                return ToolResult(tool="ai." + name, ok=False, summary="目标为空")
            if name == "decode_chain":
                return codes.decode_chain(data, depth=depth)
            from ..autopilot.tools import xor
            return xor.analyze(data)
        from ..autopilot.models import ToolResult
        return ToolResult(tool="ai.unknown", ok=False, summary="未知动作 " + name)

    # ------------------------------------------------------------------
    def run(self, kind, ws, saved, raw, category, run, can_run):
        if kind != "file":
            return
        if any(c.confidence >= 0.9 for c in ws.ranked_candidates()):
            return
        cfg = ai_config()
        targets = self._targets(ws, saved)
        if not targets:
            return
        self._saved = saved
        backend = LlamaServer(cfg["runtime"], cfg["model"], ngl=cfg["ngl"],
                              ctx=cfg["ctx"], port=cfg["port"],
                              timeout=cfg["timeout"], log=self.log,
                              reserve_mb=cfg.get("vram_reserve_mb", 4096),
                              fallback_exe=cfg.get("runtime_cpu", ""))
        if not backend.start():
            ws.notes.append("AI 裁判：本地模型未就绪，已回退确定性流程")
            return
        tried = set()
        try:
            for _ in range(max(1, int(cfg["max_decisions"]))):
                if not can_run():
                    break
                targets = self._targets(ws, saved)
                state = self._state(ws, category, targets, tried)
                action = self.decide(backend, state)
                if not action:
                    break
                if action["action"] == "stop":
                    ws.log("[ai] 裁判停止：%s" % (action["reason"] or "模型判定无需继续"))
                    ws.notes.append("AI 裁判停止：" + (action["reason"] or "无需继续"))
                    break
                try:
                    idx = int(action["target"].strip('"')[1:])
                except (ValueError, IndexError):
                    ws.log("[ai] 目标编号非法，跳过：%r" % action["target"])
                    ws.notes.append("AI 裁判目标编号非法已跳过：%r" % action["target"])
                    continue
                if idx < 0 or idx >= len(targets):
                    ws.log("[ai] 目标编号越界，跳过：T%d" % idx)
                    ws.notes.append("AI 裁判目标编号越界已跳过：T%d" % idx)
                    continue
                target_path = targets[idx]
                key = (action["action"], os.path.realpath(target_path))
                if key in tried:
                    ws.log("[ai] 重复决策，跳过：%s -> %s" % (
                        action["action"], os.path.basename(target_path)))
                    ws.notes.append("AI 裁判重复动作已跳过：%s -> %s" % (
                        action["action"], os.path.basename(target_path)))
                    continue
                tried.add(key)
                if action["action"] not in self._allowed_actions(target_path):
                    msg = "动作与目标类型不匹配，跳过：%s -> %s（允许：%s）" % (
                        action["action"], os.path.basename(target_path),
                        ",".join(self._allowed_actions(target_path)))
                    ws.log("[ai] " + msg)
                    ws.notes.append("AI 裁判" + msg)
                    continue
                ws.log("[ai] 裁判决策：%s -> %s (depth=%d) | %s" % (
                    action["action"], os.path.basename(target_path),
                    action["depth"], action["reason"]))
                ws.record(0, "ai.conductor", "AI 裁判调度", dict(action, target=target_path))
                ws.notes.append("AI 裁判：%s -> %s (depth=%d)" % (
                    action["action"], os.path.basename(target_path), action["depth"]))
                res = run(lambda a=action, p=target_path: self._dispatch(
                    a, p, ws, raw, category), "AI导调:" + action["action"])
                if res is None:
                    break
                if any(c.confidence >= 0.9 for c in res.candidates):
                    break
        finally:
            backend.stop()
