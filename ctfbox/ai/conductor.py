# -*- coding: utf-8 -*-
"""AI 裁判 v4.0：读 AutoPilot 结构化报告，在固定白名单里选下一步动作与深度。

v4.0 修复（对照 v3.7.0 实测缺陷）：
  P0  already_tried 并入确定性流程已完成步骤（读 evidence.jsonl），杜绝重复执行；
  P0  decode_chain 升级为 caesar_brute，自动枚举 0-25 位移 + 仿射；
  P1  Web 链路真正接入（去掉 kind!=file 就 return 的短路）；
  P2  新增 c_audit 动作，对 .c/.cpp 源码做审计；
  P3  prompt 硬约束「已完成动作/禁用动作」，URL 带凭据脱敏。

模型只做"选动作 + 填参数"，不直接生成结论；所有执行仍走编排层工具，
责任闸门 / scope 白名单 / 审计不变。
"""
import json
import os
import re

from .backend import LlamaServer
from .config import ai_config

ACTIONS = {
    "deep_misc": "对目标做深度 MISC 分析（音频/图片/文档/取证等）",
    "stego_image": "图片隐写分析（LSB/频域/附加数据）",
    "archive_extract": "解压目标压缩包并递归扫描成员",
    "binary_deep": "二进制结构深度分析（PE/ELF/保护/导入表）",
    "decompile": "Ghidra 无头反编译（伪代码落盘）",
    "decode_chain": "编码/解码链尝试（base64/hex/url 等）",
    "caesar_brute": "凯撒/仿射全位移爆破（0-25 位移 + 常见仿射系数）",
    "xor_analyze": "异或暴力与密钥推断",
    "c_audit": "C/C++ 源码审计（溢出/格式化串/命令注入/硬编码 flag）",
    "web_deep": "Web 深度探测（更多目录/参数/注入点）",
    "stop": "信息已足够或无法继续，停止",
}

_GRAMMAR_ACTION_ALTS = " | ".join('"\\"%s\\""' % a for a in ACTIONS)
GRAMMAR = (
    'root   ::= "{" sp "\\"action\\"" sp ":" sp action sp "," '
    'sp "\\"target\\"" sp ":" sp target sp "," '
    'sp "\\"depth\\"" sp ":" sp depth sp "," '
    'sp "\\"reason\\"" sp ":" sp str sp "}"\n'
    "action ::= " + _GRAMMAR_ACTION_ALTS + "\n"
    'target ::= "\\"T" [0-9]+ "\\""\n'
    "depth  ::= [1-3]\n"
    'str    ::= "\\"" ([^"\\\\\\x00-\\x1f] | "\\\\" ["\\\\/bfnrt])* "\\""\n'
    'sp     ::= [ \\t\\n]*'
).strip()

_IMAGE_EXT = {".png", ".jpg", ".jpeg", ".gif", ".bmp", ".webp", ".tif", ".tiff"}
_ARCHIVE_EXT = {".zip", ".rar", ".7z", ".tar", ".gz", ".bz2", ".xz"}
_BINARY_EXT = {".exe", ".elf", ".dll", ".so", ".bin", ".sys", ".o", ".scr"}
_SOURCE_EXT = {".c", ".cc", ".cpp", ".cxx", ".h", ".hpp"}

_EXT_CATEGORY = {
    ".mp3": "audio", ".wav": "audio", ".flac": "audio", ".ogg": "audio",
    ".m4a": "audio", ".aac": "audio", ".wma": "audio", ".amr": "audio",
    ".png": "image", ".jpg": "image", ".jpeg": "image", ".gif": "image",
    ".bmp": "image", ".webp": "image", ".tif": "image", ".tiff": "image",
    ".zip": "archive", ".rar": "archive", ".7z": "archive", ".tar": "archive",
    ".gz": "archive", ".bz2": "archive", ".xz": "archive",
    ".exe": "binary", ".elf": "binary", ".dll": "binary", ".so": "binary",
    ".py": "misc", ".txt": "misc", ".c": "source", ".cpp": "source",
}

MAX_TARGET_BYTES = 64 * 1024 * 1024

# 确定性流程已经跑过的工具名 -> 对应的 AI 动作（避免 AI 重复决策）
_DETERMINISTIC_TOOL_TO_ACTION = {
    "codes.chain": "decode_chain",
    "xor.single": "xor_analyze",
    "xor.repeating": "xor_analyze",
    "xor.crib": "xor_analyze",
    "binary.parse": "binary_deep",
    "binary.protect": "binary_deep",
    "binary.imports": "binary_deep",
    "deep.text": "deep_misc",
    "deep.audio": "deep_misc",
    "deep.image": "deep_misc",
    "deep.document": "deep_misc",
    "web.probe": "web_deep",
    "web.dirsearch": "web_deep",
}


def _sanitize_url(url: str) -> str:
    """去掉 URL 里的 user:pass@，避免明文凭据落盘。"""
    if not url:
        return url
    return re.sub(r"^([a-zA-Z][a-zA-Z0-9+\-.]*)://([^/:@]+):([^/@]+)@",
                  r"\1://***:***@", str(url))


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
        if ext in _SOURCE_EXT:
            return "source"
        try:
            with open(path, "rb") as fp:
                head = fp.read(4)
            if head[:2] == b"MZ" or head == b"\x7fELF":
                return "binary"
        except OSError:
            pass
        return "other"

    def _allowed_actions(self, path, kind):
        base = ["deep_misc", "decode_chain", "caesar_brute", "xor_analyze"]
        fk = self._file_kind(path)
        if fk == "image":
            base.append("stego_image")
        elif fk == "archive":
            base.append("archive_extract")
        elif fk == "binary":
            base += ["binary_deep", "decompile"]
        elif fk == "source":
            base.append("c_audit")
        if kind == "web":
            base.append("web_deep")
        return base

    # ------------------------------------------------------------------
    def _targets(self, ws, saved, kind):
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
        # Web 类没有文件 artifacts 时，至少给一个虚拟目标 T0 让模型能选 web_deep
        if kind == "web" and not items:
            items.append("__web_target__")
        return items

    def _read_done_actions(self, ws):
        """从 evidence.jsonl 读确定性流程已经跑过的工具，映射到 AI 动作名集合。"""
        done = set()
        ev = getattr(ws, "evidence_path", "")
        if not ev or not os.path.isfile(ev):
            return done
        try:
            with open(ev, encoding="utf-8") as fp:
                for line in fp:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        item = json.loads(line)
                    except Exception:
                        continue
                    tool = str(item.get("tool", ""))
                    for prefix, action in _DETERMINISTIC_TOOL_TO_ACTION.items():
                        if tool.startswith(prefix):
                            done.add(action)
        except Exception:
            pass
        return done

    def _state(self, ws, category, targets, tried, kind):
        cands = []
        for c in ws.ranked_candidates()[:5]:
            cands.append({"value": str(c.value)[:80], "confidence": round(c.confidence, 2),
                          "reason": str(c.reason)[:80]})
        done_actions = self._read_done_actions(ws)
        tlist = []
        for idx, path in enumerate(targets):
            if path == "__web_target__":
                tlist.append({"id": "T%d" % idx, "name": "(Web 目标)",
                              "size": -1, "allowed": ["web_deep", "stop"]})
                continue
            try:
                size = os.path.getsize(path)
            except OSError:
                size = -1
            done = {a for a, p in tried if p == os.path.realpath(path)}
            allowed = [a for a in self._allowed_actions(path, kind)
                       if a not in done and a not in done_actions]
            tlist.append({"id": "T%d" % idx, "name": os.path.basename(path),
                          "size": size, "allowed": allowed})
        return {
            "category": category,
            "targets": tlist,
            "candidates": cands,
            "already_tried": sorted("%s:%s" % (a, os.path.basename(p)) for a, p in tried),
            "already_done_by_pipeline": sorted(done_actions),
            "notes": [str(n)[:120] for n in ws.notes[-6:]],
        }

    def _prompt(self, state):
        action_table = "\n".join("- %s: %s" % (k, v) for k, v in ACTIONS.items())
        sys_prompt = (
            "你是 CTF 工具箱的调度裁判，只做一件事：根据任务状态，在给定动作白名单里"
            "选择下一步动作与参数。严格只输出 JSON，不要解释。仅限已授权 CTF/靶场。\n"
            "动作表：\n%s\n"
            "硬规则：\n"
            "1) target 只能是给定 target id（T0 为原始输入）；\n"
            "2) 每个 target 的 allowed 是唯一可选动作集合，动作不在其中一律无效，"
            "已经在 already_tried 或 already_done_by_pipeline 里的动作禁止再选；\n"
            "3) depth 取 1-3；\n"
            "4) 没有合适的下一步必须输出 stop，不要为了动而动；\n"
            "5) reason 必须与所选动作一致，禁止自相矛盾。\n"
            '输出示例：{"action":"caesar_brute","target":"T0","depth":2,"reason":"疑似凯撒密码需枚举位移"}'
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

    # ------------------------------------------------------------------
    def _dispatch(self, action, target_path, ws, raw, category):
        from ..autopilot.tools import archive, binary, codes, deepmisc, ghidra, stego
        from ..autopilot.models import ToolResult

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
        if name == "c_audit":
            return self._c_audit(target_path, outdir)
        if name == "web_deep":
            # Web 深度探测：用小字典追加常见敏感路径
            from ..autopilot.models import ToolResult, Candidate
            from ..common import scan_flags
            url = getattr(self, "_web_url", "") or (raw if isinstance(raw, str) else "")
            if not url:
                return ToolResult(tool="ai.web_deep", ok=False, summary="无 Web 目标 URL")
            hits = []
            candidates = []
            try:
                import requests as _rq
                import urllib3
                urllib3.disable_warnings()
            except Exception:
                return ToolResult(tool="ai.web_deep", ok=False, summary="requests 不可用")
            for p in (".git/HEAD", ".svn/entries", ".env", "backup.zip", "www.zip",
                      "admin/", "robots.txt", "sitemap.xml", "flag", "flag.txt",
                      "config.php.bak", "database.sql", "phpinfo.php"):
                try:
                    u = url.rstrip("/") + "/" + p
                    resp = _rq.get(u, timeout=6, allow_redirects=True, verify=False)
                    if resp.status_code == 200 and len(resp.content) > 0:
                        hits.append({"path": p, "status": resp.status_code,
                                     "size": len(resp.content)})
                        for fl in scan_flags(resp.content, strong_only=True):
                            candidates.append(Candidate(
                                value=fl, confidence=0.9,
                                source="ai.web_deep", reason="Web 深度探测命中 " + p))
                except Exception:
                    continue
            return ToolResult(
                tool="ai.web_deep", ok=True,
                summary="Web 深度探测 %d 个敏感路径，命中 %d 个" % (12, len(hits)),
                data={"hits": hits}, candidates=candidates)
        if name in ("decode_chain", "caesar_brute", "xor_analyze"):
            data = raw
            if target_path != getattr(self, "_saved", None) and target_path != "__web_target__":
                try:
                    with open(target_path, "rb") as fp:
                        data = fp.read()
                except Exception as exc:
                    return ToolResult(tool="ai." + name, ok=False, summary="读取失败: %s" % exc)
            if not data:
                return ToolResult(tool="ai." + name, ok=False, summary="目标为空")
            if name == "decode_chain":
                return codes.decode_chain(data, depth=depth)
            if name == "caesar_brute":
                return self._caesar_brute(data)
            from ..autopilot.tools import xor
            return xor.analyze(data)
        return ToolResult(tool="ai.unknown", ok=False, summary="未知动作 " + name)

    # ------------------------------------------------------------------
    @staticmethod
    def _caesar_brute(data: bytes):
        """凯撒 0-25 位移 + 常见仿射 (a=1, b=0..25; a=3, b=0..25) 爆破。"""
        from ..autopilot.models import ToolResult, Candidate
        from ..common import scan_flags

        try:
            text = data.decode("utf-8", errors="ignore")
        except Exception:
            text = ""
        if not text.strip():
            return ToolResult(tool="ai.caesar", ok=False, summary="无文本可爆破")

        candidates, hits = [], []

        def _try_shift(s, shift):
            out = []
            for ch in s:
                if "a" <= ch <= "z":
                    out.append(chr((ord(ch) - ord("a") + shift) % 26 + ord("a")))
                elif "A" <= ch <= "Z":
                    out.append(chr((ord(ch) - ord("A") + shift) % 26 + ord("A")))
                else:
                    out.append(ch)
            return "".join(out)

        for shift in range(26):
            dec = _try_shift(text, shift)
            flags = scan_flags(dec.encode("utf-8", "ignore"), strong_only=True)
            if flags:
                hits.append({"shift": shift, "flags": flags, "preview": dec[:120]})
                for fl in flags:
                    candidates.append(Candidate(
                        value=fl, confidence=0.9,
                        source="ai.caesar",
                        reason="凯撒位移 %d" % shift))
        # 仿射 a=3,5,7,11,15 b=0..25
        for a in (3, 5, 7, 11, 15):
            for b in range(26):
                out = []
                ok = True
                for ch in text:
                    if "a" <= ch <= "z":
                        x = ord(ch) - ord("a")
                        inv = pow(a, -1, 26) if _modinv(a, 26) else -1
                        if inv < 0:
                            ok = False
                            break
                        y = (inv * (x - b)) % 26
                        out.append(chr(y + ord("a")))
                    elif "A" <= ch <= "Z":
                        x = ord(ch) - ord("A")
                        inv = pow(a, -1, 26) if _modinv(a, 26) else -1
                        if inv < 0:
                            ok = False
                            break
                        y = (inv * (x - b)) % 26
                        out.append(chr(y + ord("A")))
                    else:
                        out.append(ch)
                if not ok:
                    continue
                dec = "".join(out)
                flags = scan_flags(dec.encode("utf-8", "ignore"), strong_only=True)
                if flags:
                    hits.append({"affine": [a, b], "flags": flags, "preview": dec[:120]})
                    for fl in flags:
                        candidates.append(Candidate(
                            value=fl, confidence=0.88,
                            source="ai.caesar",
                            reason="仿射 a=%d b=%d" % (a, b)))
        return ToolResult(
            tool="ai.caesar",
            ok=True,
            summary="凯撒 26 位移 + 仿射枚举，命中 %d 组" % len(hits),
            data={"hits": hits[:20]},
            candidates=candidates,
        )

    @staticmethod
    def _c_audit(path, outdir):
        """对 C/C++ 源码做简单审计：危险函数、硬编码 flag、缓冲区操作。"""
        from ..autopilot.models import ToolResult, Candidate
        from ..common import scan_flags

        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as fp:
                src = fp.read()
        except Exception as exc:
            return ToolResult(tool="ai.c_audit", ok=False, summary="读取失败: %s" % exc)

        risks = []
        dangerous = {
            "strcpy": "无长度检查字符串拷贝",
            "strcat": "无长度检查字符串拼接",
            "sprintf": "无长度检查格式化输出",
            "gets": "极危险的 gets()",
            "system": "直接调用 shell",
            "popen": "直接调用 shell",
            "scanf": "%s 无长度限制",
        }
        for fn, desc in dangerous.items():
            for m in re.finditer(r"\b%s\s*\(" % re.escape(fn), src):
                line_no = src.count("\n", 0, m.start()) + 1
                risks.append({"line": line_no, "call": fn, "risk": desc})

        candidates = []
        flags = scan_flags(src.encode("utf-8", "ignore"), strong_only=True)
        for fl in flags:
            candidates.append(Candidate(value=fl, confidence=0.9,
                                        source="ai.c_audit", reason="C 源码中硬编码"))

        return ToolResult(
            tool="ai.c_audit", ok=True,
            summary="审计 %s：发现 %d 处危险调用，%d 个候选 flag" % (
                os.path.basename(path), len(risks), len(candidates)),
            data={"risks": risks[:30]},
            candidates=candidates,
        )

    # ------------------------------------------------------------------
    def run(self, kind, ws, saved, raw, category, run, can_run, url=""):
        # v4.0: 不再短路 Web；Web 走虚拟目标 T0
        if kind == "web":
            self._web_url = _sanitize_url(url or "")
        if any(c.confidence >= 0.9 for c in ws.ranked_candidates()):
            return
        cfg = ai_config()
        targets = self._targets(ws, saved, kind)
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
                targets = self._targets(ws, saved, kind)
                state = self._state(ws, category, targets, tried, kind)
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
                if target_path == "__web_target__":
                    real_key = ("web_deep", "__web__")
                else:
                    real_key = (action["action"], os.path.realpath(target_path))
                if real_key in tried:
                    ws.log("[ai] 重复决策，跳过：%s" % action["action"])
                    ws.notes.append("AI 裁判重复动作已跳过：" + action["action"])
                    continue
                tried.add(real_key)
                # 确定性流程已跑过的动作直接跳过
                if action["action"] in self._read_done_actions(ws):
                    ws.log("[ai] 确定性流程已执行过 %s，跳过" % action["action"])
                    ws.notes.append("AI 裁判跳过已执行动作：" + action["action"])
                    continue
                allowed = self._allowed_actions(target_path, kind)
                if action["action"] not in allowed:
                    msg = "动作与目标类型不匹配，跳过：%s（允许：%s）" % (
                        action["action"], ",".join(allowed))
                    ws.log("[ai] " + msg)
                    ws.notes.append("AI 裁判" + msg)
                    continue
                ws.log("[ai] 裁判决策：%s -> %s (depth=%d) | %s" % (
                    action["action"],
                    "(Web 目标)" if target_path == "__web_target__" else os.path.basename(target_path),
                    action["depth"], action["reason"]))
                ws.record(0, "ai.conductor", "AI 裁判调度",
                          dict(action, target=target_path))
                ws.notes.append("AI 裁判：%s -> %s (depth=%d)" % (
                    action["action"],
                    "(Web)" if target_path == "__web_target__" else os.path.basename(target_path),
                    action["depth"]))
                res = run(lambda a=action, p=target_path: self._dispatch(
                    a, p, ws, raw, category), "AI导调:" + action["action"])
                if res is None:
                    break
                if any(c.confidence >= 0.9 for c in res.candidates):
                    break
        finally:
            backend.stop()


def _modinv(a, m):
    try:
        inv = pow(a, -1, m)
        return inv
    except ValueError:
        return -1
