# -*- coding: utf-8 -*-
"""AI 模型投毒 / 后门静态检测（v4.0 新增第七大梭哈模块）。

支持格式（全部静态扫描，绝不 import / torch.load / pickle.load）：
  - .pkl / .pickle / .joblib / .pt / .pth / .ckpt ：扫描 pickle 字节码中的危险 op
  - .safetensors ：解析 JSON 头，检查 metadata 里的可疑条目
  - .onnx        ：protobuf 头里找自定义 op / 可疑初始化
  - .h5 / .hdf5  ：扫描 HDF5 里的可执行片段字符串
  - .pb          ：TensorFlow SavedModel，扫描 graph_def 里的可疑节点

输出：风险条目列表 + 是否检出后门 + 证据摘要。
"""
import json
import os
import re
import struct
import zipfile

# pickle op 码中能直接触发代码执行的（来自 pickletools）
_PICKLE_DANGEROUS_OPS = {
    "i": "BUILD（执行类构造）",
    "R": "REDUCE（调用可调用对象）",
    "}": "SETITEM（构造 dict）",
    "]": "APPEND（构造 list）",
    "}": "SETITEM",
}
# 危险字符串特征（在 pickle 字节流里出现就高风险）
# pickle 的 GLOBAL op (c) 会把模块名和函数名分两行写，所以这里用单独的 token
_PICKLE_RISK_STRINGS = [
    b"os.system", b"subprocess", b"popen", b"commands.getoutput",
    b"eval(", b"exec(", b"__import__", b"importlib",
    b"socket.", b"urllib", b"requests.", b"http.client",
    b"pty.spawn", b"pty.openpty", b"ctypes", b"cdll", b"win32api",
    b"base64.b64decode", b"codecs.decode", b"marshal.loads",
    b"pickle.loads", b"yaml.load", b"pickle.Unpickler",
    b"torch.hub", b"torch.utils.model_zoo",
    b"numpy.load", b"numpy.frombuffer",
]
# pickle GLOBAL op (c, 0x63) 后紧跟的危险模块/函数名（短 token，单独成行）
_PICKLE_RISK_TOKENS = [
    b"system\n", b"popen\n", b"exec\n", b"eval\n",
    b"subprocess\n", b"socket\n", b"ctypes\n",
    b"builtins\n", b"__import__\n", b"marshal\n",
    b"os\nsystem\n", b"os\npopen\n", b"posix\nsystem\n",
]

# safetensors metadata 里的可疑 key
_SAFETENSORS_RISK_KEYS = {
    "pickle", "code", "exec", "eval", "script", "entrypoint",
    "run", "start", "init", "custom", "loader", "backend",
}


def _scan_pickle_bytes(data: bytes):
    """静态扫 pickle 字节流：不 unpickle，只找危险字符串和 REDUCE/BUILD op。"""
    findings = []
    # 1) 危险字符串特征
    for pat in _PICKLE_RISK_STRINGS:
        idx = data.find(pat)
        if idx >= 0:
            ctx_start = max(0, idx - 24)
            ctx_end = min(len(data), idx + len(pat) + 40)
            ctx = data[ctx_start:ctx_end]
            try:
                ctx_repr = repr(ctx)
            except Exception:
                ctx_repr = "<binary>"
            findings.append({
                "type": "risk_string",
                "pattern": pat.decode("utf-8", errors="replace"),
                "offset": idx,
                "context": ctx_repr[:200],
                "severity": "high" if pat in (b"os.system", b"subprocess", b"eval(",
                                              b"exec(", b"__import__", b"socket.") else "medium",
            })
    # 1.5) pickle GLOBAL op 的危险 token（模块名/函数名分两行）
    for pat in _PICKLE_RISK_TOKENS:
        idx = data.find(pat)
        if idx >= 0:
            findings.append({
                "type": "pickle_global_risk",
                "pattern": pat.decode("utf-8", errors="replace").strip(),
                "offset": idx,
                "context": repr(data[max(0, idx-16):idx+len(pat)+16])[:200],
                "severity": "high",
            })
    # 2) pickle op：REDUCE = b"R" (0x52), BUILD = b")" (0x29)
    #    这两个 op 本身不危险，但配合上面的危险字符串就是后门
    reduce_count = data.count(b"R")
    build_count = data.count(b")")
    if findings:
        findings.append({
            "type": "op_summary",
            "reduce_ops": reduce_count,
            "build_ops": build_count,
            "note": "pickle 字节流含 %d 个 REDUCE、%d 个 BUILD op" % (reduce_count, build_count),
        })
    return findings


def _scan_safetensors(path: str):
    """safetensors 格式：前 8 字节是小端 uint64，表示 header 长度，后面是 JSON。"""
    findings = []
    try:
        with open(path, "rb") as fp:
            header_len = struct.unpack("<Q", fp.read(8))[0]
            if header_len <= 0 or header_len > 16 * 1024 * 1024:
                return [{"type": "format_error", "note": "header 长度异常: %d" % header_len}]
            header = json.loads(fp.read(header_len).decode("utf-8", errors="replace"))
    except Exception as exc:
        return [{"type": "parse_error", "note": str(exc)[:200]}]

    metadata = header.get("__metadata__") or {}
    for key, value in metadata.items():
        kl = key.lower()
        if any(rk in kl for rk in _SAFETENSORS_RISK_KEYS):
            findings.append({
                "type": "safetensors_metadata",
                "key": key,
                "value": str(value)[:200],
                "severity": "high",
            })
        # metadata value 里如果出现危险字符串
        vs = str(value).encode("utf-8", errors="ignore")
        for pat in _PICKLE_RISK_STRINGS:
            if pat in vs:
                findings.append({
                    "type": "safetensors_risk_value",
                    "key": key,
                    "pattern": pat.decode("utf-8", errors="replace"),
                    "severity": "high",
                })
    return findings


def _scan_pytorch_zip(path: str):
    """PyTorch .pt/.pth/.ckpt 本质是 zip，里面有 data.pkl。扫 zip 里所有 pickle 文件。"""
    findings = []
    if not zipfile.is_zipfile(path):
        return findings
    try:
        with zipfile.ZipFile(path) as zf:
            names = zf.namelist()
            findings.append({"type": "zip_contents", "entries": names[:30]})
            for name in names:
                if name.endswith((".pkl", ".pickle", ".pt", ".pth")):
                    try:
                        data = zf.read(name)
                    except Exception:
                        continue
                    sub = _scan_pickle_bytes(data)
                    for s in sub:
                        s["inside_zip"] = name
                        findings.append(s)
    except Exception as exc:
        findings.append({"type": "zip_error", "note": str(exc)[:200]})
    return findings


def _scan_onnx(path: str):
    """粗扫 onnx：找自定义 op 名称里的危险字符串。"""
    findings = []
    try:
        with open(path, "rb") as fp:
            data = fp.read(4 * 1024 * 1024)  # 只读前 4MB
    except Exception as exc:
        return [{"type": "read_error", "note": str(exc)[:200]}]
    for pat in (b"CustomOp", b"Executable", b"system", b"subprocess", b"exec", b"eval"):
        idx = data.find(pat)
        if idx >= 0:
            findings.append({
                "type": "onnx_suspicious_op",
                "pattern": pat.decode("utf-8", errors="replace"),
                "offset": idx,
                "severity": "medium",
            })
    return findings


def analyze(path: str, outdir: str = ""):
    """主入口：根据扩展名分派扫描器，返回 dict 结果。"""
    ext = os.path.splitext(path)[1].lower()
    size = os.path.getsize(path) if os.path.isfile(path) else 0
    result = {
        "tool": "ai_poison",
        "file": os.path.basename(path),
        "ext": ext,
        "size": size,
        "findings": [],
        "verdict": "clean",
    }
    if ext in (".pkl", ".pickle", ".joblib"):
        try:
            with open(path, "rb") as fp:
                data = fp.read(min(size, 64 * 1024 * 1024))
            result["findings"] = _scan_pickle_bytes(data)
        except Exception as exc:
            result["findings"] = [{"type": "read_error", "note": str(exc)[:200]}]
    elif ext in (".pt", ".pth", ".ckpt", ".bin"):
        result["findings"] = _scan_pytorch_zip(path)
    elif ext == ".safetensors":
        result["findings"] = _scan_safetensors(path)
    elif ext == ".onnx":
        result["findings"] = _scan_onnx(path)
    elif ext in (".h5", ".hdf5", ".pb"):
        # 粗扫前 4MB
        try:
            with open(path, "rb") as fp:
                data = fp.read(4 * 1024 * 1024)
            result["findings"] = _scan_pickle_bytes(data)
        except Exception as exc:
            result["findings"] = [{"type": "read_error", "note": str(exc)[:200]}]
    else:
        result["findings"] = [{"type": "unsupported", "note": "扩展名 %s 不在 AI 模型投毒扫描范围" % ext}]

    # 综合判定
    high = [f for f in result["findings"] if f.get("severity") == "high"]
    if high:
        result["verdict"] = "malicious"
    elif result["findings"]:
        result["verdict"] = "suspicious"

    if outdir:
        try:
            os.makedirs(outdir, exist_ok=True)
            out = os.path.join(outdir, "ai_poison_report.json")
            with open(out, "w", encoding="utf-8") as fp:
                json.dump(result, fp, ensure_ascii=False, indent=2)
            result["report_path"] = out
        except Exception:
            pass
    return result


def is_ai_model_file(path: str) -> bool:
    ext = os.path.splitext(path)[1].lower()
    return ext in (".pkl", ".pickle", ".joblib", ".pt", ".pth", ".ckpt",
                   ".bin", ".safetensors", ".onnx", ".h5", ".hdf5", ".pb")
