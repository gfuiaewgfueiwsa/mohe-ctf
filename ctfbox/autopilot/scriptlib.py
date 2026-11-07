# -*- coding: utf-8 -*-
"""脚本库自动调用清单：只登记只读/离线脚本，参数模板由判型结果填充。

安全边界：
  - 不登记任何网络扫描、暴力破解、本地样本利用脚本；
  - 不运行 ret2text/format_string 等会执行样本的 Pwn 脚本；
  - web/ 目录下的 webshell 与扫描器保持人工使用，不自动执行；
  - 所有脚本只读取任务输入副本，输出定向到任务 artifacts。
"""
import os
import re
from dataclasses import dataclass, field
from typing import Callable, List, Tuple

# 依赖探测名（import 名）
@dataclass(frozen=True)
class ScriptSpec:
    id: str
    path: str                     # scripts/library 下相对路径
    direction: str
    description: str
    timeout: int = 60
    needs: Tuple[str, ...] = ()
    stage: str = ""
    build: Callable = None        # fn(ctx) -> list[str]；ctx 含 file/outdir/workdir/text

    def args(self, ctx) -> List[str]:
        if self.build is None:
            return [ctx["file"]]
        built = self.build(ctx)
        return [str(x) for x in built] if built else []


def _out(ctx, name):
    return os.path.join(ctx["workdir"], name)


def _small_text(ctx, limit=4000):
    return (ctx.get("text") or "")[:limit]


def _rsa_params(ctx):
    """从题面提取 n/e/c/p/q/d/dp/dq，写成脚本要求的 params.txt。"""
    text = ctx.get("text") or ""
    found = {}
    for mo in re.finditer(
            r"(?im)^\s*(n|e|c|p|q|d|dp|dq)\s*[:=]\s*(0x[0-9a-fA-F]+|\d+)", text):
        found[mo.group(1).lower()] = mo.group(2)
    if "n" not in found or "c" not in found:
        return None
    path = _out(ctx, "rsa_params.txt")
    with open(path, "w", encoding="utf-8") as fp:
        for key, value in found.items():
            fp.write("%s = %s\n" % (key, value))
    return path


def _jwt_token(ctx):
    found = re.search(r"\beyJ[\w-]{10,}\.[\w-]{10,}\.[\w-]{10,}", ctx.get("text") or "")
    return found.group(0) if found else ""


def _hash_value(ctx):
    compact = re.sub(r"\s+", "", ctx.get("text") or "")
    found = re.fullmatch(r"[A-Fa-f0-9]{32,128}", compact or "")
    return compact if found else ""


def _pixel_matrix(ctx):
    lines = [l.strip() for l in (ctx.get("text") or "").splitlines() if l.strip()]
    binary = [l for l in lines if re.fullmatch(r"[01]{8,}", l)]
    if len(binary) < 8:
        return None
    path = _out(ctx, "pixel_matrix.txt")
    with open(path, "w", encoding="utf-8") as fp:
        fp.write("\n".join(binary))
    return path


def _pixel_args(ctx):
    path = _pixel_matrix(ctx)
    return [path, "--cell", "10"] if path else None


def _rsa_script_args(ctx):
    params = _rsa_params(ctx)
    return ["--params", params] if params else None


def _registry_args(ctx):
    """单文件 hive 按文件名映射参数；SAM/SYSTEM 需成对，单文件时不硬跑。"""
    path = ctx["file"]
    base = os.path.basename(path).lower()
    if "ntuser" in base or base.startswith("usrclass"):
        return ["--ntuser", path]
    if base.startswith("software"):
        return ["--software", path, "--autoruns"]
    return None


REGISTRY = {
    # ---------------- Misc ----------------
    "strings_enhanced": ScriptSpec(
        "strings_enhanced", "misc/strings_enhanced.py", "misc",
        "ASCII/UTF-16LE/GBK strings + flag 高亮", 45, stage="strings",
        build=lambda c: [c["file"], "-n", "6", "--enc", "ascii,utf16,gbk",
                         "-o", _out(c, "strings.txt")]),
    "file_carver": ScriptSpec(
        "file_carver", "misc/file_carver.py", "misc",
        "按 magic 雕刻内嵌 ZIP/PNG/PDF/ELF 等", 90, stage="unknown",
        build=lambda c: [c["file"], "-o", _out(c, "carved")]),
    "entropy_map": ScriptSpec(
        "entropy_map", "misc/entropy_map.py", "misc",
        "分块熵图，定位加密/压缩数据段", 45, stage="unknown",
        build=lambda c: [c["file"], "--block", "4096",
                         "--csv", _out(c, "entropy.csv")]),
    "qrcode_decode": ScriptSpec(
        "qrcode_decode", "misc/qrcode_decode.py", "misc",
        "本地二维码/条形码识别（含旋转）", 40, needs=("cv2",), stage="image",
        build=lambda c: [c["file"]]),
    "gif_split_frames": ScriptSpec(
        "gif_split_frames", "misc/gif_split_frames.py", "misc",
        "GIF 帧拆分 + 帧差图", 60, needs=("numpy", "PIL"), stage="image",
        build=lambda c: [c["file"], "--dir", _out(c, "gif_frames")]),
    "lsb_stego_png": ScriptSpec(
        "lsb_stego_png", "misc/lsb_stego_png.py", "misc",
        "PNG/BMP LSB 位平面枚举提取", 90, needs=("PIL",), stage="image",
        build=lambda c: [c["file"]]),
    "exif_dump": ScriptSpec(
        "exif_dump", "misc/exif_dump.py", "misc",
        "EXIF/元数据完整导出", 30, needs=("PIL",), stage="image",
        build=lambda c: [c["file"]]),
    "png_ihdr_fix": ScriptSpec(
        "png_ihdr_fix", "misc/png_ihdr_fix.py", "misc",
        "PNG IHDR 宽高损坏修复", 60, stage="image",
        build=lambda c: [c["file"]]),
    "audio_spectrogram": ScriptSpec(
        "audio_spectrogram", "misc/audio_spectrogram.py", "misc",
        "音频语谱图/波形图（肉眼看 flag）", 90,
        needs=("numpy", "matplotlib", "PIL"), stage="audio",
        build=lambda c: [c["file"], "--out", _out(c, "spectrogram")]),
    "audio_lsb_wav": ScriptSpec(
        "audio_lsb_wav", "misc/audio_lsb_wav.py", "misc",
        "WAV 多位面 LSB 提取", 60, needs=("numpy",), stage="audio",
        build=lambda c: [c["file"]]),
    "pixel_matrix_qr": ScriptSpec(
        "pixel_matrix_qr", "misc/pixel_matrix_qr.py", "misc",
        "0/1 像素矩阵还原二维码", 45, stage="text",
        build=lambda c: _pixel_args(c)),
    "zero_width_stego": ScriptSpec(
        "zero_width_stego", "misc/zero_width_stego.py", "misc",
        "零宽字符隐写解码", 30, stage="text",
        build=lambda c: ["dec", "-f", c["file"]]),
    "docx_hidden_extract": ScriptSpec(
        "docx_hidden_extract", "misc/docx_hidden_extract.py", "misc",
        "Office 隐藏文字/批注/内嵌对象提取", 60, stage="document",
        build=lambda c: [c["file"], "-o", _out(c, "docx_hidden")]),
    "pdf_hidden_extract": ScriptSpec(
        "pdf_hidden_extract", "misc/pdf_hidden_extract.py", "misc",
        "PDF 隐藏图层/附件/JS/元数据提取", 60, stage="document",
        build=lambda c: [c["file"], "-o", _out(c, "pdf_hidden")]),
    "zip_crc_crack": ScriptSpec(
        "zip_crc_crack", "misc/zip_crc_crack.py", "misc",
        "加密 ZIP 小文件 CRC 碰撞还原", 120, stage="archive",
        build=lambda c: [c["file"], "--max", "6"]),

    # ---------------- Forensics ----------------
    "evtx_deep_parse": ScriptSpec(
        "evtx_deep_parse", "forensics/evtx_deep_parse.py", "forensics",
        "EVTX 事件解析/高危事件/CSV", 90, needs=("Evtx",), stage="forensic",
        build=lambda c: [c["file"], "--csv", _out(c, "evtx.csv")]),
    "pcap_http_extract": ScriptSpec(
        "pcap_http_extract", "forensics/pcap_http_extract.py", "forensics",
        "HTTP 流重组与对象提取", 120, needs=("scapy",), stage="capture",
        build=lambda c: [c["file"], "-o", _out(c, "http_objects")]),
    "pcap_dns_exfil": ScriptSpec(
        "pcap_dns_exfil", "forensics/pcap_dns_exfil.py", "forensics",
        "DNS 外带隧道还原", 60, needs=("scapy",), stage="capture",
        build=lambda c: [c["file"]]),
    "usb_hid_keylog": ScriptSpec(
        "usb_hid_keylog", "forensics/usb_hid_keylog.py", "forensics",
        "USB HID 键盘流量还原", 60, needs=("scapy",), stage="capture",
        build=lambda c: [c["file"]]),
    "registry_hive_parse": ScriptSpec(
        "registry_hive_parse", "forensics/registry_hive_parse.py", "forensics",
        "注册表 hive 自启/NTUSER 解析（SOFTWARE/NTUSER 单文件）", 90,
        needs=("Registry",), stage="forensic",
        build=_registry_args),

    # ---------------- Reverse / Pwn（只读） ----------------
    "pyc_magic_repair": ScriptSpec(
        "pyc_magic_repair", "reverse/pyc_magic_repair.py", "reverse",
        "pyc 魔数/头部修复", 45, stage="reverse",
        build=lambda c: [c["file"], "-o", _out(c, "fixed.pyc")]),
    "checksec_binary": ScriptSpec(
        "checksec_binary", "pwn/checksec_binary.py", "pwn",
        "ELF/PE 保护机制检查", 30, stage="pwn",
        build=lambda c: [c["file"], "--json", _out(c, "checksec.json")]),

    # ---------------- Crypto（输入为本文件/题面） ----------------
    "xor_repeating_key": ScriptSpec(
        "xor_repeating_key", "crypto/xor_repeating_key.py", "crypto",
        "重复密钥 XOR 自动破解", 45, stage="crypto",
        build=lambda c: [c["file"]]),
    "xor_single_byte": ScriptSpec(
        "xor_single_byte", "crypto/xor_single_byte.py", "crypto",
        "单字节 XOR 频率分析", 30, stage="crypto",
        build=lambda c: ["-f", c["file"], "--top", "8"]),
    "base_family_decode": ScriptSpec(
        "base_family_decode", "crypto/base_family_decode.py", "crypto",
        "Base16/32/58/85/91 链式解码", 45, stage="crypto",
        build=lambda c: ["-f", c["file"], "--depth", "8"]),
    "classical_crack": ScriptSpec(
        "classical_crack", "crypto/classical_crack.py", "crypto",
        "凯撒/仿射/栅栏等古典密码", 30, stage="crypto",
        build=lambda c: (["-s", _small_text(c)] if _small_text(c) else None)),
    "vigenere_crack": ScriptSpec(
        "vigenere_crack", "crypto/vigenere_crack.py", "crypto",
        "维吉尼亚自动破译", 45, stage="crypto",
        build=lambda c: ["-f", c["file"], "--maxlen", "20"]),
    "hash_identify": ScriptSpec(
        "hash_identify", "utils/hash_identify.py", "utils",
        "哈希类型识别", 20, stage="crypto",
        build=lambda c: (["--text", _hash_value(c)] if _hash_value(c) else None)),
    "jwt_crack": ScriptSpec(
        "jwt_crack", "crypto/jwt_crack.py", "crypto",
        "JWT 解码与弱密钥检查", 30, stage="crypto",
        build=lambda c: ([_jwt_token(c)] if _jwt_token(c) else None)),
    "rsa_all_in_one": ScriptSpec(
        "rsa_all_in_one", "crypto/rsa_all_in_one.py", "crypto",
        "RSA 常见攻击一键尝试", 90, stage="crypto",
        build=lambda c: _rsa_script_args(c)),
    "encode_decode_hub": ScriptSpec(
        "encode_decode_hub", "utils/encode_decode_hub.py", "utils",
        "自动识别并链式解码", 30, stage="text",
        build=lambda c: (["auto", _small_text(c, 2000)] if _small_text(c) else None)),
}


def library_root() -> str:
    """与 gui 的脚本库定位保持一致。"""
    try:
        from ..ui_scripts import library_root as _root
        return _root()
    except Exception:
        from ..common import APP_DIR
        return os.path.join(APP_DIR, "scripts", "library")


def get(script_id: str) -> ScriptSpec:
    return REGISTRY.get(script_id)


def script_path(spec: ScriptSpec) -> str:
    return os.path.join(library_root(), *spec.path.split("/"))


def select(script_ids) -> List[ScriptSpec]:
    out = []
    for sid in script_ids or []:
        spec = REGISTRY.get(sid)
        if spec and spec not in out:
            out.append(spec)
    return out


def describe() -> List[dict]:
    return [{"id": s.id, "direction": s.direction, "description": s.description,
             "needs": list(s.needs), "stage": s.stage}
            for s in REGISTRY.values()]
