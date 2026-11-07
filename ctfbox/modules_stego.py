# -*- coding: utf-8 -*-
"""杂项隐写与修复：零宽字符隐写、WAV 音频 LSB/频谱、损坏文件头修复。"""
import os
import re
import wave
import struct
from .common import Report, scan_flags, WORKSPACE

# ----------------------------------------------------------------------------
# 零宽 / 不可见字符隐写
# ----------------------------------------------------------------------------
# 码点 -> 索引（显式码点，避免源码中出现不可见字符）
ZW_ORDS = {0x200b: 0, 0x200c: 1, 0x200d: 2, 0x2060: 3, 0xfeff: 4,
           0x200e: 5, 0x200f: 6, 0x2028: 7, 0x2029: 8,
           0x2009: 9, 0x200a: 10, 0x00ad: 11}

def _bits_to_bytes(bits, msb=True):
    while len(bits) % 8:
        bits = bits[:len(bits) - len(bits) % 8]
    out = bytearray()
    for i in range(0, len(bits) - 7, 8):
        v = 0
        for j, b in enumerate(bits[i:i + 8]):
            if msb:
                v = (v << 1) | b
            else:
                v |= b << j
        out.append(v)
    return bytes(out)

def _printable_ratio(b):
    if not b:
        return 0.0
    ok = sum(1 for x in b if 9 <= x <= 13 or 32 <= x < 127)
    return ok / len(b)

def analyze_zero_width(text: str, report: Report):
    """检测文本中的零宽/不可见字符并按多种映射解码。"""
    vals = [ZW_ORDS[ord(c)] for c in text if ord(c) in ZW_ORDS]
    if len(vals) < 6:
        return
    report.add("ok", f"发现 {len(vals)} 个零宽/不可见字符", "疑似零宽隐写，尝试多方案解码…")
    candidates = []

    def consider(name, bits):
        if len(bits) < 8:
            return
        for msb in (True, False):
            b = _bits_to_bytes(list(bits), msb)
            if _printable_ratio(b[:64]) > 0.85:
                t = b.decode("utf-8", errors="replace")
                candidates.append((f"{name}/{'MSB' if msb else 'LSB'}", t))

    # 方案1：2bit，ZWSP/ZWNJ/ZWWJ/WJ = 0..3
    m2 = {0: 0, 1: 1, 2: 2, 3: 3}
    bits = []
    for v in vals:
        if v in m2:
            bits += [(m2[v] >> 1) & 1, m2[v] & 1]
    consider("四符号2bit", bits)
    # 方案2：单bit，ZWNJ=0/ZWJ=1（最常见的二值隐写）
    for zero, one in ((1, 2), (0, 1), (0, 2)):
        bits = []
        for v in vals:
            if v == zero:
                bits.append(0)
            elif v == one:
                bits.append(1)
        consider(f"二值({zero}/{one})", bits)
    # 方案3：3bit，前 8 个符号
    bits = []
    for v in vals:
        if v < 8:
            bits += [(v >> 2) & 1, (v >> 1) & 1, v & 1]
    consider("八符号3bit", bits)
    # 方案4：全部符号按出现顺序映射为索引宽度（4bit，覆盖16种）
    uniq = list(dict.fromkeys(vals))
    if len(uniq) <= 16:
        mp = {v: i for i, v in enumerate(uniq)}
        width = max(1, (len(uniq) - 1).bit_length())
        bits = []
        for v in vals:
            x = mp[v]
            bits += [(x >> (width - 1 - k)) & 1 for k in range(width)]
        consider(f"自适应{len(uniq)}符号{width}bit", bits)

    seen = set()
    for name, t in candidates:
        key = t[:50]
        if key in seen:
            continue
        seen.add(key)
        report.add("ok", f"零宽隐写解码({name})", t[:500])
        for fl in scan_flags(t.encode("utf-8", "ignore")):
            report.add("flag", "零宽隐写中发现 flag", fl)
    if not candidates:
        report.add("info", "零宽字符", "已检出不可见字符但未解出可读文本，可尝试在线零宽隐写工具(StegCloak)")

# ----------------------------------------------------------------------------
# WAV 音频分析
# ----------------------------------------------------------------------------
WAV_MAX_SAMPLES = 20_000_000   # LSB 参与样本数上限（防超大音频）

def analyze_wav(path: str, report: Report, outdir: str):
    try:
        import numpy as np
        from PIL import Image
    except Exception:
        report.add("warn", "缺少 numpy/Pillow，音频分析不可用", "")
        return
    try:
        wf = wave.open(path, "rb")
    except Exception as e:
        report.add("warn", "WAV 打开失败", str(e))
        return
    nch, sw, sr, nframes = wf.getnchannels(), wf.getsampwidth(), wf.getframerate(), wf.getnframes()
    dur = nframes / max(1, sr)
    raw = wf.readframes(nframes)
    wf.close()
    report.add("info", "WAV 音频信息",
               f"声道={nch} 采样率={sr}Hz 位深={sw*8}bit 帧数={nframes} 时长={dur:.2f}s")

    if sw == 1:                          # 8-bit PCM 是无符号
        arr = np.frombuffer(raw, dtype=np.uint8).astype(np.int16) - 128
    elif sw == 2:
        arr = np.frombuffer(raw, dtype="<i2")
    elif sw == 4:
        arr = np.frombuffer(raw, dtype="<i4")
    elif sw == 3:                        # 24-bit
        b = np.frombuffer(raw, dtype=np.uint8).reshape(-1, 3)
        arr = (b[:, 0].astype(np.int32) | (b[:, 1].astype(np.int32) << 8) |
               (b[:, 2].astype(np.int32) << 16))
        arr = np.where(arr & 0x800000, arr - 0x1000000, arr)
    else:
        report.add("warn", "非标准 PCM 位深", f"{sw*8}bit，跳过 LSB")
        arr = None

    if arr is not None:
        arr = arr[:WAV_MAX_SAMPLES]
        if nch > 1:
            arr = arr.reshape(-1, nch)
            planes = {("声道%d" % (i + 1)): arr[:, i] for i in range(nch)}
            planes["全部交错"] = arr.reshape(-1)
        else:
            planes = {"单声道": arr}
        hits = 0
        for pname, samples in planes.items():
            bits = (samples.astype(np.int64) & 1).tolist()
            for msb in (True, False):
                data = _bits_to_bytes(bits, msb)
                flags = scan_flags(data)
                head = data[:120]
                pr = _printable_ratio(head)
                if flags or (pr > 0.9 and re.search(rb"[A-Za-z0-9_ \{\}]{6,}", head)):
                    fp = os.path.join(outdir, f"wav_lsb_{pname}_{'MSB' if msb else 'LSB'}.bin")
                    with open(fp, "wb") as f:
                        f.write(data[:1024 * 1024])
                    report.add("ok", f"WAV LSB 提取({pname}/{'MSB' if msb else 'LSB'})",
                               f"预览: {head[:120]!r}\n已保存: {fp}")
                    for fl in flags:
                        report.add("flag", "WAV LSB 中发现 flag", fl)
                    hits += 1
        if not hits:
            report.add("info", "WAV LSB 隐写", "常见通道/位序未发现可读数据")

    # 频谱图（盲文/摩斯/频谱画字题肉眼查看）
    try:
        mono = arr.reshape(-1, nch).mean(axis=1) if (arr is not None and nch > 1) else arr
        if mono is not None:
            mono = mono.astype(np.float64)
            win, hop, nfft = 2048, 512, 2048
            frames = [mono[i:i + win] * np.hanning(win)
                      for i in range(0, max(1, len(mono) - win), hop)][:4096]
            if frames:
                spec = np.abs(np.fft.rfft(np.array(frames), n=nfft)) ** 0.35
                spec = spec / (spec.max() or 1)
                img = (np.flipud(spec.T[:600]) * 255).astype(np.uint8)
                img = np.stack([img] * 3, axis=-1)
                fp = os.path.join(outdir, "wav_spectrogram.png")
                Image.fromarray(img).save(fp)
                report.add("ok", "WAV 频谱图已生成", fp + "（频谱画字/盲文/摩斯题请肉眼查看）")
    except Exception as e:
        report.add("info", "频谱图生成跳过", str(e)[:100])

# ----------------------------------------------------------------------------
# 损坏文件头修复
# ----------------------------------------------------------------------------
# (magic, 类型, 扩展名)；按特异性排序
REPAIR_MAGICS = [
    (b"\x89PNG\r\n\x1a\n", "PNG图片", ".png"),
    (b"\xff\xd8\xff", "JPEG图片", ".jpg"),
    (b"GIF87a", "GIF图片", ".gif"),
    (b"GIF89a", "GIF图片", ".gif"),
    (b"%PDF", "PDF文档", ".pdf"),
    (b"Rar!\x1a\x07\x00", "RAR4压缩包", ".rar"),
    (b"Rar!\x1a\x07\x01\x00", "RAR5压缩包", ".rar"),
    (b"7z\xbc\xaf\x27\x1c", "7z压缩包", ".7z"),
    (b"PK\x03\x04", "ZIP压缩包", ".zip"),
    (b"\x1f\x8b\x08", "GZIP", ".gz"),
    (b"BZh", "BZIP2", ".bz2"),
    (b"\xfd7zXZ\x00", "XZ", ".xz"),
    (b"\x7fELF", "ELF可执行文件", ".elf"),
    (b"MZ", "PE可执行文件", ".exe"),
    (b"SQLite format 3\x00", "SQLite数据库", ".sqlite"),
    (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "OLE复合文档", ".doc"),
    (b"ID3", "MP3音频", ".mp3"),
    (b"OggS", "OGG", ".ogg"),
    (b"fLaC", "FLAC音频", ".flac"),
    (b"RIFF", "RIFF容器", ".riff"),
]
SEARCH_WINDOW = 65536     # 在前 64KB 内寻找被垃圾字节推后 的 magic

def repair_file(path: str, report: Report, outdir: str) -> bool:
    """修复被加垃圾头 / magic 被改 / ZIP 伪加密的文件，输出修复副本（不改原文件）。
    返回是否产生了修复文件。"""
    with open(path, "rb") as f:
        data = f.read()
    if not data:
        return False
    base = os.path.basename(path)
    os.makedirs(outdir, exist_ok=True)

    # 1) magic 被整体推后（前面被塞垃圾字节）
    best = None
    for magic, name, ext in REPAIR_MAGICS:
        idx = data.find(magic, 1, SEARCH_WINDOW)
        if idx > 0 and (best is None or idx < best[0]):
            best = (idx, magic, name, ext)
    if best:
        idx, magic, name, ext = best
        fp = os.path.join(outdir, "repaired_" + os.path.splitext(base)[0] + ext)
        with open(fp, "wb") as f:
            f.write(data[idx:])
        report.add("ok", f"文件头被插入 {idx} 字节垃圾数据，已去除", f"识别为 {name}，修复文件: {fp}")
        report.extracted.append(fp)
        for fl in scan_flags(data[idx:idx + 4 * 1024 * 1024]):
            report.add("flag", "修复后文件中发现 flag", fl)
        return True

    # 2) magic 在 0 偏移但被篡改：按扩展名推断并覆盖
    ext = os.path.splitext(path)[1].lower()
    for magic, name, mext in REPAIR_MAGICS:
        if ext == mext and not data.startswith(magic):
            fixed = magic + data[len(magic):]
            fp = os.path.join(outdir, "repaired_" + base)
            with open(fp, "wb") as f:
                f.write(fixed)
            report.add("ok", f"文件头 magic 损坏，已按 .{mext} 修复", f"应为 {name}，修复文件: {fp}")
            report.extracted.append(fp)
            return True

    # 3) ZIP 伪加密：通用位标志被置 0x0001（本地头/中央目录）
    if data[:2] in (b"PK\x03\x04",) or b"PK\x01\x02" in data[:SEARCH_WINDOW]:
        fixed = _fix_fake_zip_encryption(data)
        if fixed is not None:
            fp = os.path.join(outdir, "repaired_" + os.path.splitext(base)[0] + ".zip")
            with open(fp, "wb") as f:
                f.write(fixed)
            report.add("ok", "检测到 ZIP/RAR 伪加密标志，已清除", f"修复文件: {fp}")
            report.extracted.append(fp)
            return True
    return False

def _fix_fake_zip_encryption(data: bytes):
    """把 ZIP 本地文件头与中央目录的加密通用位(bit0)清零（仅当无真实加密数据特征时）。"""
    out = bytearray(data)
    changed = False
    # 中央目录头 PK\x01\x02，通用位标志偏移 +8，2字节
    i = 0
    while True:
        j = out.find(b"PK\x01\x02", i)
        if j < 0:
            break
        flag_off = j + 8
        if flag_off + 2 <= len(out):
            flag = struct.unpack_from("<H", out, flag_off)[0]
            if flag & 1:
                struct.pack_into("<H", out, flag_off, flag & ~1)
                changed = True
        i = j + 4
    # 本地头 PK\x03\x04，通用位标志偏移 +6
    i = 0
    while True:
        j = out.find(b"PK\x03\x04", i)
        if j < 0:
            break
        flag_off = j + 6
        if flag_off + 2 <= len(out):
            flag = struct.unpack_from("<H", out, flag_off)[0]
            if flag & 1:
                struct.pack_into("<H", out, flag_off, flag & ~1)
                changed = True
        i = j + 4
    return bytes(out) if changed else None

# ----------------------------------------------------------------------------
# cloacked-pixel：AES-CBC(32字节分组) + RGB LSB(MSB序) 的密码隐写
# ----------------------------------------------------------------------------
CLOACKED_MAGIC = (b"PK\x03\x04", b"\x89PNG", b"\xff\xd8\xff", b"%PDF", b"Rar!",
                  b"7z\xbc\xaf\x27\x1c", b"\x1f\x8b", b"GIF8", b"BM")


def _cloacked_bits(path):
    try:
        import numpy as np
        from PIL import Image
    except Exception:
        return b""
    try:
        img = Image.open(path).convert("RGB")
        arr = np.asarray(img, dtype=np.uint8)
    except Exception:
        return b""
    vals = arr.reshape(-1) & 1
    n = (vals.size // 8) * 8
    if not n:
        return b""
    words = (1 << np.arange(7, -1, -1)).astype(np.uint32)
    return (vals[:n].reshape(-1, 8).astype(np.uint32) * words).sum(axis=1) \
        .astype(np.uint8).tobytes()


def _pkcs7_ok(data, block=32):
    if not data:
        return False
    n = data[-1]
    return 1 <= n <= block and data[-n:] == bytes([n]) * n


def _cloacked_score(plain):
    from .common import scan_flags
    flags = scan_flags(plain, strong_only=True)
    if flags:
        return "flag", flags
    if any(plain.startswith(m) for m in CLOACKED_MAGIC):
        return "file", []
    if len(plain) >= 8 and _printable_ratio(plain[:4096]) > 0.85:
        return "text", []
    return "", []


def cloacked_extract(path, passwords=None, outdir=""):
    """尝试用候选口令解 cloacked-pixel。返回 dict（ok/password/data/kind/flags）。"""
    from . import modules_zipcrack as zipcrack
    blob = _cloacked_bits(path)
    if len(blob) < 36:
        return {"ok": False, "reason": "LSB 数据不足"}
    length = struct.unpack_from("<i", blob, 0)[0]
    # cloacked-pixel 的数据 = 16 字节 IV + 32 字节分组密文
    if length < 32 or length % 16 or length > len(blob) - 4:
        return {"ok": False, "reason": "未发现 cloacked-pixel 长度头"}
    ciphertext = blob[4:4 + length]
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    except Exception:
        return {"ok": False, "reason": "缺少 cryptography，无法解 AES-CBC"}
    import hashlib
    words = passwords if passwords is not None else zipcrack.password_candidates(path)
    tried = 0
    for word in words:
        for raw in zipcrack.password_bytes(word):
            tried += 1
            key = hashlib.sha256(raw).digest()
            try:
                dec = Cipher(algorithms.AES(key), modes.CBC(ciphertext[:16])).decryptor()
                plain = dec.update(ciphertext[16:]) + dec.finalize()
            except Exception:
                continue
            if not _pkcs7_ok(plain):
                continue
            body = plain[:-plain[-1]]
            kind, flags = _cloacked_score(body)
            if not kind:
                continue
            out_path = ""
            if outdir:
                os.makedirs(outdir, exist_ok=True)
                out_path = os.path.join(outdir, "cloacked_%s.bin" % re.sub(
                    r"[^0-9A-Za-z_.-]", "_", str(word))[:40])
                with open(out_path, "wb") as fp:
                    fp.write(body)
            return {"ok": True, "password": word, "data": body, "kind": kind,
                    "flags": flags, "tried": tried, "out_path": out_path,
                    "length": length}
    return {"ok": False, "reason": "候选口令未命中", "tried": tried,
            "length": length}


def analyze_cloacked(path, report, outdir, passwords=None):
    res = cloacked_extract(path, passwords=passwords, outdir=outdir)
    if res.get("ok"):
        preview = res["data"][:300].decode("utf-8", "replace")
        report.add("ok", "cloacked-pixel 解密成功（口令 %r）" % res.get("password"),
                   "类型=%s\n预览: %r\n已保存: %s" % (
                       res.get("kind"), preview, res.get("out_path") or "-"))
        for flag in res.get("flags") or []:
            report.add("flag", "cloacked-pixel 中发现 flag", flag)
        if res.get("out_path"):
            report.extracted.append(res["out_path"])
    elif "长度头" not in res.get("reason", ""):
        report.add("info", "cloacked-pixel", res.get("reason", "未命中"))
    return res
