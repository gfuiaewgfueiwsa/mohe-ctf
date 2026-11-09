# -*- coding: utf-8 -*-
"""图片隐写分析：EXIF / PNG块 / LSB / GIF帧 / 二维码 / 尺寸CRC修复 / 附加数据 / 频谱。"""
import os
import io
import re
import zlib
import struct
import binascii
from .common import Finding, Report, scan_flags, extract_strings, WORKSPACE, shannon_entropy

try:
    from PIL import Image, ImageSequence
    import numpy as np
except Exception:
    Image = None

PNG_SIG = b"\x89PNG\r\n\x1a\n"

# ----------------------------------------------------------------------------
# 入口
# ----------------------------------------------------------------------------
def analyze(path, report: Report, passwords=None):
    if Image is None:
        report.add("warn", "Pillow/numpy 未安装，图片分析不可用")
        return
    try:
        img = Image.open(path)
    except Exception as e:
        # v4.0.4：PNG 宽高被改坏导致无法打开 → IHDR CRC 爆破修复后重开（经典"图片宽高"题）
        img = None
        if path.lower().endswith(".png"):
            try:
                with open(path, "rb") as _f:
                    _raw0 = _f.read()
                _pos = _raw0.find(b"IHDR") - 4
                if _pos >= 0:
                    _fixed = _fix_ihdr_crc(_raw0, _pos)
                    if _fixed:
                        _od = os.path.join(
                            WORKSPACE, "image_" + os.path.basename(path).replace(".", "_"))
                        os.makedirs(_od, exist_ok=True)
                        _fp = os.path.join(_od, "fixed_" + os.path.basename(path))
                        with open(_fp, "wb") as _f2:
                            _f2.write(_fixed)
                        report.add("ok", "PNG 宽高被改：IHDR CRC 爆破修复成功",
                                   _fp + "（按修复副本继续分析）", _fp)
                        report.extracted.append(_fp)
                        img = Image.open(_fp)
                        path = _fp
            except Exception:
                img = None
        if img is None:
            report.add("warn", "图片无法打开", str(e))
            return

    with open(path, "rb") as f:
        raw = f.read()

    outdir = os.path.join(WORKSPACE, "image_" + os.path.basename(path).replace(".", "_"))
    os.makedirs(outdir, exist_ok=True)

    report.add("info", "图片基本信息",
               f"格式={img.format} 尺寸={img.width}x{img.height} 模式={img.mode} 帧数={getattr(img, 'n_frames', 1)}")

    _exif(img, report, outdir)
    if img.format == "PNG":
        _png_chunks(raw, report, path, outdir, img)
    if img.format in ("JPEG", "MPO"):
        _jpeg_segments(raw, report, outdir)
        _ela(path, raw, report, outdir)
    if img.format == "GIF":
        _gif_frames(img, report, outdir)
    _lsb(img, report, outdir)
    try:
        from .modules_stego import analyze_cloacked
        analyze_cloacked(path, report, outdir, passwords=passwords)
    except Exception:
        pass
    _qr(raw, report, outdir, img)
    _appended(raw, img.format, report, outdir)
    _fft(img, report, outdir)
    _extra_visuals(img, report, outdir)

# ----------------------------------------------------------------------------
# EXIF
# ----------------------------------------------------------------------------
def _exif(img, report, outdir=None):
    try:
        exif = img.getexif()
    except Exception:
        exif = None
    # EXIF 内嵌缩略图（常被忽略的藏身处）
    try:
        blob = exif.tobytes() if exif else b""
        m = re.search(rb"\xff\xd8.+?\xff\xd9", blob, re.S)
        if m and m.group(0).count(b"\xff\xd8") >= 1 and len(m.group(0)) > 200:
            tp = os.path.join(outdir or ".", "exif_thumb.jpg")
            os.makedirs(os.path.dirname(tp), exist_ok=True)
            with open(tp, "wb") as f:
                f.write(m.group(0))
            report.add("ok", "EXIF 内嵌缩略图", tp + "（将递归分析，缩略图可能与主图不同）", tp)
            report.extracted.append(tp)
    except Exception:
        pass
    if not exif:
        report.add("info", "EXIF", "无 EXIF 数据")
        return
    from PIL.ExifTags import TAGS, GPSTAGS
    lines = []
    gps = {}
    for tag_id, val in exif.items():
        name = TAGS.get(tag_id, tag_id)
        if name == "GPSInfo":
            for gid, gv in val.items():
                gps[GPSTAGS.get(gid, gid)] = gv
            continue
        lines.append(f"{name}: {val}")
    if gps:
        lines.append("GPSInfo: " + "; ".join(f"{k}={v}" for k, v in gps.items()))
    if lines:
        report.add("ok", "EXIF 元数据", "\n".join(str(x) for x in lines))
        joined = "\n".join(lines)
        for fl in scan_flags(joined.encode("utf-8", "ignore")):
            report.add("flag", "EXIF 中发现 flag", fl)
        # v4.0.4：UTF-16 编码的 EXIF 字段（XPComment/XPTitle/XPAuthor 等常藏 flag）。
        # repr 里表现为大量 \x00，先去掉字面转义再扫；同时按 bytes 原值做 UTF-16 解码。
        for fl in scan_flags(re.sub(r"\\x00", "", joined).encode("utf-8", "ignore")):
            report.add("flag", "EXIF 中发现 flag(UTF-16)", fl)
        for _tid, _val in exif.items():
            if not isinstance(_val, bytes) or len(_val) < 6:
                continue
            for _enc in ("utf-16-le", "utf-16-be", "utf-8"):
                try:
                    _t = _val.decode(_enc, errors="ignore")
                except Exception:
                    continue
                for fl in scan_flags(_t.encode("utf-8", "ignore")):
                    report.add("flag", "EXIF 字段中发现 flag", fl)
    # PIL 注释
    try:
        info = img.info
        for k, v in info.items():
            if isinstance(v, str) and len(v) > 1:
                report.add("info", f"图片info字段 {k}", v[:500])
                for fl in scan_flags(v.encode("utf-8", "ignore")):
                    report.add("flag", f"info[{k}] 中发现 flag", fl)
    except Exception:
        pass

# ----------------------------------------------------------------------------
# PNG chunk 分析 + IHDR CRC 修复（改宽高经典题）
# ----------------------------------------------------------------------------
def _png_chunks(raw, report, path, outdir, img):
    if not raw.startswith(PNG_SIG):
        return
    pos = len(PNG_SIG)
    chunks = []
    text_chunks = []
    custom_chunks = []
    STD_CHUNKS = {b"IHDR", b"PLTE", b"IDAT", b"IEND", b"tRNS", b"cHRM", b"gAMA",
                  b"iCCP", b"sBIT", b"sRGB", b"tEXt", b"zTXt", b"iTXt", b"bKGD",
                  b"hIST", b"pHYs", b"sPLT", b"tIME", b"acTL", b"fcTL", b"fdAT",
                  b"eXIf", b"vpAg", b"vp8 ", b"vp8x", b"ANIM", b"ANMF"}
    idat = 0
    end_pos = None
    while pos + 8 <= len(raw):
        length = struct.unpack(">I", raw[pos:pos + 4])[0]
        ctype = raw[pos + 4:pos + 8]
        data = raw[pos + 8:pos + 8 + length]
        crc_stored = raw[pos + 8 + length:pos + 12 + length]
        crc_calc = struct.pack(">I", binascii.crc32(ctype + data) & 0xffffffff)
        ok = crc_stored == crc_calc
        chunks.append((ctype, length, ok))
        if ctype == b"IDAT":
            idat += 1
        if ctype in (b"tEXt", b"zTXt", b"iTXt"):
            try:
                if ctype == b"zTXt":
                    k, rest = data.split(b"\x00", 1)
                    txt = k.decode("latin-1") + ": " + zlib.decompress(rest[1:]).decode("latin-1", "replace")
                elif ctype == b"iTXt":
                    txt = data.decode("latin-1", "replace")
                else:
                    txt = data.decode("latin-1", "replace")
                text_chunks.append(txt)
            except Exception:
                text_chunks.append(data.decode("latin-1", "replace"))
        # 非标准自定义块（CTF 常直接新建一个块塞 flag/文件）
        if ctype not in STD_CHUNKS:
            custom_chunks.append((ctype, data))
        if ctype == b"IHDR":
            w, h = struct.unpack(">II", data[:8])
            if not ok:
                report.add("warn", "IHDR CRC 校验失败", "宽高可能被篡改，尝试暴力还原…")
                fixed = _fix_ihdr_crc(raw, pos)
                if fixed:
                    fp = os.path.join(outdir, "fixed_ihdr.png")
                    with open(fp, "wb") as f:
                        f.write(fixed)
                    report.add("ok", "IHDR 宽高已还原", f"修复文件: {fp}")
                    for fl in scan_flags(fixed):
                        report.add("flag", "修复后图片中发现 flag", fl)
        if ctype == b"IEND":
            end_pos = pos + 12 + length
            break
        pos += 12 + length

    report.add("info", "PNG 块结构",
               f"共{len(chunks)}块, IDAT={idat}, " +
               ", ".join(f"{t.decode('latin-1')}({'OK' if ok else 'CRC错'},{l})" for t, l, ok in chunks[:20]))
    bad = [c for c in chunks if not c[2]]
    if bad:
        report.add("warn", "存在 CRC 错误的块", ", ".join(c[0].decode("latin-1", "?") for c in bad))
    if text_chunks:
        joined = "\n".join(text_chunks)
        report.add("ok", "PNG 文本块(tEXt/zTXt/iTXt)", joined[:2000])
        for fl in scan_flags(joined.encode("latin-1", "ignore")):
            report.add("flag", "PNG 文本块中发现 flag", fl)
    if custom_chunks:
        for ctype, cdata in custom_chunks[:10]:
            tname = ctype.decode("latin-1", "replace")
            txt = cdata.decode("latin-1", "replace")
            printable = sum(1 for b in cdata[:200] if 9 <= b <= 13 or 32 <= b < 127) / max(1, min(len(cdata), 200))
            report.add("ok", f"PNG 自定义块 {tname}（{len(cdata)} 字节）",
                       txt[:500] if printable > 0.8 else f"二进制数据，已落盘（{len(cdata)} 字节）")
            cp = os.path.join(outdir, f"png_chunk_{safe_chunk(tname)}.bin")
            with open(cp, "wb") as f:
                f.write(cdata)
            report.extracted.append(cp)   # 自定义块递归雕刻/解码
            for fl in scan_flags(cdata[:2 * 1024 * 1024]):
                report.add("flag", f"PNG 块 {tname} 中发现 flag", fl)
    return end_pos


def safe_chunk(name):
    return re.sub(r"[^A-Za-z0-9_]", "_", name)[:16] or "x"

def _fix_ihdr_crc(raw, ihdr_pos):
    """枚举宽/高，找到 CRC 正确的组合并返回修复后的 PNG。"""
    data_start = ihdr_pos + 8
    orig = raw[data_start:data_start + 13]
    bitdepth = orig[8:]
    # 优先只改高度（最常见），再宽高都枚举到 4096
    for h in range(1, 4097):
        nd = struct.pack(">II", struct.unpack(">I", orig[0:4])[0], h) + bitdepth
        crc = binascii.crc32(b"IHDR" + nd) & 0xffffffff
        if crc == struct.unpack(">I", raw[ihdr_pos + 21:ihdr_pos + 25])[0]:
            return raw[:data_start] + nd + raw[data_start + 13:]
    w0 = struct.unpack(">I", orig[0:4])[0]
    for w in range(1, 4097):
        for h in range(1, 4097):
            nd = struct.pack(">II", w, h) + bitdepth
            crc = binascii.crc32(b"IHDR" + nd) & 0xffffffff
            if crc == struct.unpack(">I", raw[ihdr_pos + 21:ihdr_pos + 25])[0]:
                return raw[:data_start] + nd + raw[data_start + 13:]
    return None

# ----------------------------------------------------------------------------
# JPEG 段 / 注释 / FFD9 后附加
# ----------------------------------------------------------------------------
def _jpeg_segments(raw, report, outdir):
    """遍历 JPEG 所有标记段，提取 COM 注释与 APPn（EXIF/XMP/ICC/Photoshop）文本。"""
    APP_NAMES = {0xE0: "APP0/JFIF", 0xE1: "APP1(EXIF/XMP)", 0xE2: "APP2(ICC/MPF)",
                 0xED: "APP13(Photoshop/IPTC)", 0xE1 | 0: "APP1"}
    i, texts, app_blobs = 2 if raw[:2] == b"\xff\xd8" else 0, [], []
    n = len(raw)
    while i < n - 4:
        if raw[i] != 0xFF:
            i += 1
            continue
        # 跳过填充 0xFF
        j = i
        while j < n and raw[j] == 0xFF:
            j += 1
        if j >= n:
            break
        marker = raw[j]
        head = j + 1
        if marker in (0xD8, 0xD9) or 0xD0 <= marker <= 0xD7:
            i = head
            continue
        if head + 2 > n:
            break
        ln = struct.unpack(">H", raw[head:head + 2])[0]
        body = raw[head + 2:head + ln] if ln >= 2 else b""
        if marker == 0xFE:
            texts.append(body.decode("latin-1", "replace"))
        elif 0xE0 <= marker <= 0xEF:
            txt = body.decode("latin-1", "replace")
            # 只保留含可打印线索的段，过滤纯二进制 EXIF
            printable = sum(1 for c in body[:400] if 9 <= c <= 13 or 32 <= c < 127) / max(1, min(len(body), 400))
            if printable > 0.85 and re.search(r"[A-Za-z0-9_{}]{6,}", txt):
                app_blobs.append((APP_NAMES.get(marker, f"APP{marker - 0xE0}"), txt))
        if marker == 0xDA:   # SOS，之后是扫描数据，停止段遍历
            break
        i = head + ln if ln > 2 else head
    if texts:
        report.add("ok", "JPEG COM 注释段", "\n".join(texts)[:2000])
        for fl in scan_flags("\n".join(texts).encode("latin-1")):
            report.add("flag", "JPEG 注释中发现 flag", fl)
    for name, txt in app_blobs:
        report.add("ok", f"JPEG {name} 段文本", txt[:1500])
        for fl in scan_flags(txt.encode("latin-1", "ignore")):
            report.add("flag", f"JPEG {name} 中发现 flag", fl)


def _ela(path, raw, report, outdir):
    """JPEG 误差水平分析(ELA)：重存固定质量后与原图求差，高亮篡改/拼贴区域。"""
    try:
        import cv2
        orig = cv2.imdecode(np.frombuffer(raw, np.uint8), cv2.IMREAD_COLOR)
        if orig is None:
            return
        tmp = os.path.join(outdir, "_ela_resave.jpg")
        cv2.imwrite(tmp, orig, [cv2.IMWRITE_JPEG_QUALITY, 90])
        re = cv2.imread(tmp)
        if re is None or re.shape != orig.shape:
            return
        diff = cv2.absdiff(orig, re)
        gray = cv2.cvtColor(diff, cv2.COLOR_BGR2GRAY)
        m = max(1.0, float(gray.max()))
        heat = cv2.applyColorMap(np.clip(gray.astype(np.float32) / m * 255, 0, 255).astype(np.uint8),
                                 cv2.COLORMAP_JET)
        fp = os.path.join(outdir, "jpeg_ela.png")
        cv2.imwrite(fp, heat)
        hi = float(np.mean(np.sort(gray.ravel())[-max(1, gray.size // 1000):]))
        report.add("info", "JPEG ELA 误差分析图",
                   fp + f"（异常高亮区域可能是二次压缩/PS 拼贴；高误差均值 {hi:.1f}）")
    except Exception:
        pass

def _appended(raw, fmt, report, outdir):
    tail = None
    if fmt == "PNG":
        idx = raw.rfind(b"IEND")
        if idx != -1 and idx + 8 < len(raw):
            tail = raw[idx + 8:]
    elif fmt == "JPEG":
        idx = raw.rfind(b"\xff\xd9")
        if idx != -1 and idx + 2 < len(raw):
            tail = raw[idx + 2:]
    elif fmt == "GIF":
        idx = raw.rfind(b"\x3b")
        if idx != -1 and idx + 1 < len(raw):
            tail = raw[idx + 1:]
    if tail and len(tail.strip(b"\x00")) > 4:
        fp = os.path.join(outdir, "appended_data.bin")
        with open(fp, "wb") as f:
            f.write(tail)
        report.add("ok", f"{fmt} 结束标记后存在附加数据", f"{len(tail)} 字节，已保存: {fp}（将递归分析）", tail)
        report.extracted.append(fp)
        for fl in scan_flags(tail):
            report.add("flag", "附加数据中发现 flag", fl)
        # v4.0.4：UTF-16 编码的附加数据（截图/记事本文本常为 UTF-16LE）
        for _enc in ("utf-16-le", "utf-16-be"):
            try:
                _t = tail.decode(_enc, errors="ignore")
            except Exception:
                continue
            for fl in scan_flags(_t.encode("utf-8", "ignore")):
                report.add("flag", "附加数据中发现 flag(UTF-16)", fl)
        # v4.0.4：附加数据是压缩包（"图种"经典题：图片尾部拼接 ZIP）→ 直接解包扫成员 flag
        if tail[:2] == b"PK" or tail[:4] == b"Rar!" or tail[:6] == b"7z\xbc\xaf\x27\x1c":
            try:
                import io as _io
                import zipfile as _zf
                with _zf.ZipFile(_io.BytesIO(tail)) as _z:
                    for _nm in _z.namelist()[:30]:
                        try:
                            _data = _z.read(_nm)
                        except Exception:
                            continue
                        for fl in scan_flags(_data):
                            report.add("flag", "图种内嵌压缩包成员 %s 中发现 flag" % _nm, fl)
                        for _enc in ("utf-16-le", "utf-16-be"):
                            try:
                                _t = _data.decode(_enc, errors="ignore")
                            except Exception:
                                continue
                            for fl in scan_flags(_t.encode("utf-8", "ignore")):
                                report.add("flag", "图种内嵌压缩包成员 %s 中发现 flag" % _nm, fl)
                report.add("ok", "图种内嵌压缩包", "已解出成员并扫描 flag（%d 个成员）" % len(_z.namelist()))
            except Exception as _e:
                report.add("info", "图种内嵌压缩包", "尝试解包失败：%s" % _e)

# ----------------------------------------------------------------------------
# GIF 帧拆分
# ----------------------------------------------------------------------------
def _gif_frames(img, report, outdir):
    n = getattr(img, "n_frames", 1)
    if n <= 1:
        return
    saved = []
    for i, frame in enumerate(ImageSequence.Iterator(img)):
        fp = os.path.join(outdir, f"frame_{i:03d}.png")
        frame.convert("RGBA").save(fp)
        saved.append(fp)
    report.add("ok", f"GIF 共 {n} 帧，已全部拆分", outdir)
    report.extracted.extend(saved[:50])  # 防爆炸，递归分析前50帧
    # 帧差异
    try:
        arrs = [np.array(f.convert("RGBA")) for f in ImageSequence.Iterator(img)]
        diffs = []
        for i in range(1, len(arrs)):
            d = np.abs(arrs[i].astype(int) - arrs[0].astype(int)).sum()
            diffs.append(d)
        if diffs and max(diffs) > 0:
            mi = int(np.argmax(diffs)) + 1
            report.add("info", "帧差异", f"与首帧差异最大的是第 {mi} 帧（差异和 {diffs[mi-1]}），重点检查")
    except Exception:
        pass

# ----------------------------------------------------------------------------
# LSB 隐写（多通道/多比特序自动尝试）
# ----------------------------------------------------------------------------
def _bits_to_bytes(bits, msb_first=True):
    # numpy 向量化，避免百万级样本逐比特 Python 循环
    a = np.asarray(bits, dtype=np.uint8).reshape(-1)
    n = (a.size // 8) * 8
    if not n:
        return b""
    a = a[:n].reshape(-1, 8)
    if msb_first:
        w = (1 << np.arange(7, -1, -1)).astype(np.uint32)
    else:
        w = (1 << np.arange(0, 8)).astype(np.uint32)
    return (a.astype(np.uint32) * w).sum(axis=1, dtype=np.uint32).astype(np.uint8).tobytes()

LSB_MAX_PIXELS = 6_000_000   # 大图 LSB 只分析左上区域，避免内存/耗时爆炸

def _lsb(img, report, outdir):
    try:
        rgba = img.convert("RGBA")
        arr = np.array(rgba)
    except Exception as e:
        return
    h, w, _ = arr.shape
    if h * w > LSB_MAX_PIXELS:
        crop_h = min(h, int(LSB_MAX_PIXELS / w) + 1)   # 不能缩放（插值破坏低位），裁剪左上区域
        arr = arr[:crop_h, :, :]
        report.add("info", "LSB 大图裁剪", f"原图 {w}x{h} 像素过多，仅分析左上 {w}x{crop_h} 区域")
        h, w, _ = arr.shape
    R, G, B, A = arr[:, :, 0], arr[:, :, 1], arr[:, :, 2], arr[:, :, 3]
    # (名称, 一维样本序列)；覆盖单通道/平面拼接/像素交错/列优先/逆序
    combos = {
        "R": [R.flatten()], "G": [G.flatten()], "B": [B.flatten()],
        "RGB平面": [R.flatten(), G.flatten(), B.flatten()],
        "BGR平面": [B.flatten(), G.flatten(), R.flatten()],
        "RGBA平面": [R.flatten(), G.flatten(), B.flatten(), A.flatten()],
        "RGB交错": [arr[:, :, 0:3].reshape(-1)],
        "RGBA交错": [arr.reshape(-1)],
        "BGR交错": [arr[:, :, [2, 1, 0]].reshape(-1)],
        "RGB列优先": [arr[:, :, 0:3].transpose(1, 0, 2).reshape(-1)],
        "RGB逆序": [arr[:, :, 0:3].reshape(-1)[::-1]],
    }
    try:
        from .modules_audio import MAGIC_HEADERS
    except Exception:
        MAGIC_HEADERS = ()
    hits = []
    seen_head = set()
    for name, chans in combos.items():
        vals = np.concatenate(chans)
        # bit0 全排列 × MSB/LSB；bit1/bit2 只跑高命中组合控制开销
        bit_jobs = [0] if name not in ("R", "G", "B", "RGB平面", "RGB交错") else [0, 1, 2]
        for bit in bit_jobs:
            bits = ((vals.astype(np.int64) >> bit) & 1).astype(np.uint8)
            for msb in (True, False):
                data = _bits_to_bytes(bits, msb)
                if not data:
                    continue
                flags = scan_flags(data[:2 * 1024 * 1024])
                head = data[:200]
                printable = sum(1 for b in head if 9 <= b <= 13 or 32 <= b < 127) / max(1, len(head))
                magic_hit = next(((m, nm, ext) for m, nm, ext in MAGIC_HEADERS
                                  if head.startswith(m) or data[:2048].find(m) >= 0), None)
                is_text = printable > 0.85 and re.search(rb"[A-Za-z0-9_ \{\}]{8,}", head)
                if flags or magic_hit or is_text:
                    key = data[:64]
                    if key in seen_head:
                        continue
                    seen_head.add(key)
                    hits.append((name, bit, "MSB" if msb else "LSB", flags, magic_hit, data))
    for name, bit, order, flags, magic_hit, data in hits:
        tag = f"{name}_b{bit}_{order}"
        fp = os.path.join(outdir, f"lsb_{tag}.bin")
        with open(fp, "wb") as f:
            f.write(data[: max(2 * 1024 * 1024, len(data))])
        preview = data[:300].decode("latin-1", "replace").replace("\x00", "")
        kinds = []
        if flags:
            kinds.append("flag")
        if magic_hit:
            kinds.append(magic_hit[1])
        if not kinds:
            kinds.append("可读文本")
        report.add("ok", f"LSB 低位提取 {name} 第{bit}位/{order}序 [{','.join(kinds)}]",
                   f"预览: {preview!r}\n已保存: {fp}")
        for fl in flags:
            report.add("flag", f"LSB({name}/b{bit}/{order}) 中发现 flag", fl)
        # 命中文件头：雕刻成对应文件并登记递归
        if magic_hit:
            magic, mname, ext = magic_hit
            off = data.find(magic)
            if off < 0:
                off = 0
            mp = os.path.join(outdir, f"lsb_payload_{tag}{ext}")
            with open(mp, "wb") as f:
                f.write(data[off:off + 16 * 1024 * 1024])
            report.add("ok", f"LSB 中雕刻出 {mname}", mp)
            report.extracted.append(mp)
    if not hits:
        report.add("info", "LSB 隐写", "常见通道/位面/排列未发现可读数据")

    # 低位平面放大图（肉眼题）
    try:
        for ci, cname in enumerate("RGB"):
            plane = ((arr[:, :, ci] & 1) * 255).astype("uint8")
            Image.fromarray(plane).save(os.path.join(outdir, f"bitplane_{cname}.png"))
        report.add("info", "低位平面图已生成", os.path.join(outdir, "bitplane_*.png") + "（肉眼题请查看黑白图）")
    except Exception:
        pass

# ----------------------------------------------------------------------------
# 二维码识别（原图/灰度/二值化/放大/GIF逐帧）
# ----------------------------------------------------------------------------
def _qr(raw, report, outdir, img):
    try:
        import cv2
    except Exception:
        report.add("warn", "OpenCV 未安装，跳过二维码识别")
        return
    det = cv2.QRCodeDetector()
    found = []

    def probe(im_arr, tag):
        try:
            txt, pts, _ = det.detectAndDecode(im_arr)
            if txt:
                found.append((tag, txt))
        except Exception:
            pass

    base = cv2.imdecode(np.frombuffer(raw[:30 * 1024 * 1024], np.uint8), cv2.IMREAD_COLOR)
    if base is not None:
        bh, bw = base.shape[:2]
        if max(bh, bw) > 2000:   # 超大图先缩小再探测，避免后续放大策略叠加爆炸
            s = 2000 / max(bh, bw)
            base = cv2.resize(base, (max(1, int(bw * s)), max(1, int(bh * s))),
                              interpolation=cv2.INTER_AREA)
        probe(base, "原图")
        gray = cv2.cvtColor(base, cv2.COLOR_BGR2GRAY)
        probe(gray, "灰度")
        probe(255 - gray, "反色灰度")
        gh, gw = gray.shape[:2]
        if gh * gw <= 2_000_000:   # 小图才放大；大图放大无意义且极慢
            for scale in (2, 3, 4):
                big = cv2.resize(gray, None, fx=scale, fy=scale, interpolation=cv2.INTER_CUBIC)
                probe(big, f"放大{scale}x")
                probe(255 - big, f"反色放大{scale}x")
                _, th = cv2.threshold(big, 0, 255, cv2.THRESH_BINARY + cv2.THRESH_OTSU)
                probe(th, f"二值化{scale}x")
        # 低位平面里藏二维码（LSB 位平面肉眼题常是二维码）
        try:
            rgb = cv2.cvtColor(base, cv2.COLOR_BGR2RGB)
            for ci, cn in ((0, "R"), (1, "G"), (2, "B")):
                plane = ((rgb[:, :, ci] & 1) * 255).astype("uint8")
                probe(plane, f"{cn}位平面")
                probe(255 - plane, f"{cn}位平面反色")
        except Exception:
            pass
        # 一维条码（EAN/UPC/Code128 等，需要 opencv-contrib）
        try:
            bd = cv2.barcode.BarcodeDetector()
            ok2, decoded, dtype, _ = bd.detectAndDecode(base)
            if ok2:
                for dval, dt in zip(decoded, dtype):
                    if dval:
                        found.append((f"一维条码{dt}", dval))
        except Exception:
            pass
    # GIF 逐帧
    if getattr(img, "is_animated", False):
        for i, frame in enumerate(ImageSequence.Iterator(img)):
            arr = cv2.cvtColor(np.array(frame.convert("RGB")), cv2.COLOR_RGB2BGR)
            probe(arr, f"GIF第{i}帧")
    if found:
        seen = set()
        for tag, txt in found:
            if txt in seen:
                continue
            seen.add(txt)
            report.add("ok", f"二维码识别({tag})", txt)
            for fl in scan_flags(txt.encode()):
                report.add("flag", "二维码中发现 flag", fl)
    else:
        report.add("info", "二维码", "未检测到二维码")

# ----------------------------------------------------------------------------
# FFT 频谱（盲水印肉眼题）
# ----------------------------------------------------------------------------
def _fft(img, report, outdir):
    try:
        gray_img = img.convert("L")
        if max(gray_img.size) > 1024:   # 频谱肉眼题，缩略到 1024 足够且快
            gray_img.thumbnail((1024, 1024))
        gray = np.array(gray_img, dtype=np.float64)
        f = np.fft.fft2(gray)
        spec = np.fft.fftshift(np.log(np.abs(f) + 1))
        span = spec.max() - spec.min()
        if span <= 0:
            spec = np.zeros_like(spec)
        else:
            spec = (spec - spec.min()) / span * 255
        fp = os.path.join(outdir, "fft_spectrum.png")
        Image.fromarray(spec.astype("uint8")).save(fp)
        report.add("info", "FFT 频谱图已生成", fp + "（频域盲水印题请肉眼查看是否有图案/文字）")
    except Exception as e:
        pass


def _fft_channel(chan, size=1024):
    g = Image.fromarray(chan)
    if max(g.size) > size:
        g.thumbnail((size, size))
    a = np.array(g, dtype=np.float64)
    f = np.fft.fft2(a)
    spec = np.fft.fftshift(np.log(np.abs(f) + 1))
    lo, hi = spec.min(), spec.max()
    return np.clip((spec - lo) / max(1e-6, hi - lo) * 255, 0, 255).astype("uint8")


def _extra_visuals(img, report, outdir):
    """组合 LSB 彩图、随机色映射、分通道 FFT——StegSolve 风格肉眼辅助图。"""
    made = []
    try:
        rgba = img.convert("RGBA")
        arr = np.array(rgba)
        h, w, _ = arr.shape
        if h * w > LSB_MAX_PIXELS:
            arr = arr[:min(h, int(LSB_MAX_PIXELS / w) + 1), :, :]
        # 1) RGB 三个 bit0 合成为一张彩色图（低位噪声里若有规律图案立即可见）
        combo = np.zeros((arr.shape[0], arr.shape[1], 3), dtype=np.uint8)
        for ci in range(3):
            combo[:, :, ci] = ((arr[:, :, ci] & 1) * 255).astype("uint8")
        fp = os.path.join(outdir, "lsb_rgb_combo.png")
        Image.fromarray(combo).save(fp)
        made.append(("RGB低位合成彩图", fp))
        # 2) 随机色映射（把 bit0 0/1 映射成高对比随机色，凸显隐藏二值图）
        rng = np.random.RandomState(0x5EED)
        pal0 = rng.integers(0, 255, 3)
        pal1 = rng.integers(0, 255, 3)
        m = (arr[:, :, 0] & 1).astype(bool)
        rnd = np.where(m[:, :, None], pal1, pal0).astype(np.uint8)
        fp = os.path.join(outdir, "lsb_random_colormap.png")
        Image.fromarray(rnd).save(fp)
        made.append(("低位随机色映射", fp))
        # 3) R/G/B 分通道 FFT（彩色盲水印可能只落在单一通道）
        for ci, cn in ((0, "R"), (1, "G"), (2, "B")):
            sp = _fft_channel(arr[:, :, ci])
            fp = os.path.join(outdir, f"fft_{cn}.png")
            Image.fromarray(sp).save(fp)
            made.append((f"{cn}通道FFT频谱", fp))
        for nm, p in made:
            report.add("info", f"已生成{nm}", p + "（请肉眼查看是否有隐藏图案/文字/二维码）")
    except Exception:
        pass
