# -*- coding: utf-8 -*-
"""PolarCTF（及同类国产 CTF）高频套路增强模块。

本模块只做“增量增强”，不改动既有分析链；由 dispatcher 在文本/图片/压缩/
文档/音频分流中调用。所有函数均做了异常隔离，单题失败不影响主流程。

覆盖实战题型（均在 PolarCTF 真实题目中验证）：
  1. 0/255、0/1 像素矩阵还原二维码        （如“0和255”“01”）
  2. data:image/...;base64 文本还原图片     （如“二维码”）
  3. ZIP 伪加密（本地头/中央目录标志位不一致）修复（如“属性？真加密？”）
  4. ZIP 注释多进制/培根密码解码            （十进制 ASCII、0x、AB 培根）
  5. docx 多点隐写拼接（白字/隐藏/嵌入对象/文档属性）（如“docx隐写”“找一找”）
  6. F5 隐写提取（JPEG，调用随包 Java/F5）  （如“刷新试一下”）
  7. 兽音译者变体（自定义四符号，如 喵/呜/啊/~）
  8. WAV 语谱图自动渲染（频谱藏字）
  9. “答案 -> MD5 -> flag{}”包装辅助
"""
import os
import re
import ast
import glob
import base64
import hashlib
import itertools
import struct
import zipfile
import subprocess

from .common import TOOLS_DIR, APP_DIR, save_artifact, safe_name, scan_flags


def _add(rep, level, title, detail="", data=None):
    if rep is not None:
        rep.add(level, title, detail, data)


# ============================================================================
# 1. 像素矩阵（0/255 或 0/1）还原二维码
# ============================================================================
def _parse_matrix(text):
    """从文本中解析二维 0/1 或 0/255 矩阵，返回 list[list[int]]（0/1）或 None。"""
    # 1) Python/JS 字面量嵌套列表
    for m in re.finditer(r"\[\s*\[[\s\S]{20,}?\]\s*\]", text):
        chunk = m.group(0)
        try:
            obj = ast.literal_eval(chunk)
        except Exception:
            continue
        if isinstance(obj, list) and obj and isinstance(obj[0], list):
            try:
                vals = {v for row in obj for v in row}
            except TypeError:
                continue
            if vals <= {0, 255}:
                return [[1 if v == 0 else 0 for v in row] for row in obj]   # 0=黑
            if vals <= {0, 1}:
                return [[1 if v == 1 else 0 for v in row] for row in obj]   # 1=黑
    # 2) 纯文本：每行一组 0/1（可被空格/逗号分隔），或连续 01 串
    lines = [ln.strip() for ln in text.splitlines() if ln.strip()]
    rows = []
    mode = None
    for ln in lines:
        nums = re.findall(r"(?<!\d)(255|0|1)(?!\d)", ln)
        joined = "".join(nums)
        chars = re.sub(r"[\s,;|]+", "", ln)
        if set(chars) <= {"0", "1"} and len(chars) >= 8:
            row = [1 if c == "1" else 0 for c in chars]
            mode = "01"
        elif nums and all(n in ("0", "255") for n in nums) and len(nums) >= 8:
            row = [1 if n == "0" else 0 for n in nums]   # 0=黑
            mode = "0255"
        else:
            continue
        rows.append(row)
    if rows:
        w = max(len(r) for r in rows)
        if len(rows) >= 8 and w >= 8 and all(abs(len(r) - w) <= 1 for r in rows):
            rows = [r + [0] * (w - len(r)) for r in rows]
            return rows
    return None


def pixel_matrix_qr(text, out_dir):
    """若文本是像素矩阵，渲染成二维码图片并识别。返回 (png_path, data) 或 None。"""
    mat = _parse_matrix(text)
    if not mat:
        return None
    h, w = len(mat), len(mat[0])
    try:
        import numpy as np
        import cv2
    except Exception:
        return None
    scale, quiet = 18, 4
    canvas = np.full(((h + 2 * quiet) * scale, (w + 2 * quiet) * scale), 255, np.uint8)
    for y in range(h):
        for x in range(w):
            if mat[y][x] == 1:
                y0, x0 = (y + quiet) * scale, (x + quiet) * scale
                canvas[y0:y0 + scale, x0:x0 + scale] = 0
    os.makedirs(out_dir, exist_ok=True)
    png = os.path.join(out_dir, "pixel_matrix_qr.png")
    try:
        # OpenCV 在 Windows 中文路径下 imwrite 会静默失败，用 imencode+tofile
        ok, buf = cv2.imencode(".png", canvas)
        if ok:
            buf.tofile(png)
        else:
            raise RuntimeError("imencode failed")
    except Exception:
        from PIL import Image
        Image.fromarray(canvas).save(png)
    det = cv2.QRCodeDetector()
    data = ""
    try:
        d, _, _ = det.detectAndDecode(canvas)
        data = d or ""
        if not data:
            ok, datas, _, _ = det.detectAndDecodeMulti(canvas)
            if ok:
                data = " | ".join(x for x in datas if x)
    except Exception:
        data = ""
    return png, data


# ============================================================================
# 2. data URI 图片还原
# ============================================================================
_DATA_URI = re.compile(r"data:image/([a-zA-Z0-9.+-]+);base64,([A-Za-z0-9+/=\s]+)")


def data_uri_images(text, out_dir):
    """提取 data:image/...;base64 内嵌图片，存盘返回路径列表。"""
    out = []
    for n, m in enumerate(_DATA_URI.finditer(text)):
        ext, b64 = m.group(1).lower(), m.group(2)
        try:
            raw = base64.b64decode(re.sub(r"\s+", "", b64))
        except Exception:
            continue
        if raw[:4] in (b"\x89PNG", b"\xff\xd8\xff") or raw[:6] in (b"GIF87a", b"GIF89a"):
            os.makedirs(out_dir, exist_ok=True)
            real_ext = "png" if raw[:4] == b"\x89PNG" else ("jpg" if raw[:3] == b"\xff\xd8" else "gif")
            p = os.path.join(out_dir, f"datauri_{n}.{real_ext}")
            save_artifact(p, raw)
            out.append(p)
    return out


# ============================================================================
# 3. ZIP 伪加密修复
# ============================================================================
def repair_fake_encrypted_zip(path, out_dir):
    """检测并修复 ZIP 本地文件头/中央目录加密标志位不一致（伪加密）。
    返回修复副本路径；不是伪加密返回 None。"""
    try:
        b = bytearray(open(path, "rb").read())
        if b[:4] != b"PK\x03\x04":
            return None
        lf = struct.unpack_from("<H", b, 6)[0]
        cd_pos = b.find(b"PK\x01\x02")
        if cd_pos < 0:
            return None
        cd = struct.unpack_from("<H", b, cd_pos + 8)[0]
        # 中央目录声明加密、本地头未加密 => 典型伪加密；或二者加密位不一致
        if bool(cd & 1) != bool(lf & 1) or (cd & 1 and not (lf & 1)):
            struct.pack_into("<H", b, 6, lf & ~1)
            # 同时清理所有中央目录头的加密位
            idx = 0
            while True:
                j = b.find(b"PK\x01\x02", idx)
                if j < 0:
                    break
                f2 = struct.unpack_from("<H", b, j + 8)[0]
                struct.pack_into("<H", b, j + 8, f2 & ~1)
                idx = j + 4
            os.makedirs(out_dir, exist_ok=True)
            fixed = os.path.join(out_dir, safe_name(os.path.basename(path)) + ".fixed.zip")
            save_artifact(fixed, bytes(b))
            return fixed
    except Exception:
        return None
    return None


# ============================================================================
# 4. ZIP 注释 / 文本中的多进制与培根密码
# ============================================================================
_BACON24 = "ABCDEFGHIKLMNOPQRSTUVWXYZ"


def decode_obfuscated_text(text):
    """对一段短文本尝试：十进制 ASCII、十六进制、八进制、培根密码。返回 [(title,out)]。"""
    res = []
    compact = text.strip()
    # 十进制 ASCII（逗号/空格分隔，数值集中在可打印区）
    nums = re.findall(r"\d{1,3}", compact)
    if 3 <= len(nums) <= 200:
        vals = [int(n) for n in nums]
        if vals and all(9 <= v <= 126 for v in vals) and sum(32 <= v <= 126 for v in vals) / len(vals) > 0.8:
            s = "".join(chr(v) for v in vals if 32 <= v <= 126)
            if any(c.isalpha() for c in s):
                res.append(("十进制ASCII", s))
    # 十六进制串/序列
    hs = re.findall(r"\b([0-9a-fA-F]{2}(?:[\s,;]?[0-9a-fA-F]{2}){2,})\b", compact)
    for h in hs[:3]:
        hx = re.sub(r"[\s,;]", "", h)
        try:
            b = bytes.fromhex(hx)
            s = b.decode("utf-8", "replace")
            if sum(32 <= ord(c) < 127 for c in s) > len(s) * 0.8:
                res.append(("十六进制", s))
        except Exception:
            pass
    # 培根密码（A/B，连续 5 位一组）
    ab = "".join(c for c in compact if c in "ABab")
    if len(ab) >= 10:
        for off in range(min(5, len(ab) - 9)):
            seg = ab[off:]
            vals = []
            for i in range(0, len(seg) - 4, 5):
                v = 0
                for c in seg[i:i + 5]:
                    v = (v << 1) | (1 if c.upper() == "B" else 0)
                vals.append(v)
            if vals and all(v < 24 for v in vals) and len(vals) >= 3:
                res.append((f"培根密码(off{off})", "".join(_BACON24[v] for v in vals)))
    return res


def analyze_zip_comments(path, rep):
    """提取 ZIP（含嵌套成员）注释并做多进制/培根解码。"""
    try:
        z = zipfile.ZipFile(path)
    except Exception:
        return
    comments = []
    if z.comment:
        comments.append(("压缩包注释", z.comment))
    for info in z.infolist():
        if info.comment:
            comments.append((f"成员 {info.filename} 注释", info.comment))
    for name, raw in comments:
        txt = None
        for enc in ("utf-8", "gbk"):
            try:
                txt = raw.decode(enc)
                break
            except Exception:
                continue
        _add(rep, "info", name, txt[:300])
        if txt:
            for title, out in decode_obfuscated_text(txt):
                _add(rep, "ok", f"{name}-{title}", out)
                for fl in scan_flags(out.encode("utf-8", "ignore")):
                    _add(rep, "flag", f"{name}-{title} 解出 flag", fl)


# ============================================================================
# 5. docx 多点隐写拼接
# ============================================================================
def _docx_namespace_runs(root):
    import xml.etree.ElementTree as ET
    W = "{http://schemas.openxmlformats.org/wordprocessingml/2006/main}"
    white, vanish, normal_ascii = [], [], []
    for r in root.iter(W + "r"):
        rpr = r.find(W + "rPr")
        is_white = is_vanish = False
        if rpr is not None:
            if rpr.find(W + "vanish") is not None:
                is_vanish = True
            c = rpr.find(W + "color")
            if c is not None and (c.get(W + "val") or "").lower() in ("ffffff", "white"):
                is_white = True
        txt = "".join(t.text or "" for t in r.iter(W + "t"))
        if not txt:
            continue
        if is_vanish:
            vanish.append(txt)
        elif is_white:
            white.append(txt)
        else:
            ascii_part = "".join(ch for ch in txt if 32 <= ord(ch) < 127)
            if ascii_part.strip():
                normal_ascii.append(ascii_part)
    return white, vanish, normal_ascii


def docx_multistego(path, rep):
    """聚合 docx 中：白字、隐藏文字、嵌入对象、文档属性里的 flag 片段并按序拼接。"""
    import xml.etree.ElementTree as ET
    try:
        z = zipfile.ZipFile(path)
    except Exception:
        return
    W = "{http://schemas.openxmlformats.org/wordprocessingml/2006/main}"
    BODY_CHARS = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
                     "_!@#$%^&*.-+")
    # 1) 按文档顺序收集 run：(text, kind)
    runs = []
    try:
        root = ET.fromstring(z.read("word/document.xml"))
        for r in root.iter(W + "r"):
            rpr = r.find(W + "rPr")
            kind = "normal"
            if rpr is not None:
                if rpr.find(W + "vanish") is not None:
                    kind = "vanish"
                else:
                    c = rpr.find(W + "color")
                    if c is not None and (c.get(W + "val") or "").lower() in ("ffffff", "white"):
                        kind = "white"
            txt = "".join(t.text or "" for t in r.iter(W + "t"))
            if txt:
                runs.append((txt, kind))
    except KeyError:
        pass
    # 合并连续的白色/隐藏 run 为整段（引导词常与 flag 体分属相邻 run）；正文 run 保持细粒度
    seq = []
    for t, k in runs:
        if k in ("white", "vanish") and seq and seq[-1][1] == k:
            seq[-1] = (seq[-1][0] + t, k)
        else:
            seq.append((t, k))
    runs = seq
    white = "".join(t for t, k in runs if k == "white")
    vanish = "".join(t for t, k in runs if k == "vanish")
    if white:
        _add(rep, "ok", "docx 白色文字", white[:500])
    if vanish:
        _add(rep, "ok", "docx 隐藏文字(vanish)", vanish[:500])

    # 2) 嵌入对象 / 文档属性作为补充片段（常为尾段）
    extras = []
    for n in z.namelist():
        low = n.lower()
        if low.endswith((".txt", ".dat")) or (n.startswith("word/") and not low.endswith((".xml", ".rels"))
                                              and "." in os.path.basename(n)):
            try:
                raw = z.read(n)
            except Exception:
                continue
            s = None
            for enc in ("utf-8", "gbk"):
                try:
                    s = raw.decode(enc)
                    break
                except Exception:
                    s = None
            if s and sum(32 <= ord(c) < 127 for c in s) > len(s) * 0.6:
                _add(rep, "ok", f"docx 嵌入对象 {os.path.basename(n)}", s[:300])
                extras.append(s)
                for fl in scan_flags(s.encode("utf-8", "ignore")):
                    _add(rep, "flag", "docx 嵌入对象含 flag", fl)
    try:
        core = z.read("docProps/core.xml").decode("utf-8", "replace")
        for tag in ("description", "title", "subject", "creator", "keywords", "lastModifiedBy"):
            m = re.search(rf"<(?:dc|cp):{tag}[^>]*>(.*?)</(?:dc|cp):{tag}>", core, re.S)
            if m and m.group(1).strip():
                val = m.group(1).strip()
                _add(rep, "ok", f"docx 属性 {tag}", val[:200])
                extras.append(val)
    except KeyError:
        pass

    # 3) 定位 flag{ 锚点（优先白色/隐藏 run，其次正文 run）
    def body_of(text):
        """剥离中文引导词与 flag{ / flag: 前缀，返回疑似 flag 体。"""
        if "{" in text:
            text = text.rsplit("{", 1)[1]
        text = re.sub(r".*?flag\s*[：:]", "", text, flags=re.S)
        return "".join(c for c in text if c in BODY_CHARS or c == "}")

    anchor_i = None
    for i, (t, k) in enumerate(runs):
        if "flag{" in t and k in ("white", "vanish"):
            anchor_i = i
            break
    if anchor_i is None:
        for i, (t, k) in enumerate(runs):
            if "flag{" in t:
                anchor_i = i
                break
    if anchor_i is None:
        # 无 flag{ 锚点：若嵌入对象直接含完整 flag 已在上面上报
        return
    acc = body_of(runs[anchor_i][0])
    normal_accept = True   # 锚点后仅接受连续的纯 hex/标识 token 正文 run，遇正文即停
    for t, k in runs[anchor_i + 1:]:
        if k in ("white", "vanish"):
            acc += body_of(t)
        else:
            ascii_part = "".join(c for c in t if 32 <= ord(c) < 127).strip()
            is_token = bool(re.fullmatch(r"[0-9a-fA-F]{3,40}", ascii_part) or
                            re.fullmatch(r"[A-Za-z0-9_]{3,40}", ascii_part))
            if normal_accept and is_token:
                acc += ascii_part
            elif ascii_part or any(ord(c) > 0x2e80 for c in t):
                normal_accept = False
    for s in extras:
        acc += body_of(s)
    # 截到第一个闭合 }
    acc = acc.replace("{", "")
    if "}" in acc:
        acc = acc[:acc.index("}") + 1]
    cand = "flag{" + acc.strip("}") + ("}" if acc.endswith("}") else "")
    if re.fullmatch(r"flag\{[A-Za-z0-9_!@#$%^&*.\-+]{2,200}\}?", cand) and cand.endswith("}"):
        _add(rep, "flag", "docx 多点拼接 flag", cand)
    else:
        _add(rep, "info", "docx 片段拼接候选(请人工核对)", cand)


# ============================================================================
# 6. F5 隐写提取（JPEG）
# ============================================================================
def _find_java():
    hits = glob.glob(os.path.join(APP_DIR, "tools", "runtime", "jdk*", "bin", "java.exe"))
    if hits:
        return hits[0]
    import shutil
    return shutil.which("java") or shutil.which("java.exe")


def _f5_class_dir():
    hits = glob.glob(os.path.join(TOOLS_DIR, "f5", "**", "Extract.class"), recursive=True)
    return os.path.dirname(hits[0]) if hits else None


def f5_extract_chain(path, rep, out_dir, passwords=("",)):
    """对 JPEG 用 F5-steganography 提取（随包 Java + F5 class）。"""
    cdir = _f5_class_dir()
    java = _find_java()
    if not cdir or not java:
        _add(rep, "info", "F5 提取跳过", "未找到随包 Java 或 F5 Extract.class（工具中心可补）")
        return
    # 收集候选密码：EXIF 的 XPComment/XPTitle 等常被用作 F5 口令
    extra = []
    try:
        from PIL import Image
        from PIL.ExifTags import TAGS
        img = Image.open(path)
        ex = img.getexif()
        for tag in (0x9C9C, 0x9C9B, 0x9C9D, 0x9C9E, 0x9C9F):
            v = ex.get(tag)
            if isinstance(v, bytes):
                v = v.decode("utf-16-le", "ignore").strip("\x00").strip()
            if v:
                extra.append(str(v))
    except Exception:
        pass
    pws = []
    for p in list(passwords) + ["", "abc123"] + extra:
        if p not in pws:
            pws.append(p)
    os.makedirs(out_dir, exist_ok=True)
    for n, pw in enumerate(pws[:8]):
        outp = os.path.join(out_dir, f"f5_out_{n}.bin")
        args = [java, "--add-exports", "java.base/sun.security.provider=ALL-UNNAMED",
                "Extract"]
        if pw:
            args += ["-p", pw]
        args += ["-e", outp, os.path.abspath(path)]
        try:
            r = subprocess.run(args, cwd=cdir, capture_output=True, timeout=120,
                               text=True, errors="replace")
        except Exception as e:
            _add(rep, "info", "F5 运行失败", str(e)[:120])
            return
        if os.path.isfile(outp) and os.path.getsize(outp) > 0:
            data = open(outp, "rb").read()
            fl = scan_flags(data)
            if fl:
                for f in fl:
                    _add(rep, "flag", f"F5 隐写提取成功(口令 {pw!r})", f)
                return
            # 提取出的是可识别文件（zip/png 等）也登记
            if data[:4] in (b"PK\x03\x04", b"\x89PNG") or data[:3] == b"\xff\xd8":
                if outp not in rep.extracted:
                    rep.extracted.append(outp)
                _add(rep, "ok", f"F5 提取出嵌入文件(口令 {pw!r})", outp)
                return
            txt = None
            try:
                txt = data.decode("utf-8")
            except Exception:
                pass
            if txt and sum(32 <= ord(c) < 127 or ord(c) > 0x4e00 for c in txt) > len(txt) * 0.85:
                _add(rep, "ok", f"F5 提取文本(口令 {pw!r})", txt[:300])
                for f in scan_flags(data):
                    _add(rep, "flag", "F5 提取文本含 flag", f)
                return


# ============================================================================
# 7. 兽音译者变体（自定义四符号集）
# ============================================================================
def roar_variant_decode(text):
    """识别自定义四符号兽音类密文并枚举映射解码，返回可读字符串或 None。

    真实兽音算法（roar.iiilab.com 系）：原文码点转 4 位十六进制，每位 hex
    加位置偏移 n%16 后模 16，再拆成 2 个四进制符号（高位在前），常带头 3 尾 1。
    解码即逆过程：每 2 符号还原 1 位 hex（减偏移），每 4 位 hex 还原 1 个码点。
    符号集自定义（如 喵/呜/啊/~），故枚举 24 种映射、头尾长度与偏移方向。
    """
    from collections import Counter
    # 1) 频率最高的 4 个非空白符号（CJK 安全：不能用 isalnum 过滤，呜/喵/啊 会被误判）
    cnt = Counter(c for c in text if not c.isspace())
    if len(cnt) < 4:
        return None
    top = [c for c, _ in cnt.most_common(4)]
    symset = set(top)
    total = sum(cnt.values())
    if sum(cnt[c] for c in top) < total * 0.6:
        return None
    # 2) 最长纯符号连续段作为密文主体（避开引导语里孤立的杂散符号，保持对齐）
    best_run, cur = "", []
    for c in text:
        if c in symset:
            cur.append(c)
        else:
            if len(cur) > len(best_run):
                best_run = "".join(cur)
            cur = []
    if len(cur) > len(best_run):
        best_run = "".join(cur)
    body = best_run
    if len(body) < 8:
        return None
    # 3) 枚举映射 / 头尾 / 偏移方向，按真实算法解码并取可读性最高者
    best = None
    for perm in itertools.permutations(range(4)):
        mp = dict(zip(top, perm))
        digits = [mp[c] for c in body]
        for head in range(0, 7):
            for foot in range(0, 3):
                inner = digits[head: len(digits) - foot if foot else len(digits)]
                if len(inner) < 2 or len(inner) % 2:
                    continue
                for sign in (-1, 1):
                    hexd = [((inner[n] * 4 + inner[n + 1]) + sign * ((n // 2) % 16)) % 16
                            for n in range(0, len(inner), 2)]
                    if len(hexd) % 4:
                        continue
                    out, ok = [], True
                    for i in range(0, len(hexd), 4):
                        cp = ((hexd[i] << 12) | (hexd[i + 1] << 8)
                              | (hexd[i + 2] << 4) | hexd[i + 3])
                        if cp > 0x10FFFF or 0xD800 <= cp <= 0xDFFF:
                            ok = False
                            break
                        out.append(chr(cp))
                    if not ok or not out:
                        continue
                    s = "".join(out)
                    ascii_n = sum(1 for c in s if 32 <= ord(c) < 127)
                    cjk_n = sum(1 for c in s if 0x4e00 <= ord(c) <= 0x9fff)
                    readable = (ascii_n + cjk_n) / len(s)
                    if readable > 0.9 and re.search(r"[一-鿿A-Za-z{]", s):
                        # ASCII 加权优先：避免随机 CJK 垃圾与明文同分按枚举顺序抢占
                        score = ascii_n * 2 + cjk_n
                        if best is None or score > best[0]:
                            best = (score, s)
    return best[1] if best else None


# ============================================================================
# 8. WAV 语谱图渲染
# ============================================================================
def wav_spectrogram(path, out_dir):
    """渲染 WAV 语谱图（频谱藏字题），返回 png 路径或 None。"""
    try:
        import wave
        import numpy as np
        from PIL import Image
    except Exception:
        return None
    try:
        w = wave.open(path, "rb")
        ch, sw, fr = w.getnchannels(), w.getsampwidth(), w.getframerate()
        raw = w.readframes(w.getnframes())
        dt = {1: np.uint8, 2: np.int16, 4: np.int32}.get(sw)
        if dt is None:
            return None
        x = np.frombuffer(raw, dtype=dt).astype(np.float32)
        if ch == 2:
            x = x.reshape(-1, 2)[:, 0]
        nfft, hop = 2048, 128
        win = np.hanning(nfft)
        frames = [np.abs(np.fft.rfft(x[i:i + nfft] * win))
                  for i in range(0, len(x) - nfft, hop)]
        if not frames:
            return None
        S = np.array(frames).T
        Sdb = 20 * np.log10(S + 1e-6)
        lo, hi = np.percentile(Sdb, 25), np.percentile(Sdb, 99.95)
        img = np.clip((Sdb - lo) / (hi - lo), 0, 1)
        im = np.flipud((img * 255).astype(np.uint8))
        os.makedirs(out_dir, exist_ok=True)
        png = os.path.join(out_dir, "spectrogram.png")
        Image.fromarray(im).save(png)
        # 低频带放大版（文字常贴底）
        h = im.shape[0]
        band = im[int(h * 0.78):, :]
        Image.fromarray(band).resize((band.shape[1] * 2, band.shape[0] * 3),
                                     Image.NEAREST).save(os.path.join(out_dir, "spectrogram_low.png"))
        return png
    except Exception:
        return None


# ============================================================================
# 9. 答案 MD5 包装
# ============================================================================
def md5_flag(answer, prefix="flag"):
    """Polar 高频套路：答案字符串 -> 32 位小写 MD5 -> flag{md5}。"""
    if answer is None:
        return None
    a = str(answer).strip().strip("{}")
    h = hashlib.md5(a.encode("utf-8")).hexdigest()
    return f"{prefix}{{{h}}}"
