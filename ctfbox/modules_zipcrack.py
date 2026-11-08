# -*- coding: utf-8 -*-
"""ZipCrypto 口令恢复：候选派生 + 12 字节头快速校验 + john 深度回退。

边界：
  - 只处理本地 CTF 附件，不做网络请求；
  - 命中必须经过完整解密 + CRC32 复核，头校验单独命中不算结果；
  - john 回退只在显式 deep 时调用，并有超时与临时会话隔离。
"""
import os
import re
import struct
import subprocess
import time
import zipfile
import zlib

from .modules_text import WEAK_PASSWORDS

CRC_TABLE = [0] * 256
for _i in range(256):
    _c = _i
    for _ in range(8):
        _c = (0xEDB88320 ^ (_c >> 1)) if (_c & 1) else (_c >> 1)
    CRC_TABLE[_i] = _c

KEYBOARD_ROWS = ("qwertyuiop", "asdfghjkl", "zxcvbnm")
KEYBOARD_COLS = ("qaz", "wsx", "edc", "rfv", "tgb", "yhn", "ujm", "ik", "ol", "p")
SUFFIXES = ("", "123", "1234", "12345", "123456", "!", "!!", "2020", "2021",
            "2022", "000", "666", "888", "520", "1314")
MAX_CANDIDATES = 200000


def _crc32_byte(crc, b):
    return (crc >> 8) ^ CRC_TABLE[(crc ^ b) & 0xFF]


class Keys:
    __slots__ = ("k0", "k1", "k2")

    def __init__(self):
        self.k0, self.k1, self.k2 = 0x12345678, 0x23456789, 0x34567890

    def update(self, b):
        self.k0 = _crc32_byte(self.k0, b)
        self.k1 = ((self.k1 + (self.k0 & 0xFF)) * 134775813 + 1) & 0xFFFFFFFF
        self.k2 = _crc32_byte(self.k2, self.k1 >> 24)

    def decrypt(self, b):
        t = (self.k2 | 2) & 0xFFFF
        p = b ^ (((t * (t ^ 1)) >> 8) & 0xFF)
        self.update(p)
        return p


def keyboard_words():
    """键盘行/列走位及其镜像（zaq -> zaqqaz、qaz -> qazzaq）。"""
    bases = set()
    for line in KEYBOARD_ROWS + KEYBOARD_COLS:
        for size in range(2, 7):
            for start in range(0, len(line) - size + 1):
                word = line[start:start + size]
                bases.add(word)
                bases.add(word[::-1])
    words = set()
    for word in bases:
        words.add(word)
        words.add(word + word[::-1])
        words.add(word[::-1] + word)
    return sorted(words)


def _stem_variants(path, hints):
    words = []

    def add(word):
        word = (word or "").strip()
        if 1 <= len(word) <= 64:
            words.append(word)

    names = [os.path.basename(path)]
    parent = os.path.dirname(os.path.abspath(path))
    if parent:
        names.append(os.path.basename(parent))
    for name in names:
        stem = os.path.splitext(name)[0]
        add(stem)
        for token in re.split(r"[^0-9A-Za-z\u4e00-\u9fff]+", stem):
            add(token)
            for num in re.findall(r"\d{2,}", token):
                add(num)
                if len(num) >= 4:
                    add(num[:4])
                if len(num) >= 6:
                    add(num[:6])
    for hint in hints or []:
        hint = str(hint or "").strip()
        add(hint)
        for token in re.split(r"[^0-9A-Za-z\u4e00-\u9fff]+", hint):
            add(token)
            for num in re.findall(r"\d{2,}", token):
                add(num)
                if len(num) >= 4:
                    add(num[:4])
                if len(num) >= 6:
                    add(num[:6])
            # 中文题名按原样保留；ASCII 片段再去掉常见题型词
            if token.lower() in ("misc", "crypto", "web", "reverse", "pwn", "flag"):
                continue
    return words


def _date_variants(path):
    stamps = []
    try:
        stamps.append(time.localtime(os.path.getmtime(path)))
    except Exception:
        pass
    try:
        with zipfile.ZipFile(path) as zf:
            for info in zf.infolist()[:3]:
                stamps.append(info.date_time)
    except Exception:
        pass
    out = []
    for st in stamps:
        try:
            year, month, day = int(st[0]), int(st[1]), int(st[2])
        except Exception:
            continue
        out += [
            "%04d" % year, "%02d%02d" % (month, day), "%04d%02d" % (year, month),
            "%04d%02d%02d" % (year, month, day),
            "%02d%02d%04d" % (day, month, year),
            "%02d%02d%02d" % (year % 100, month, day),
        ]
    return out


def password_candidates(path, hints=None, known=None):
    """返回去重后的明文候选；不限定只用于 ZIP，图片口令复用同一套。"""
    ordered = []

    def add(word):
        if word is None:
            return
        word = str(word)
        if 0 <= len(word) <= 64:
            ordered.append(word)

    for word in known or []:
        add(word)
    add("")
    for word in WEAK_PASSWORDS:
        add(word)
    for word in keyboard_words():
        add(word)

    bases = _stem_variants(path, hints)
    suffixes = SUFFIXES + tuple(_date_variants(path))
    seen_base = set()
    for base in bases:
        if base in seen_base:
            continue
        seen_base.add(base)
        variants = {base, base.lower(), base.upper(), base.capitalize()}
        variants.add("".join(ch.upper() if i % 2 else ch.lower()
                             for i, ch in enumerate(base)))
        for variant in variants:
            for suffix in suffixes:
                add(variant + suffix)
        # 常见 leet 变形
        leet = base.translate(str.maketrans("oaeis", "04315"))
        if leet != base:
            add(leet)
            add(leet.capitalize())

    # 数字密码爆破：当文件名/hint 含 number/数字/位数提示时，自动试 0-999999
    path_lower = (path or "").lower()
    hints_str = " ".join(str(h) for h in (hints or [])).lower()
    all_text = path_lower + " " + hints_str
    digit_digits = None
    import re as _re
    m = _re.search(r"(\d+)\s*(number|位|digit)", all_text)
    if m:
        try:
            digit_digits = int(m.group(1))
        except Exception:
            pass
    if "number" in all_text or "数字" in all_text or digit_digits:
        rng = range(10 ** digit_digits) if digit_digits and digit_digits <= 6 else range(1000000)
        for i in rng:
            add(str(i).zfill(digit_digits) if digit_digits else str(i))
    else:
        # 默认也试 0-9999（4位），CTF 常见
        for i in range(10000):
            add(f"{i:04d}")

    out, seen = [], set()
    for word in ordered:
        if word in seen:
            continue
        seen.add(word)
        out.append(word)
        if len(out) >= MAX_CANDIDATES:
            break
    return out


def password_bytes(word):
    """按 UTF-8 / GBK / UTF-16LE 依次给出原始字节，去重。"""
    if isinstance(word, bytes):
        return [word]
    raw = [word.encode("utf-8")]
    for enc in ("gbk", "utf-16-le"):
        if any(ord(ch) > 127 for ch in word):
            try:
                data = word.encode(enc)
            except Exception:
                continue
            if data not in raw:
                raw.append(data)
    return raw


def zip_header_check(path):
    """返回 (header12, check_byte, info) 或 (None, None, 原因)。"""
    try:
        zf = zipfile.ZipFile(path)
    except Exception as exc:
        return None, None, "不是可读 ZIP：%s" % exc
    try:
        target = None
        for info in zf.infolist():
            if info.is_dir() or not (info.flag_bits & 0x1):
                continue
            target = info
            break
        if target is None:
            return None, None, "ZIP 未加密"
        if target.compress_type == 99:
            return None, None, "WinZip AES（非 ZipCrypto），需 7z/hashcat 路径"
        with open(path, "rb") as fp:
            fp.seek(target.header_offset)
            local = fp.read(30)
            if len(local) < 30 or local[:4] != b"PK\x03\x04":
                return None, None, "本地文件头解析失败"
            flag, _method, _mtime, _mdate, crc, _cs, _us, nlen, elen = \
                struct.unpack("<HHHHIIIHH", local[6:30])
            fp.seek(target.header_offset + 30 + nlen + elen)
            header = fp.read(12)
        if len(header) < 12:
            return None, None, "加密头长度不足"
        if flag & 0x8:
            # 数据描述符条目的本地 CRC 为 0，校验字节改用 DOS 时间高字节（小时）
            check = (_mtime >> 8) & 0xFF
        else:
            check = (crc >> 24) & 0xFF
        return header, check, target
    finally:
        zf.close()


def check_password(header, check, raw_password):
    keys = Keys()
    for b in raw_password:
        keys.update(b)
    value = 0
    for b in header:
        value = keys.decrypt(b)
    return value == check


def _verify(path, info, raw_password):
    try:
        with zipfile.ZipFile(path) as zf:
            data = zf.read(info.filename, pwd=raw_password)
        if info.CRC and zlib.crc32(data) != info.CRC:
            return None
        return data
    except Exception:
        return None


def crack_zip(path, hints=None, known=None, max_tries=None, deadline=None, log=None):
    """先做候选字典的头校验；命中后完整解密 + CRC 复核。"""
    log = log or (lambda m: None)
    started = time.time()
    header, check, info = zip_header_check(path)
    if header is None:
        return {"ok": False, "reason": info, "tried": 0, "seconds": 0.0}
    words = password_candidates(path, hints=hints, known=known)
    limit = max_tries or MAX_CANDIDATES
    tried = 0
    header_hits = 0
    for word in words:
        if tried >= limit:
            break
        if deadline and time.time() > deadline:
            break
        for raw in password_bytes(word):
            tried += 1
            if not check_password(header, check, raw):
                continue
            header_hits += 1
            data = _verify(path, info, raw)
            if data is not None:
                elapsed = round(time.time() - started, 3)
                log("ZipCrypto 口令命中：%r（候选 %d，头命中 %d，%.3fs）"
                    % (word, tried, header_hits, elapsed))
                return {"ok": True, "password": word, "password_bytes": raw,
                        "member": info.filename, "size": len(data),
                        "tried": tried, "header_hits": header_hits,
                        "seconds": elapsed}
    elapsed = round(time.time() - started, 3)
    return {"ok": False, "reason": "候选未命中", "tried": tried,
            "header_hits": header_hits, "seconds": elapsed}


def _john_paths():
    try:
        from .toolsmgr import get_tool
        john = get_tool("john")
    except Exception:
        john = ""
    if not john or not os.path.isfile(john):
        return "", ""
    run_dir = os.path.dirname(os.path.abspath(john))
    zip2john = os.path.join(run_dir, "zip2john.exe")
    if not os.path.isfile(zip2john):
        zip2john = os.path.join(run_dir, "zip2john.py")
    return john, zip2john


def john_crack(path, outdir, hints=None, timeout=90, log=None):
    """john PKZIP 深度回退：password.lst + rules，带超时与会话隔离。"""
    log = log or (lambda m: None)
    john, zip2john = _john_paths()
    if not john or not zip2john:
        return {"ok": False, "reason": "未找到随包 john/zip2john"}
    os.makedirs(outdir, exist_ok=True)
    hash_file = os.path.join(outdir, "zipcrack.hash")
    pot_file = os.path.join(outdir, "zipcrack.pot")
    for stale in (hash_file, pot_file):
        try:
            if os.path.isfile(stale):
                os.remove(stale)
        except Exception:
            pass
    try:
        if zip2john.lower().endswith(".exe"):
            proc = subprocess.run([zip2john, path], capture_output=True, timeout=30)
        else:
            proc = subprocess.run(["python", zip2john, path], capture_output=True, timeout=30)
        text = (proc.stdout or b"").decode("utf-8", "replace")
        line = next((ln for ln in text.splitlines() if "$pkzip" in ln), "")
        if not line:
            return {"ok": False, "reason": "zip2john 未生成 PKZIP 哈希"}
        with open(hash_file, "w", encoding="utf-8") as fp:
            fp.write(line + "\n")
    except Exception as exc:
        return {"ok": False, "reason": "zip2john 失败：%s" % exc}

    wordlist = os.path.join(os.path.dirname(john), "password.lst")
    args = [john, "--format=PKZIP", "--pot=" + pot_file,
            "--session=" + os.path.join(outdir, "zipcrack")]
    if os.path.isfile(wordlist):
        args += ["--wordlist=" + wordlist, "--rules"]
    else:
        return {"ok": False, "reason": "john 缺少 password.lst"}
    args.append(hash_file)
    try:
        log("john 深度回退：password.lst + rules，超时 %ds" % timeout)
        subprocess.run(args, capture_output=True, timeout=max(10, timeout))
    except subprocess.TimeoutExpired:
        log("john 达到超时，保留已写入 pot 的结果")
    except Exception as exc:
        return {"ok": False, "reason": "john 执行失败：%s" % exc}

    words = []
    try:
        with open(pot_file, encoding="utf-8", errors="replace") as fp:
            for line in fp:
                if ":" in line:
                    words.append(line.split(":", 1)[1].rstrip("\r\n"))
    except Exception:
        pass
    header, check, info = zip_header_check(path)
    if header is None:
        return {"ok": False, "reason": info}
    for word in words:
        for raw in password_bytes(word):
            data = _verify(path, info, raw)
            if data is not None:
                return {"ok": True, "password": word, "password_bytes": raw,
                        "member": info.filename, "size": len(data),
                        "tried": 0, "source": "john"}
    return {"ok": False, "reason": "john 未命中"}
