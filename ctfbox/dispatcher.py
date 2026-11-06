# -*- coding: utf-8 -*-
"""一把梭调度器：识别 -> 分流分析 -> 雕刻/字符串 -> 递归。"""
import os
import re
import sys
import json
import sqlite3
import subprocess
from .common import (Report, WORKSPACE, file_hashes, human_size, scan_flags,
                     extract_strings, try_decode_text)
from . import identifier
from . import modules_text
from . import modules_image
from . import modules_archive
from . import modules_carve
from . import modules_traffic
from . import modules_reverse
from . import modules_stego
from . import modules_document
from . import modules_crypto
from . import modules_codes
from . import modules_forensics
from . import modules_pyre
from . import modules_log
from . import modules_polar
from . import modules_audio

MAX_DEPTH = 4
MAX_FILES = 300
MAX_TOTAL_BYTES = 500 * 1024 * 1024


def _zip_fingerprint(path):
    """压缩包内容指纹：成员名+CRC+未压缩大小。
    修复 ZIP 与雕刻 ZIP 常是同一容器的两份副本（尾部垃圾字节不同），
    用成员指纹可识别这类重复，避免整棵子树分析两遍。无法读取时返回 None。"""
    try:
        import zipfile as _zf
        with _zf.ZipFile(path) as z:
            members = sorted((i.filename, i.CRC, i.file_size) for i in z.infolist())
        if not members:
            return None
        return "zip:" + "|".join(f"{n}:{c}:{s}" for n, c, s in members)
    except Exception:
        return None


class Dispatcher:
    def __init__(self, log_cb=print, max_depth=MAX_DEPTH, flag_patterns=None):
        self.log = log_cb
        self.max_depth = max_depth
        self.visited = set()
        self.count = 0
        self.total_bytes = 0
        self.flag_patterns = flag_patterns
        self.crc_consumed = set()   # 已由 CRC 套件批量处理的编号小 zip，递归时跳过
        self.seen_hashes = set()    # 已分析文件的 SHA256，内容相同的文件只分析一次
        self.seen_archfp = set()    # 已分析压缩包的成员指纹（文件名+CRC+大小）

    def run(self, path: str) -> Report:
        self.log(f"[*] 开始分析: {path}")
        report = self._analyze(path, depth=0)
        flags = report.flags()
        if flags:
            self.log("=" * 60)
            for rpath, f in flags:
                self.log(f"[!!!] FLAG 发现: {f.detail or f.title}  (来源: {os.path.basename(rpath)})")
            self.log("=" * 60)
        else:
            self.log("[*] 自动流程未直接匹配 flag，请查看上方可疑结果或换用手动工具页")
        return report

    def _analyze(self, path: str, depth: int) -> Report:
        path = os.path.abspath(path)
        if not os.path.isfile(path):
            return Report(path=path)
        st = os.stat(path)
        key = (st.st_size, st.st_mtime_ns, path)
        if key in self.visited:
            return Report(path=path)
        self.visited.add(key)
        # 内容级去重（仅递归层）：修复副本/雕刻副本会解出字节完全相同的成员，
        # SHA256 相同的文件只分析一次，避免重复 flag 与重复结论刷屏。
        early_hsh = None
        if depth >= 1 and st.st_size <= 50 * 1024 * 1024:
            try:
                early_hsh = file_hashes(path)
                if early_hsh["sha256"] in self.seen_hashes:
                    self.log("  " * depth + f"[-] 内容与已分析文件相同，跳过: {os.path.basename(path)}")
                    return Report(path=path)
                self.seen_hashes.add(early_hsh["sha256"])
            except Exception:
                early_hsh = None
        self.count += 1
        self.total_bytes += st.st_size
        if self.count > MAX_FILES:
            return Report(path=path, findings=[], category="skipped")
        if self.total_bytes > MAX_TOTAL_BYTES:
            return Report(path=path)

        indent = "  " * depth
        try:
            info = identifier.identify(path)
        except Exception as e:
            self.log(f"{indent}[!] 识别失败 {path}: {e}")
            return Report(path=path)
        rep = Report(path=path, category=info.category, ftype=info.ftype)
        self.log(f"{indent}[+] {os.path.basename(path)} -> {info.ftype} (熵 {info.entropy:.3f}, {human_size(info.size)})")

        outdir = os.path.join(WORKSPACE, "out_" + re.sub(r"[^\w.-]", "_", os.path.basename(path))[:40] + f"_{abs(hash(path)) % 0xffff:04x}")
        os.makedirs(outdir, exist_ok=True)

        # 基础信息
        try:
            hsh = early_hsh or file_hashes(path)
            rep.add("info", "文件指纹",
                    f"大小: {info.size} ({human_size(info.size)})\n"
                    f"MD5: {hsh['md5']}\nSHA1: {hsh['sha1']}\nSHA256: {hsh['sha256']}\nCRC32: {hsh['crc32']}")
            rep.add("info", "文件头(Hex)", info.head_hex)
        except Exception as e:
            rep.add("warn", "指纹计算失败", str(e))

        with open(path, "rb") as f:
            raw = f.read() if info.size <= 50 * 1024 * 1024 else f.read(20 * 1024 * 1024)

        # 全文件 flag 粗扫（文本/小文件）。只把【强匹配】(flag{}/已知前缀) 直接提升为 flag，
        # 避免弱模式在高熵二进制/样式表上的 word{...} 误报 flooding。
        if info.size <= 10 * 1024 * 1024:
            for fl in scan_flags(raw, strong_only=True):
                rep.add("flag", "文件内容直接包含 flag", fl)

        # NTFS 备用数据流（任意类型文件都可能挂 ADS）
        if sys.platform.startswith("win") and depth == 0:
            try:
                streams = modules_forensics.list_ads(path)
                if streams:
                    modules_forensics.extract_ads(path, rep, os.path.join(outdir, "ads"))
            except Exception:
                pass

        # 压缩包成员指纹去重（仅递归层）：同一容器经"修复 ZIP"与"ZIP 雕刻"
        # 两条路径各产出一份副本（尾部垃圾字节不同，文件哈希不同），成员一致时只分析一次。
        if depth >= 1 and info.category == "archive":
            afp = _zip_fingerprint(path)
            if afp and afp in self.seen_archfp:
                self.log(f"{indent}[-] 压缩包成员与已分析容器相同，跳过: {os.path.basename(path)}")
                rep.add("info", "重复压缩包已跳过",
                        "成员列表/CRC 与前面分析过的容器一致（修复副本与雕刻副本重复）")
                return rep
            if afp:
                self.seen_archfp.add(afp)

        # ---- 分流 ----
        try:
            if info.category == "text":
                self._text_flow(path, raw, rep, indent)
                # 正文里单独藏着的 base64 / hex 片段，主流程常按哈希处理，这里再扫一遍
                try:
                    from . import textscan
                    textscan.encoded_token_scan(raw.decode("utf-8", "replace"), rep)
                except Exception:
                    pass
            elif info.category == "image":
                # 文件头与图片 magic 不符（被加垃圾头/篡改）时先修复，修复副本会递归分析
                img_magics = (b"\x89PNG", b"\xff\xd8\xff", b"GIF8", b"BM", b"II*\x00",
                              b"MM\x00*", b"RIFF", b"\x00\x00\x01\x00", b"\x00\x00\x02\x00")
                if not raw.startswith(img_magics):
                    try:
                        modules_stego.repair_file(path, rep, outdir)
                    except Exception:
                        pass
                modules_image.analyze(path, rep)
                # 图片马 / 多态脚本
                try:
                    modules_forensics.scan_polyglot(path, rep, os.path.join(outdir, "polyglot"))
                except Exception:
                    pass
                # steghide 隐写链（jpg/wav/bmp）
                if info.ext in (".jpg", ".jpeg", ".bmp", ".wav", ".au"):
                    try:
                        modules_forensics.steghide_chain(path, rep, out_dir=os.path.join(outdir, "steghide"))
                    except Exception:
                        pass
                # F5 隐写提取（JPEG，随包 Java + F5 class）
                if info.ext in (".jpg", ".jpeg"):
                    try:
                        modules_polar.f5_extract_chain(path, rep, os.path.join(outdir, "f5"))
                    except Exception:
                        pass
                self._exiftool(path, rep)
                modules_carve.scan_and_carve(path, rep, outdir, depth=depth)
                modules_carve.strings_scan(path, rep)
            elif info.category == "archive":
                # ZIP 伪加密修复（本地头/中央目录标志位不一致），修复副本加入递归
                try:
                    if path.lower().endswith(".zip"):
                        fixed_zip = modules_polar.repair_fake_encrypted_zip(
                            path, os.path.join(outdir, "fake_enc_fix"))
                        if fixed_zip:
                            rep.add("ok", "检测到 ZIP 伪加密，已生成修复副本", fixed_zip)
                            if fixed_zip not in rep.extracted:
                                rep.extracted.append(fixed_zip)
                except Exception:
                    pass
                modules_archive.analyze(path, rep, info.ftype, outdir)
                # Office 文档（.docx 常被识别为 ZIP）多点隐写拼接
                if path.lower().endswith(".docx"):
                    try:
                        modules_polar.docx_multistego(path, rep)
                    except Exception as e:
                        rep.add("info", "docx 多点隐写跳过", str(e)[:100])
                # ZIP / Office 包注释里可能藏密码或多进制/培根密文
                if path.lower().endswith((".zip", ".docx", ".xlsx", ".pptx", ".jar")):
                    try:
                        modules_polar.analyze_zip_comments(path, rep)
                    except Exception:
                        pass
                modules_carve.scan_and_carve(path, rep, outdir, carve=False, depth=depth)
                consumed = self._crc_suite_after_extract(outdir, rep)
                if consumed:
                    # 这些编号小 zip 已由 CRC 套件批量碰撞统一处理，递归时跳过，避免逐一起进程池
                    self.crc_consumed |= consumed
            elif info.category == "capture":
                modules_traffic.analyze(path, rep, outdir)
            elif info.category == "executable":
                self._executable_flow(path, raw, rep, info, outdir, depth)
            elif info.category == "forensic":
                self._forensic_flow(path, raw, rep, info, outdir, depth)
            elif info.category == "database":
                self._sqlite(path, rep)
            elif info.category == "crypto":
                self._crypto_artifact(path, raw, rep)
            elif info.category == "document":
                self._document(path, raw, rep, info, outdir, depth)
            elif info.category == "media":
                ext = info.ext.lower()
                is_video = (ext not in modules_audio.AUDIO_EXTS) and (
                            "视频" in info.ftype or
                            ext in (".mp4", ".mov", ".mkv", ".webm", ".flv", ".avi", ".ts",
                                    ".m4v", ".wmv", ".3gp", ".mpg", ".mpeg", ".m2ts", ".ogv"))
                is_audio = (ext in modules_audio.AUDIO_EXTS or
                            ("音频" in info.ftype and not is_video) or
                            (ext == ".wav") or (raw[:12].find(b"WAVE") in (8, 9, 10) and not is_video))
                if is_video:
                    from . import modules_video
                    try:
                        modules_video.analyze(path, rep, outdir)
                    except Exception as e:
                        rep.add("info", "视频分析跳过", str(e)[:120])
                if is_audio:
                    # 音频隐写全套（解码/元数据/多位面LSB/语谱图/波形/DTMF/摩斯/FSK/
                    # 中置侧置/反转/尾部附加/DeepSound 痕迹/steghide）
                    try:
                        modules_audio.analyze(path, rep, os.path.join(outdir, "audio"))
                    except Exception as e:
                        rep.add("info", "音频分析跳过", str(e)[:120])
                self._exiftool(path, rep)
                modules_carve.scan_and_carve(path, rep, outdir, depth=depth)
                modules_carve.strings_scan(path, rep)
            else:
                # 未知 / 取证镜像：先尝试文件头修复（垃圾头/magic 损坏），再雕刻 + strings
                try:
                    modules_stego.repair_file(path, rep, outdir)
                except Exception:
                    pass
                modules_carve.scan_and_carve(path, rep, outdir, depth=depth)
                modules_carve.strings_scan(path, rep)
                if info.extra.get("suspect_encrypted"):
                    rep.add("warn", "高熵无签名", "疑似加密容器(VeraCrypt/TrueCrypt/BitLocker)或压缩数据，"
                                              "取证题可用 volatility/磁盘工具；密码题尝试已知口令挂载")
        except Exception as e:
            import traceback
            rep.add("warn", "分析模块异常", f"{type(e).__name__}: {e}\n{traceback.format_exc()[:500]}")
            self.log(f"{indent}[!] 模块异常: {e}")

        # binwalk 增强（若安装）
        self._binwalk(path, rep)

        # ---- 递归 ----
        for fp in list(dict.fromkeys(rep.extracted)):
            if not os.path.isfile(fp):
                continue
            if os.path.abspath(fp) in self.crc_consumed:
                continue    # 已由 CRC 套件统一碰撞，无需单独递归
            if depth + 1 > self.max_depth:
                rep.add("info", "递归深度限制", f"跳过 {fp}")
                continue
            child = self._analyze(fp, depth + 1)
            rep.children.append(child)

        # 汇总日志
        for fnd in rep.findings:
            icon = {"flag": "[!!!]", "ok": "[+]", "warn": "[!]", "info": "[*]", "tool": "[TOOL]"}.get(fnd.level, "[*]")
            self.log(f"{indent}{icon} {fnd.title}" + (f": {fnd.detail[:200]}" if fnd.detail else ""))
        return rep

    # ------------------------------------------------------------------
    def _text_flow(self, path, raw, rep: Report, indent):
        is_text, enc, text = try_decode_text(raw)
        if not text:
            text = raw.decode("utf-8", errors="replace")
        rep.add("info", "文本编码", enc or "utf-8(replace)")
        tx_out = os.path.join(WORKSPACE, "polar_" + re.sub(r"[^\w.-]", "_", os.path.basename(path))[:30])
        # Web 访问日志（access.log / nginx / IIS 等）
        try:
            log_hits = len(re.findall(r'(?:GET|POST|PUT|DELETE|HEAD|OPTIONS)\s+\S+\s+HTTP/', text))
            ip_lines = len(re.findall(r'^\d{1,3}(?:\.\d{1,3}){3}\b', text, re.M))
            if log_hits >= 5 or (log_hits >= 3 and ip_lines >= 3):
                modules_log.analyze_weblog(path, rep, os.path.join(
                    os.path.dirname(path) or ".", "weblog_out"))
        except Exception as e:
            rep.add("info", "日志分析跳过", str(e)[:80])
        # 零宽 / 不可见字符隐写
        try:
            modules_stego.analyze_zero_width(text, rep)
        except Exception as e:
            rep.add("info", "零宽分析跳过", str(e)[:80])
        # Polar 套路：0/255、0/1 像素矩阵还原二维码
        try:
            qr = modules_polar.pixel_matrix_qr(text, tx_out)
            if qr:
                png, qdata = qr
                rep.add("ok", "像素矩阵还原二维码", f"图像: {png}\n内容: {qdata}")
                if qdata:
                    rep.add("flag", "像素矩阵二维码内容", qdata)
                    for fl in scan_flags(qdata.encode("utf-8", "ignore")):
                        rep.add("flag", "像素矩阵二维码 flag", fl)
        except Exception as e:
            rep.add("info", "像素矩阵二维码跳过", str(e)[:80])
        # Polar 套路：data:image/...;base64 内嵌图片（还原后递归分析）
        try:
            for imgp in modules_polar.data_uri_images(text, tx_out):
                if imgp not in rep.extracted:
                    rep.extracted.append(imgp)
                rep.add("ok", "data URI 内嵌图片已还原", imgp)
        except Exception:
            pass
        # 兽音译者变体（自定义四符号，如 喵/呜/啊/~）
        try:
            rv = modules_polar.roar_variant_decode(text)
            if rv:
                rep.add("ok", "兽音变体解码", rv[:500])
                for fl in scan_flags(rv.encode("utf-8", "ignore")):
                    rep.add("flag", "兽音变体解出 flag", fl)
        except Exception:
            pass
        # 特殊编码 / 密码学密文自动识别（兽音/盲文/云影/QWE/Base100/JWT/AAEncode 等）
        try:
            special = modules_codes.detect_special(text)
            for title, val, _score in special[:12]:
                rep.add("ok", title, (val or "")[:1000])
                if val:
                    for fl in scan_flags(val.encode("utf-8", "ignore"), strong_only=True):
                        rep.add("flag", title + " 解出 flag", fl)
        except Exception as e:
            rep.add("info", "特殊编码识别跳过", str(e)[:80])
        # 国内特色编码：核心价值观 / 与佛论禅
        if all(w in text for w in ("富强", "民主")) and sum(text.count(w) for w in
           ("富强", "民主", "文明", "和谐", "自由", "平等", "公正", "法治",
            "爱国", "敬业", "诚信", "友善")) >= 6:
            try:
                val = modules_text.core_values_decode(text)
                rep.add("ok", "社会主义核心价值观解码", val[:1000])
                for fl in scan_flags(val.encode("utf-8", "ignore")):
                    rep.add("flag", "核心价值观解出 flag", fl)
            except Exception as e:
                rep.add("info", "核心价值观解码跳过", str(e)[:80])
        if "佛曰" in text or "如是我闻" in text:
            try:
                val = modules_text.tudou_decode(text)
                rep.add("ok", "与佛论禅(TudouCode)解码", val[:1000])
                for fl in scan_flags(val.encode("utf-8", "ignore")):
                    rep.add("flag", "与佛论禅解出 flag", fl)
            except Exception as e:
                rep.add("info", "与佛论禅解码跳过", str(e)[:80])
        # 新约佛论禅（与佛论禅新版变种）
        if "新约" in text and ("佛" in text or "：" in text):
            try:
                from .modules_codes import foyinjutsu_decode
                val = foyinjutsu_decode(text)
                rep.add("ok", "新约佛论禅解码", val[:1000])
                for fl in scan_flags(val.encode("utf-8", "ignore")):
                    rep.add("flag", "新约佛论禅解出 flag", fl)
            except Exception:
                pass
        # 哈希识别
        for token in set(re.findall(r"\b[A-Za-z0-9$./]{8,140}\b", text)):
            kinds = modules_text.identify_hash(token)
            if kinds and "未识别" not in kinds[0]:
                rep.add("ok", f"疑似哈希: {token[:40]}…", ", ".join(kinds))
                cracked = modules_text.crack_hash(token)
                if cracked:
                    rep.add("flag", f"哈希 {token[:20]}… 爆破成功",
                            f"明文: {cracked[0]} ({cracked[1]})")
        # 自动链式解码
        # 降噪：原文已直接含强 flag 时，只展示高分链或能解出【新】flag 的链，
        # 不再罗列 Base91/ROT 之类对普通英文文本必然产生的无意义结果。
        existing_flags = {f.detail for f in rep.findings if f.level == "flag"}
        results = modules_text.auto_decode(text, depth=3)

        def _chain_readable(v):
            """解码结果是否真的像自然语言（过滤 Base85/91 乱码与半残 ROT 链）。"""
            if not v or not v.strip():
                return False
            if re.search(r"[\x00-\x08\x0b\x0c\x0e-\x1f]", v):
                return False
            compact = re.sub(r"\s", "", v)
            if len(compact) < 8:
                return False
            printable = sum(1 for c in compact if 32 <= ord(c) < 127 or 0x4e00 <= ord(c) <= 0x9fff)
            if printable / len(compact) < 0.95:
                return False
            cn = len(re.findall(r"[\u4e00-\u9fff]", compact))
            if cn:
                return cn / len(compact) >= 0.3          # 以中文为主才算中文解码
            letters = re.findall(r"[a-z]", v.lower())
            if not letters:
                return False
            hit = sum(len(w) for w in modules_text.COMMON_WORDS if w in v.lower())
            return hit / len(letters) >= 0.6            # 大部分字母要落在真实单词上

        shown = 0
        for chain, val, score in results[:15]:
            val = val or ""
            # 恒等解码（输出与输入完全相同，如 ROT47->ROT47）没有信息量，直接丢弃
            if val.strip() and val.strip() == text.strip():
                continue
            chain_flags = [fl for fl in scan_flags(val.encode("utf-8", "ignore"),
                                                   strong_only=True)
                           if fl not in existing_flags]
            if not chain_flags:
                # 原文/本文件已拿到强 flag：不再展示任何解不出新 flag 的链
                if existing_flags:
                    continue
                # 无 flag 时必须真正像自然语言，挡住 xxx{...} 形状加分与乱码假阳性
                if not _chain_readable(val):
                    continue
            rep.add("ok" if score >= 6 else "info", f"解码链: {chain}", val[:1000])
            for fl in chain_flags:
                rep.add("flag", f"{chain} 解出 flag", fl)
                existing_flags.add(fl)
            shown += 1
        if not results:
            rep.add("info", "自动解码", "未匹配常见编码")

    def _crc_suite_after_extract(self, outdir, rep: Report):
        """解压后若出现一批 outN.zip / 编号小压缩包，自动做跨文件 CRC 套件碰撞。
        返回被套件统一处理掉的 zip 绝对路径集合（调用方据此跳过逐个递归）。"""
        consumed = set()
        try:
            zips = []
            for root, _, files in os.walk(outdir):
                for f in files:
                    if f.lower().endswith(".zip"):
                        zips.append(os.path.abspath(os.path.join(root, f)))
            numbered = [z for z in zips if re.search(r"\d+", os.path.basename(z))]
            if len(numbered) >= 3:
                numbered = sorted(numbered)
                consumed |= set(numbered)
                sub = Report("crc_suite")
                modules_archive.analyze_crc_suite(
                    numbered, sub, os.path.join(outdir, "crc_suite"))
                for fnd in sub.findings:
                    rep.add(fnd.level, "[CRC套件] " + fnd.title, fnd.detail, fnd.data)
                rep.extracted.extend(sub.extracted)
        except Exception as e:
            rep.add("info", "CRC 套件分析跳过", str(e)[:100])
        return consumed

    def _executable_flow(self, path, raw, rep, info, outdir, depth):
        name = os.path.basename(path).lower()
        # Python 字节码
        if info.ext in (".pyc", ".pyo") or raw[:2] in (b"\x42\x0d", b"\x55\x0d", b"\x6f\x0d",
                                                        b"\xa7\x0d", b"\xcb\x0d", b"\xee\x0c"):
            try:
                modules_pyre.decompile_pyc(path, rep, outdir)
            except Exception as e:
                rep.add("info", "pyc 反编译跳过", str(e)[:120])
        # PE / ELF：常规逆向
        if info.category == "executable" and raw[:2] in (b"MZ", b"\x7fELF"):
            modules_reverse.analyze(path, rep, info.ftype, outdir)
            self._die(path, rep)
            # PyInstaller 解包
            try:
                if modules_pyre.extract_pyinstaller(path, rep, outdir):
                    rep.add("ok", "PyInstaller", "已解包内置 Python 程序，可对其中 pyc 再反编译")
            except Exception as e:
                rep.add("info", "PyInstaller 解包跳过", str(e)[:100])
            # PE 资源提取（图标/版本/内嵌文件）
            try:
                modules_pyre.extract_pe_resources(path, rep, os.path.join(outdir, "pe_res"))
            except Exception as e:
                rep.add("info", "PE 资源提取跳过", str(e)[:100])
        # Electron asar
        if name.endswith(".asar"):
            try:
                modules_pyre.extract_asar(path, rep, os.path.join(outdir, "asar"))
            except Exception as e:
                rep.add("info", "ASAR 解包跳过", str(e)[:120])
        modules_carve.scan_and_carve(path, rep, outdir, depth=depth)
        modules_carve.strings_scan(path, rep)

    def _forensic_flow(self, path, raw, rep, info, outdir, depth):
        name = os.path.basename(path).lower()
        ext = info.ext
        # 注册表 hive
        if raw[:4] == b"regf" or name in ("sam", "system", "software", "security", "ntuser.dat") \
                or "ntuser" in name:
            try:
                modules_forensics.analyze_registry_hive(path, rep, os.path.join(outdir, "registry"))
            except Exception as e:
                rep.add("info", "注册表分析跳过", str(e)[:120])
        # Windows 事件日志
        if raw[:8] == b"ElfFile\x00" or ext == ".evtx":
            try:
                modules_forensics.analyze_evtx(path, rep, os.path.join(outdir, "evtx"))
            except Exception as e:
                rep.add("info", "evtx 分析跳过", str(e)[:120])
        # 磁盘 / 内存镜像（含 VMDK/VHD/raw）
        if raw[:4] == b"KDMV" or ext in (".vmdk", ".vhd", ".vhdx", ".vdi", ".ova",
                                         ".img", ".raw", ".dd", ".e01") or name.endswith(".img"):
            try:
                modules_forensics.extract_disk_image(path, rep, os.path.join(outdir, "disk"))
            except Exception as e:
                rep.add("info", "磁盘镜像分析跳过", str(e)[:120])
        # vim swap
        if ext in (".swp", ".swo", ".swn") or raw[:6] == b"b0VIM ":
            try:
                modules_forensics.recover_vim_swap(path, rep, os.path.join(outdir, "swap"))
            except Exception as e:
                rep.add("info", "swap 恢复跳过", str(e)[:120])
        # Electron asar（forensic 兜底）
        if ext == ".asar":
            try:
                modules_pyre.extract_asar(path, rep, os.path.join(outdir, "asar"))
            except Exception as e:
                rep.add("info", "ASAR 解包跳过", str(e)[:120])
        # 路由器配置 / 嵌入压缩流（超大固件/镜像全文件正则会卡死，限制 80MB）
        if "conf" in name or name.endswith((".bin", ".cfg", ".dat", ".bak")):
            try:
                if info.size <= 80 * 1024 * 1024:
                    modules_forensics.extract_embedded_streams(
                        path, rep, os.path.join(outdir, "streams"))
                else:
                    rep.add("info", "嵌入流提取跳过",
                            f"文件 {human_size(info.size)} 超过 80MB，仅做前 80MB 雕刻，"
                            "固件请用 binwalk/EMBA 手动分析，避免卡死")
            except Exception as e:
                rep.add("info", "嵌入流提取跳过", str(e)[:120])
        # 通用：雕刻 + strings，避免遗漏
        modules_carve.scan_and_carve(path, rep, outdir, carve=True, depth=depth)
        modules_carve.strings_scan(path, rep)

    def _sqlite(self, path, rep: Report):
        try:
            con = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
            cur = con.cursor()
            tables = [r[0] for r in cur.execute(
                "SELECT name FROM sqlite_master WHERE type='table'")]
            rep.add("ok", "SQLite 表", ", ".join(tables))
            for t in tables[:20]:
                try:
                    rows = cur.execute(f'SELECT * FROM "{t}" LIMIT 50').fetchall()
                    cols = [d[0] for d in cur.description]
                    lines = [" | ".join(map(str, cols))]
                    for row in rows:
                        lines.append(" | ".join(str(x) for x in row))
                    blob = "\n".join(lines)
                    rep.add("info", f"表 {t} 前{len(rows)}行", blob[:3000])
                    for fl in scan_flags(blob.encode("utf-8", "ignore")):
                        rep.add("flag", f"表 {t} 中发现 flag", fl)
                except Exception:
                    pass
            con.close()
        except Exception as e:
            rep.add("warn", "SQLite 读取失败", str(e))

    def _crypto_artifact(self, path, raw, rep: Report):
        head = raw[:40].decode("latin-1", "replace")
        rep.add("info", "PEM/密钥文件", head.replace("\n", " "))
        # RSA 参数解析 / 分解 / 私钥恢复
        try:
            with open(path, "rb") as f:
                full = f.read() if os.path.getsize(path) <= 20 * 1024 * 1024 else f.read(2 * 1024 * 1024)
            modules_crypto.analyze_rsa(full, rep)
        except Exception as e:
            rep.add("info", "RSA 分析跳过", str(e)[:100])
        kind = {
            "RSA PRIVATE KEY": "RSA 私钥", "EC PRIVATE KEY": "EC 私钥",
            "OPENSSH PRIVATE KEY": "OpenSSH 私钥",
            "CERTIFICATE": "X.509 证书", "PUBLIC KEY": "公钥",
        }
        for k, v in kind.items():
            if k in head:
                rep.add("ok", "密钥类型", v)
        if "PRIVATE KEY" in head:
            rep.add("info", "CTF 提示",
                    "若提示加密私钥：尝试 ssh2john + john 爆破口令；"
                    "RSA 小模数可做 n 分解(dp/dq)或低私钥指数攻击")
        # 尝试解析证书/公钥信息
        try:
            from cryptography.hazmat.primitives import serialization
            if b"CERTIFICATE" in raw:
                from cryptography import x509
                cert = x509.load_pem_x509_certificate(raw)
                rep.add("info", "证书信息",
                        f"主体: {cert.subject.rfc4514_string()}\n签发: {cert.issuer.rfc4514_string()}\n"
                        f"有效期: {cert.not_valid_before_utc} ~ {cert.not_valid_after_utc}")
            elif b"PRIVATE KEY" in raw:
                k = serialization.load_pem_private_key(raw, password=None)
                rep.add("info", "私钥参数", f"密钥大小: {k.key_size} bit")
        except Exception as e:
            rep.add("info", "密钥解析", f"可能有口令保护: {str(e)[:120]}")

    def _document(self, path, raw, rep, info, outdir, depth=0):
        # docx/xlsx/pptx 本质 zip：先归档解压/爆破，再做 Office 专项分析
        if raw[:2] == b"PK":
            from . import modules_archive
            modules_archive.analyze(path, rep, "ZIP", outdir)
            # docx/xlsx/pptx 多点隐写（白字/隐藏文字/嵌入对象/文档属性拼接）
            if path.lower().endswith(".docx"):
                try:
                    modules_polar.docx_multistego(path, rep)
                except Exception as e:
                    rep.add("info", "docx 多点隐写跳过", str(e)[:100])
            # Office 包也是 ZIP，注释里可能藏密码/ASCII
            if path.lower().endswith(".zip"):
                try:
                    modules_polar.analyze_zip_comments(path, rep)
                except Exception:
                    pass
            try:
                modules_document.analyze_office(path, rep, outdir)
            except Exception as e:
                rep.add("info", "Office 专项分析跳过", str(e)[:100])
            return
        # PDF 深度分析
        if raw[:4] == b"%PDF":
            rep.add("info", "PDF", "提取元数据/动作/JS/表单/嵌入对象…")
            try:
                with open(path, "rb") as f:
                    pdfraw = f.read() if info.size <= 60 * 1024 * 1024 else f.read(60 * 1024 * 1024)
                modules_document.analyze_pdf(path, pdfraw, rep, outdir)
            except Exception as e:
                rep.add("info", "PDF 专项分析跳过", str(e)[:100])
            modules_carve.scan_and_carve(path, rep, outdir, depth=depth)
            return
        # OLE(doc/xls/msi)
        modules_carve.scan_and_carve(path, rep, outdir, depth=depth)
        modules_carve.strings_scan(path, rep)
        rep.add("info", "OLE 复合文档", "可在工具中心安装 oletools(pip) 做宏分析")

    # ---- 外部工具增强 ----
    def _exiftool(self, path, rep):
        from .toolsmgr import get_tool
        p = get_tool("exiftool")
        if not p:
            return
        try:
            r = subprocess.run([p, "-j", "-charset", "filename=utf8", path],
                               capture_output=True, timeout=60)
            if r.returncode == 0:
                data = json.loads(r.stdout.decode("utf-8", "replace"))
                if data:
                    keep = {k: v for k, v in data[0].items()
                            if k not in ("SourceFile", "ExifToolVersion", "File:FileSize",
                                         "File:FilePermissions", "File:Directory")
                            and not str(v).startswith("(Binary")}
                    txt = json.dumps(keep, ensure_ascii=False, indent=1)[:3000]
                    rep.add("info", "ExifTool 元数据", txt)
                    for fl in scan_flags(txt.encode("utf-8")):
                        rep.add("flag", "ExifTool 元数据中发现 flag", fl)
        except Exception:
            pass

    def _die(self, path, rep):
        from .toolsmgr import get_tool
        p = get_tool("die")
        if not p or not os.path.basename(p).lower().startswith("diec"):
            return  # 必须用命令行版 diec，GUI 版不支持 -j
        try:
            r = subprocess.run([p, "-j", path], capture_output=True, timeout=60)
            if r.returncode == 0 and r.stdout.strip():
                try:
                    data = json.loads(r.stdout.decode("utf-8", "replace"))
                    root = data[0] if isinstance(data, list) else data
                    lines = []
                    for det in root.get("detects", []):
                        for v in det.get("values", []):
                            lines.append(f"[{v.get('type','?')}] {v.get('string') or v.get('name','')}")
                    if lines:
                        rep.add("ok", "DIE 检测结果", "\n".join(lines[:15]))
                except Exception:
                    txt = r.stdout.decode("latin-1", "replace")[:1000]
                    if txt.strip():
                        rep.add("info", "DIE 检测结果", txt)
        except Exception:
            pass

    def _binwalk(self, path, rep):
        # 仅当本进程可直接 import binwalk 时调用（禁止用 sys.executable 重启 exe）
        try:
            import binwalk  # noqa: F401
        except Exception:
            return
        try:
            import binwalk as bw
            res = bw.scan(path, quiet=True, signature=True)
            lines = []
            for module in res:
                for item in module.results:
                    lines.append(f"0x{item.offset:X} {item.description}")
            if len(lines) > 1:
                rep.add("info", "binwalk 签名扫描", "\n".join(lines[:30]))
        except Exception:
            pass
