# -*- coding: utf-8 -*-
"""古典 / 现代 / 特色编码密码扩展模块。

设计原则：全部为通用算法实现，不包含任何具体题目答案；
能纯 Python 完成的不依赖外部环境，必须 JS 引擎的（AAencode/JSFuck/JJencode）
通过本机 node 的 vm 沙箱求值（仅执行用户主动输入/拖入的文本，3 秒超时）。
"""
import os
import re
import io
import sys
import json
import base64
import shutil
import hmac
import struct
import hashlib
import subprocess
import itertools
from string import ascii_lowercase, ascii_uppercase, digits, printable

from .modules_text import (
    readable_score, is_readable, caesar, morse_decode, brainfuck,
    b58_decode, b91_decode, b92_decode,
)

B64STD = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"


def _to_bytes(x: str) -> bytes:
    """智能把 hex/base64/原始文本转成字节（XOR/对称加密用）。"""
    t = x.strip()
    # hex
    h = re.sub(r"^(0x|\\x)", "", t).replace(" ", "").replace("\\x", "")
    if len(h) >= 2 and len(h) % 2 == 0 and re.fullmatch(r"[0-9a-fA-F]+", h):
        try:
            return bytes.fromhex(h)
        except Exception:
            pass
    # base64
    try:
        if len(t) >= 8 and not re.search(r"[\u4e00-\u9fff]", t):
            pad = t + "=" * (-len(t) % 4)
            b = base64.b64decode(pad, validate=False)
            if b and len(b) < len(t) * 0.8:
                return b
    except Exception:
        pass
    return t.encode("utf-8", errors="replace")


def _bytes_to_text(b: bytes) -> str:
    for enc in ("utf-8", "gbk", "latin-1"):
        try:
            return b.decode(enc)
        except Exception:
            continue
    return b.decode("utf-8", errors="replace")


# ============================================================================
# Base64 隐写（利用末块填充位藏数据，CTF 高频题，含"="被替换的变体）
# ============================================================================
def _b64_bits_from_char_index(idx: int, nbits: int) -> str:
    return format(idx, "06b")[-nbits:]


def base64_steg_extract(text: str):
    """返回 [(方案名, 解出文本)]，自动按可读性排序。"""
    lines = [ln.strip() for ln in re.split(r"[\r\n]+", text) if ln.strip()]
    # 也支持整串无换行的 base64：按 76 字符或整块无法判断，仅逐行模式可靠
    candidates = {}

    def bits_to_str(bits: str):
        out = []
        n = len(bits) // 8 * 8
        for i in range(0, n, 8):
            v = int(bits[i:i + 8], 2)
            out.append(chr(v))
        return "".join(out)

    # 方案 A：显式 '='（末块 1 个 = 取最后有效字符低 2 位；2 个 = 取低 4 位）
    bits = ""
    for ln in lines:
        pad = ln.count("=")
        core = ln.rstrip("=")
        if pad == 1 and core:
            bits += _b64_bits_from_char_index(B64STD.index(core[-1]), 2) if core[-1] in B64STD else ""
        elif pad >= 2 and core:
            bits += _b64_bits_from_char_index(B64STD.index(core[-1]), 4) if core[-1] in B64STD else ""
    if len(bits) >= 8:
        candidates["显式=号填充位"] = bits_to_str(bits)

    # 方案 B：'=' 被替换为任意字符。逐行尝试多种取位约定，整体评分选最优
    if all(set(ln) <= set(B64STD) and len(ln) % 4 == 0 for ln in lines) and len(lines) > 1:
        schemes = {
            "替换版/末字符低2位": lambda ln: _b64_bits_from_char_index(B64STD.index(ln[-1]), 2),
            "替换版/倒数第2字符低2位": lambda ln: _b64_bits_from_char_index(B64STD.index(ln[-2]), 2),
            "替换版/倒数第2字符低4位": lambda ln: _b64_bits_from_char_index(B64STD.index(ln[-2]), 4),
        }
        for name, fn in schemes.items():
            bits = ""
            ok = True
            for ln in lines:
                try:
                    bits += fn(ln)
                except Exception:
                    ok = False
                    break
            if ok and len(bits) >= 8:
                candidates[name] = bits_to_str(bits)

    # 方案 C：不分行的连续 base64，按 4 字符块扫描，仅取末块（最后一块）
    scored = sorted(((readable_score(v), k, v) for k, v in candidates.items()),
                    key=lambda x: -x[0])
    return [(k, v) for _, k, v in scored if v]


# ============================================================================
# 盲文 Braille（U+2800 起；英文 6 点 + 数字 + 8 点原始字节两种解释）
# ============================================================================
# 点位: 1=0x01 2=0x02 3=0x04 4=0x08 5=0x10 6=0x20 7=0x40 8=0x80
_BRAILLE_DOTS = {
    "a": 0x01, "b": 0x03, "c": 0x09, "d": 0x19, "e": 0x11, "f": 0x0b,
    "g": 0x1b, "h": 0x13, "i": 0x0a, "j": 0x1a, "k": 0x05, "l": 0x07,
    "m": 0x0d, "n": 0x1d, "o": 0x15, "p": 0x0f, "q": 0x1f, "r": 0x17,
    "s": 0x0e, "t": 0x1e, "u": 0x25, "v": 0x27, "w": 0x3a, "x": 0x2d,
    "y": 0x3d, "z": 0x35,
}
_BRAILLE_PUNCT = {
    0x00: " ", 0x22: ".", 0x20 + 0x02: ",",  # 宽松匹配在代码中处理
}
_BRAILLE_DOT2CH = {v: k for k, v in _BRAILLE_DOTS.items()}
_BRAILLE_DIGITS = dict(zip("abcdefghij", "1234567890"))


def braille_decode(text: str) -> str:
    """英文 6 点盲文解码；数字符 ⠼ 后 a-j 转 1-0；同时尝试 8 点原始字节解释。"""
    cells = [ord(c) - 0x2800 for c in text if 0x2800 <= ord(c) <= 0x28FF]
    if not cells:
        raise ValueError("未发现盲文字符(U+2800~U+28FF)")
    out = []
    num_mode = False
    for v in cells:
        if v == 0x3C:          # ⠼ 数字符 dots 3,4,5,6
            num_mode = True
            continue
        if v == 0x00:
            out.append(" ")
            num_mode = False
            continue
        ch = _BRAILLE_DOT2CH.get(v & 0x3F)
        if ch is None:
            # 常见标点
            extra = {0x22: ".", 0x02: ",", 0x38: "(", 0x30: ")", 0x12: "?",
                     0x26: "!", 0x06: ";", 0x36: ":", 0x2a: "/", 0x23: "-",
                     0x33: "'", 0x0c: "*"}
            ch = extra.get(v & 0x3F, "?")
        if num_mode and ch in _BRAILLE_DIGITS:
            out.append(_BRAILLE_DIGITS[ch])
        else:
            out.append(ch.upper() if num_mode and ch != "?" else ch)
            if ch in " ?.!;,":
                num_mode = False
    letter = "".join(out)

    # 8 点原始字节解释（每盲文字符的 8 个点位直接对应一个字节）
    raw = bytes(v & 0xFF for v in cells)
    pr = sum(1 for b in raw if 9 <= b <= 13 or 32 <= b < 127) / max(1, len(raw))
    if pr > 0.9:
        raw_txt = _bytes_to_text(raw)
        return f"[字母映射] {letter}\n[8点原始字节] {raw_txt}"
    return letter


def braille_encode(text: str) -> str:
    out = []
    num_mode = False
    for c in text.lower():
        if c.isdigit():
            if not num_mode:
                out.append(chr(0x2800 + 0x3C))
                num_mode = True
            inv = {v: k for k, v in _BRAILLE_DIGITS.items()}
            out.append(chr(0x2800 + _BRAILLE_DOTS[inv[c]]))
        else:
            if num_mode:
                num_mode = False
            if c == " ":
                out.append(chr(0x2800))
            elif c in _BRAILLE_DOTS:
                out.append(chr(0x2800 + _BRAILLE_DOTS[c]))
    return "".join(out)


# ============================================================================
# 兽音译者（roar.iiilab.com）：嗷呜啊呀 四字符 = 2bit，固定头
# ============================================================================
ROAR_CHARS = ["嗷", "呜", "啊", "呀"]
ROAR_HEAD = "嗷呜啊呀嗷~"


def roar_decode(text: str) -> str:
    body = text
    for head in ("嗷呜啊呀嗷~", "嗷呜啊呀嗷", "嗷呜啊呀"):
        if head in body:
            body = body.split(head, 1)[1]
            break
    body = "".join(c for c in body if c in ROAR_CHARS)
    if len(body) < 4:
        raise ValueError("非兽音密文")
    out = bytearray()
    for i in range(0, len(body) - 3, 4):
        v = 0
        for c in body[i:i + 4]:
            v = (v << 2) | ROAR_CHARS.index(c)
        out.append(v)
    return _bytes_to_text(bytes(out))


def roar_encode(text: str) -> str:
    out = [ROAR_HEAD]
    for b in text.encode("utf-8"):
        for shift in (6, 4, 2, 0):
            out.append(ROAR_CHARS[(b >> shift) & 3])
    return "".join(out)


# ============================================================================
# AAencode / JSFuck / JJencode / 颜文字 —— 借助本机 node vm 沙箱
# ============================================================================
_JS_SANDBOX = r"""
const vm = require('vm');
function tryEval(expr){
  return vm.runInNewContext(expr, {}, {timeout: 3000});
}
let chunks = '';
process.stdin.setEncoding('utf8');
process.stdin.on('data', d => chunks += d);
process.stdin.on('end', () => {
  const code = chunks.trim();
  const attempts = [code, '(' + code + ')', 'eval(' + JSON.stringify(code) + ')'];
  for (const a of attempts){
    try { const r = tryEval(a); if (typeof r === 'string'){ process.stdout.write(r); process.exit(0);} }
    catch(e){}
  }
  process.exit(1);
});
"""


def js_obfuscation_decode(text: str):
    """检测并解码 JSFuck / AAencode / JJencode。返回 (类型, 结果) 或抛异常。"""
    t = text.strip()
    kind = None
    sample = t[:2000]
    if re.search(r"[\uFF61-\uFF9Fﾟ]", sample) and any(x in sample for x in ("ﾟ", "ω", "Θ", "Д")):
        kind = "AAencode(颜文字JS)"
    elif re.fullmatch(r"[\[\]\(\)\{\}!\+\s=><&|^~,;\"'0-9.]+", t) and "[" in t and "]" in t and "!" in t:
        kind = "JSFuck"
    elif "$" in t and "~" in t and re.fullmatch(r"[\$=~!+\[\]\(\)\{\};,\s]+", t):
        kind = "JJencode"
    elif (re.search(r"[~$_]", t)
          and re.fullmatch(r"[\[\]\(\)\{\}!\+~$_\s,.'\":=;#\\<>&|-]+", t)
          and "[" in t and "]" in t):
        kind = "Jother"
    elif any(x in t for x in ("ﾟ", "ωﾟ")):
        kind = "AAencode(颜文字JS)"
    if not kind:
        raise ValueError("未识别为 JSFuck/AAencode/JJencode/Jother")
    node = shutil.which("node") or shutil.which("node.exe")
    if not node:
        raise RuntimeError(f"识别为 {kind}，但本机未找到 Node.js，无法执行 JS（可安装 Node 后重试）")
    try:
        r = subprocess.run([node, "-e", _JS_SANDBOX], input=t.encode("utf-8"),
                           capture_output=True, timeout=15)
        out = r.stdout.decode("utf-8", errors="replace")
        if r.returncode == 0 and out:
            return kind, out
        raise RuntimeError("JS 沙箱执行无输出（脚本可能依赖 DOM/浏览器环境）: "
                           + r.stderr.decode("utf-8", "replace")[:200])
    except subprocess.TimeoutExpired:
        raise RuntimeError("JS 执行超时")


# ============================================================================
# 五笔 86 解码（内置一二级简码高频表；全码/更多字可在工具中心下载字库）
# ============================================================================
# 一级简码（25）
WUBI_L1 = {"g": "一", "f": "地", "d": "在", "s": "要", "a": "工",
           "h": "上", "j": "是", "k": "中", "l": "国", "m": "同",
           "t": "和", "r": "的", "e": "有", "w": "人", "q": "我",
           "y": "主", "u": "产", "i": "不", "o": "为", "p": "这",
           "n": "民", "b": "了", "v": "发", "c": "以", "x": "经"}
# 二级简码（标准 588 中常用精选，码→可能汉字；重码给候选）
WUBI_L2 = {
    "gf": "于", "fd": "城", "ds": "石灰", "sa": "械", "af": "苷",
    "gy": "玉清", "fp": "学", "dg": "三", "st": "柏", "ag": "七",
    "gh": "下", "fh": "直", "dd": "磊", "sv": "扫", "ah": "牙",
    "gt": "班", "fk": "吉", "dv": "肆", "sx": "梯", "aj": "划",
    "gr": "珠", "fu": "志", "dm": "面", "sy": "杰", "ak": "贲",
    "ge": "表", "fm": "南", "dn": "成", "ss": "林", "al": "轨",
    "gw": "珍", "ft": "才", "db": "龙", "sr": "析", "am": "贡",
    "gq": "列", "fr": "报", "dc": "友", "se": "极", "ab": "节",
    "gv": "妻", "fb": "地", "d_": "肆", "sc": "权", "av": "婚",
    "gb": "天", "fg": "二", "da": "三", "sp": "综", "ac": "芭",
    "gp": "支", "fa": "载", "di": "雪", "so": "杰", "ao": "赫",
    "gu": "平", "ff": "寺", "dii": "非", "sg": "本", "aa": "式",
    "gg": "五", "fx": "协", "dt": "长", "sh": "盯", "an": "世",
    "gt": "五", "fo": "赤", "dy": "万", "sj": "查", "ap": "芝",
    "hg": "睛", "jh": "早", "kg": "叫", "lg": "軕", "mg": "册",
    "hf": "睦", "jf": "时", "kf": "呈", "lf": "辊", "mf": "见",
    "hd": "盹", "jd": "晨", "kd": "顺", "ld": "困", "md": "央",
    "hs": "盯", "js": "叶", "ks": "吧", "ls": "四", "ms": "财",
    "ha": "眩", "ja": "晨", "ka": "啊", "la": "罢", "ma": "曲",
    "hf": "耻", "jf": "虹", "kf": "员", "lf": "思", "mf": "员",
    "hg": "止", "jg": "虫", "kg": "哟", "lg": "罗", "mg": "崭",
    "hh": "旧", "jj": "归", "kh": "占", "lh": "卤", "mh": "岘",
    "hl": "卤", "jl": "师", "kl": "另", "ll": "男", "ml": "勋",
    "ht": "睡", "jt": "临", "kt": "吵", "lt": "因", "mt": "赂",
    "hr": "睥", "jr": "归", "kr": "吸", "lr": "边", "mr": "败",
    "hk": "足", "jk": "匙", "kk": "喧", "lk": "团", "mk": "遗",
    "he": "脸", "je": "明", "ke": "肿", "le": "胃", "me": "骨",
    "hw": "具", "jw": "蛤", "kw": "啼", "lw": "国", "mw": "赠",
    "hq": "钢", "jq": "鲜", "kq": "哟", "lq": "囵", "mq": "见",
    "hn": "电", "jn": "电", "kn": "嗯", "ln": "恩", "mn": "岂",
    "hm": "崭", "jm": "蚬", "km": "嘛", "lm": "赙", "mm": "山",
    "hb": "卫", "jb": "卫", "kb": "啊", "lb": "吧", "mb": "邮",
    "hv": "恨", "jv": "妇", "kv": "恕", "lv": "轨", "mv": "凤",
    "hc": "双", "jc": "艰", "kc": "劝", "lc": "观", "mc": "巴",
    "hx": "引", "jx": "弥", "kx": "强", "lx": "顷", "mx": "鼎",
    "tg": "生", "rg": "后", "eg": "肚", "wg": "会", "qg": "钱",
    "tf": "知", "rf": "年", "ef": "须", "wf": "分", "qf": "针",
    "td": "知", "rd": "看", "ed": "然", "wd": "估", "qd": "然",
    "ts": "条", "rs": "打", "es": "采", "ws": "作", "qs": "钉",
    "ta": "长", "ra": "找", "ea": "腊", "wa": "代", "qa": "氏",
    "th": "处", "rh": "年", "eh": "肋", "wh": "个", "qh": "外",
    "tj": "么", "rj": "提", "ej": "胆", "wj": "介", "qj": "旬",
    "tl": "备", "rl": "扪", "el": "且", "wl": "会", "ql": "角",
    "tt": "笔", "rt": "手", "et": "秀", "wt": "答", "qt": "儿",
    "tr": "物", "rr": "白", "er": "甩", "wr": "作", "qr": "角",
    "te": "秀", "re": "报", "ee": "月", "we": "众", "qe": "欠",
    "tw": "称", "rw": "兵", "ew": "肥", "ww": "从", "qw": "多",
    "tq": "称", "rq": "气", "eq": "稀", "wq": "你", "qq": "多",
    "tn": "向", "rn": "所", "en": "角", "wn": "亿", "qn": "包",
    "tm": "向", "rm": "丢", "em": "肌", "wm": "负", "qm": "风",
    "tb": "季", "rb": "李", "eb": "服", "wb": "化", "qb": "色",
    "tv": "委", "rv": "报", "ev": "妥", "wv": "份", "qv": "争",
    "tc": "么", "rc": "反", "ec": "难", "wc": "公", "qc": "巴",
    "tx": "比", "rx": "批", "ex": "能", "wx": "化", "qx": "允",
    "yg": "主", "ug": "斗", "ig": "光", "og": "炎", "pg": "定",
    "yf": "计", "uf": "半", "if": "当", "of": "炒", "pf": "守",
    "yd": "订", "ud": "关", "id": "尖", "od": "类", "pd": "害",
    "ys": "可", "us": "亲", "is": "洒", "os": "糙", "ps": "宗",
    "ya": "式", "ua": "并", "ia": "江", "oa": "烂", "pa": "宽",
    "yh": "让", "uh": "站", "ih": "小", "oh": "糙", "ph": "害",
    "yj": "刘", "uj": "间", "ij": "浊", "oj": "蝗", "pj": "审",
    "yl": "为", "ul": "闻", "il": "洒", "ol": "灿", "pl": "官",
    "yt": "放", "ut": "瓣", "it": "当", "ot": "精", "pt": "客",
    "yr": "说", "ur": "拉", "ir": "冰", "or": "粗", "pr": "害",
    "yk": "高", "uk": "部", "ik": "凉", "ok": "炉", "pk": "害",
    "ye": "就", "ue": "冰", "ie": "光", "oe": "粗", "pe": "家",
    "yw": "方", "uw": "帝", "iw": "当", "ow": "粉", "pw": "害",
    "yq": "认", "uq": "前", "iq": "就", "oq": "料", "pq": "客",
    "yn": "记", "un": "关", "in": "怀", "on": "断", "pn": "官",
    "ym": "高", "um": "商", "im": "峭", "om": "灿", "pm": "官",
    "yb": "序", "ub": "闻", "ib": "池", "ob": "汤", "pb": "宋",
    "yv": "冯", "uv": "北", "iv": "当", "ov": "粒", "pv": "审",
    "yc": "育", "uc": "并", "ic": "汉", "oc": "烂", "pc": "害",
    "yx": "弱", "ux": "纺", "ix": "忆", "ox": "糊", "px": "官",
    "ng": "怀", "bg": "承", "vg": "建", "cg": "骒", "xg": "线",
    "nf": "志", "bf": "承", "vf": "寻", "cf": "对", "xf": "结",
    "nd": "导", "bd": "巨", "vd": "肆", "cd": "艰", "xd": "能",
    "ns": "导", "bs": "阿", "vs": "杂", "cs": "戏", "xs": "能",
    "na": "官", "ba": "陈", "va": "肃", "ca": "驿", "xa": "红",
    "nh": "收", "bh": "际", "vh": "归", "ch": "骡", "xh": "引",
    "nj": "慢", "bj": "阵", "vj": "寻", "cj": "骤", "xj": "强",
    "nl": "惭", "bl": "陈", "vl": "毁", "cl": "劝", "xl": "缅",
    "nt": "必", "bt": "际", "vt": "隶", "ct": "通", "xt": "张",
    "nr": "怕", "br": "承", "vr": "艰", "cr": "予", "xr": "弱",
    "nk": "愉", "bk": "职", "vk": "录", "ck": "勇", "xk": "弱",
    "ne": "恨", "be": "阴", "ve": "通", "ce": "能", "xe": "能",
    "nw": "懈", "bw": "除", "vw": "既", "cw": "艰", "xw": "约",
    "nq": "怀", "bq": "疑", "vq": "灵", "cq": "豫", "xq": "弱",
    "nn": "忆", "bn": "也", "vn": "建", "cn": "双", "xn": "纪",
    "nm": "惭", "bm": "出", "vm": "叟", "cm": "观", "xm": "弱",
    "nb": "好", "bb": "子", "vb": "好", "cb": "邓", "xb": "弱",
    "nv": "恨", "bv": "限", "vv": "九", "cv": "艰", "xv": "弱",
    "nc": "双", "bc": "取", "vc": "双", "cc": "又", "xc": "弱",
    "nx": "纪", "bx": "孔", "vx": "绿", "cx": "马", "xx": "比",
}
# 常见全码/三级简码高频补充（码→字）
WUBI_FULL = {
    "yfh": "计", "tha": "算", "smn": "机", "sv": "要", "wwy": "从",
    "vffg": "娃", "rrhy": "抓", "fhnv": "起", "bnhn": "改", "bnh": "也",
    "thfn": "怎", "whtc": "做", "wgi": "你", "qre": "角", "adnt": "藏",
    "tyi": "文", "yygy": "方", "ipkf": "党", "fclf": "动", "wftf": "信",
    "ggll": "一", "hhll": "丨", "tyll": "丿", "yyll": "丶", "nhll": "乙",
}


def wubi_decode(text: str) -> str:
    """按空格/换行分组的五笔 86 码解码；未匹配码原样标注。"""
    groups = re.findall(r"[a-z]{1,5}", text.lower())
    if not groups:
        raise ValueError("未发现五笔字母码")
    out = []
    for g in groups:
        if g in WUBI_L1:
            out.append(WUBI_L1[g])
        elif g in WUBI_FULL:
            out.append(WUBI_FULL[g])
        elif g in WUBI_L2:
            out.append(WUBI_L2[g][0])
        elif g[:2] in WUBI_L2 and len(g) >= 3:
            out.append(WUBI_L2[g[:2]][0])
        else:
            out.append(f"[{g}?]")
    return "".join(out)


# ============================================================================
# 维吉尼亚 / 仿射 / Playfair / 列移位
# ============================================================================
def vigenere(text: str, key: str, decrypt: bool = True) -> str:
    key = re.sub(r"[^a-zA-Z]", "", key).lower()
    if not key:
        raise ValueError("需要字母密钥")
    out, ki = [], 0
    for c in text:
        if c.isalpha():
            k = ord(key[ki % len(key)]) - 97
            if decrypt:
                k = -k
            base = 65 if c.isupper() else 97
            out.append(chr((ord(c) - base + k) % 26 + base))
            ki += 1
        else:
            out.append(c)
    return "".join(out)


_EN_FREQ = {
    "a": 0.0817, "b": 0.0150, "c": 0.0278, "d": 0.0425, "e": 0.1270,
    "f": 0.0223, "g": 0.0202, "h": 0.0609, "i": 0.0697, "j": 0.0015,
    "k": 0.0077, "l": 0.0403, "m": 0.0241, "n": 0.0675, "o": 0.0751,
    "p": 0.0193, "q": 0.0010, "r": 0.0599, "s": 0.0633, "t": 0.0906,
    "u": 0.0276, "v": 0.0098, "w": 0.0236, "x": 0.0015, "y": 0.0197,
    "z": 0.0007,
}


def _chi2_score(text: str) -> float:
    """英文卡方拟合（越高越像英文；正确移位时 chi2 最小）。"""
    letters = [c for c in text.lower() if "a" <= c <= "z"]
    if not letters:
        return -1e9
    n = len(letters)
    cnt = {}
    for c in letters:
        cnt[c] = cnt.get(c, 0) + 1
    chi = 0.0
    for ch, fr in _EN_FREQ.items():
        exp = n * fr
        obs = cnt.get(ch, 0)
        chi += (obs - exp) ** 2 / max(exp, 1e-9)
    return -chi


def _freq_score(text: str) -> float:
    return _chi2_score(text)


def _common_letter_score(text: str) -> float:
    """短文本更稳的英文评分：常见字母 ETAOINSHRDLU 加分，罕见字母扣分（按字母数归一化）。"""
    t = text.lower()
    n = max(1, sum(1 for c in t if "a" <= c <= "z"))
    common = "etaoinshrdlu"
    rare = "jkqvxz"
    return (sum(t.count(c) for c in common)
            - 1.5 * sum(t.count(c) for c in rare)) / n


def english_byte_score(dec: bytes) -> float:
    """对一段已解密字节做"英文明文"评分（XOR 爆破用，按总长度归一化）。"""
    if not dec:
        return -1e9
    pr = sum(1 for b in dec if 9 <= b <= 13 or 32 <= b < 127) / len(dec)
    if pr < 0.9:
        return -1e9
    txt = dec.decode("latin-1", "replace").lower()
    letters = sum(1 for b in dec if 65 <= b <= 90 or 97 <= b <= 122)
    common = sum(txt.count(c) for c in "etaoinshrdlu")
    vowels = sum(txt.count(c) for c in "aeiou")
    sr = dec.count(32) / len(dec)
    s = common / len(dec) * 100 + pr * 10
    if 0.08 <= sr <= 0.25:
        s += 30
    if letters and 0.25 < vowels / letters < 0.6:
        s += 15
    return s


def vigenere_crack(text: str, max_len: int = 16):
    """重合指数 I.C. 推密钥长度 + 每列频率分析。返回 [(密钥, 明文, 评分)]。"""
    t = re.sub(r"[^a-zA-Z]", "", text).lower()
    results = []
    for klen in range(1, min(max_len, len(t) // 6) + 1):
        cols = ["".join(t[i::klen]) for i in range(klen)]
        avg_ic = sum(_index_of_coincidence(c) for c in cols) / klen
        key = ""
        for col in cols:
            best_s, best_k = -1e9, 0
            for sh in range(26):
                dec = caesar(col, -sh)
                sc = _common_letter_score(dec) * 100 + _chi2_score(dec) * 0.01
                if sc > best_s:
                    best_s, best_k = sc, sh
            key += chr(97 + best_k)
        plain = vigenere(text, key)
        # 主排序：明文英文特征；IC 接近英文(0.066) 加分
        results.append((key, plain,
                        _common_letter_score(re.sub(r"[^a-z]", "", plain.lower())) * 1000
                        + avg_ic * 3000 + readable_score(plain) * 5))
    results.sort(key=lambda x: -x[2])
    return results[:8]


def _index_of_coincidence(s: str) -> float:
    n = len(s)
    if n < 2:
        return 0.0
    cnt = {}
    for c in s:
        cnt[c] = cnt.get(c, 0) + 1
    return sum(v * (v - 1) for v in cnt.values()) / (n * (n - 1))


def affine(text: str, a: int, b: int, decrypt: bool = True) -> str:
    import math
    if math.gcd(a, 26) != 1:
        raise ValueError("a 必须与 26 互素")
    out = []
    if decrypt:
        ai = pow(a, -1, 26)
        for c in text:
            if c.islower():
                out.append(chr((ai * (ord(c) - 97 - b)) % 26 + 97))
            elif c.isupper():
                out.append(chr((ai * (ord(c) - 65 - b)) % 26 + 65))
            else:
                out.append(c)
    else:
        for c in text:
            if c.islower():
                out.append(chr((a * (ord(c) - 97) + b) % 26 + 97))
            elif c.isupper():
                out.append(chr((a * (ord(c) - 65) + b) % 26 + 65))
            else:
                out.append(c)
    return "".join(out)


def affine_crack(text: str):
    out = []
    for a in (1, 3, 5, 7, 9, 11, 15, 17, 19, 21, 23, 25):
        for b in range(26):
            r = affine(text, a, b)
            sc = _chi2_score(r) + readable_score(r) * 20
            out.append((a, b, r, sc))
    out.sort(key=lambda x: -x[3])
    return out[:10]


def _playfair_matrix(key: str):
    key = re.sub(r"[^a-zA-Z]", "", key).lower().replace("j", "i")
    seen, cells = set(), []
    for c in key + ascii_lowercase.replace("j", ""):
        if c not in seen:
            seen.add(c)
            cells.append(c)
    return [cells[i:i + 5] for i in range(0, 25, 5)]


def playfair(text: str, key: str, decrypt: bool = True) -> str:
    m = _playfair_matrix(key)
    pos = {m[r][c]: (r, c) for r in range(5) for c in range(5)}
    t = re.sub(r"[^a-zA-Z]", "", text).lower().replace("j", "i")
    if len(t) % 2:
        t += "x"
    out = []
    step = -1 if decrypt else 1
    for i in range(0, len(t), 2):
        a, b = t[i], t[i + 1]
        if a == b:
            b = "x"
        r1, c1 = pos[a]
        r2, c2 = pos[b]
        if r1 == r2:
            out.append(m[r1][(c1 + step) % 5])
            out.append(m[r2][(c2 + step) % 5])
        elif c1 == c2:
            out.append(m[(r1 + step) % 5][c1])
            out.append(m[(r2 + step) % 5][c2])
        else:
            out.append(m[r1][c2])
            out.append(m[r2][c1])
    return "".join(out)


def columnar_decrypt(text: str, key) -> str:
    """key 可为数字列序(如 3142)或字母密钥。"""
    t = re.sub(r"\s", "", text)
    if isinstance(key, str) and not key.isdigit():
        order = sorted(range(len(key)), key=lambda i: sorted(key.lower()).index(key.lower()[i]))
        # 标准列移位：按密钥字母序读列
        ncol = len(key)
        col_order = sorted(range(ncol), key=lambda i: key.lower()[i])
    else:
        digits = [int(c) for c in str(key)]
        ncol = len(digits)
        col_order = [digits.index(i + 1) for i in range(ncol)]
    nrow = -(-len(t) // ncol)
    # 各列长度（最后一行可能缺格）
    lengths = [nrow] * ncol
    short = nrow * ncol - len(t)
    for c in range(ncol - short, ncol):
        if short:
            lengths[c] -= 1
    cols = {}
    p = 0
    for c in col_order:
        cols[c] = t[p:p + lengths[c]]
        p += lengths[c]
    out = []
    for r in range(nrow):
        for c in range(ncol):
            if r < lengths[c]:
                out.append(cols[c][r])
    return "".join(out)


def columnar_crack(text: str, max_cols: int = 8):
    """无密钥时对列数 2..max_cols 全排列暴力（列数小实用），按可读性排序。"""
    t = re.sub(r"\s", "", text)
    results = []
    for ncol in range(2, min(max_cols + 1, len(t) // 3 + 1)):
        if ncol > 7:
            continue
        for perm in itertools.permutations(range(ncol)):
            key = "".join(str(p + 1) for p in perm)
            try:
                r = columnar_decrypt(t, key)
            except Exception:
                continue
            sc = readable_score(r) + _freq_score(r)
            if sc > 8:
                results.append((key, r, sc))
    results.sort(key=lambda x: -x[2])
    return results[:15]


# ============================================================================
# XOR 系列
# ============================================================================
def xor_bytes(data: bytes, key: bytes) -> bytes:
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))


def xor_single_crack(data: bytes):
    out = []
    for k in range(256):
        dec = bytes(b ^ k for b in data)
        txt = _bytes_to_text(dec)
        sc = english_byte_score(dec) + readable_score(txt) * 10
        if sc > 20:
            out.append((k, txt, sc))
    out.sort(key=lambda x: -x[2])
    return out[:12]


def _hamming(a: bytes, b: bytes) -> int:
    return sum(bin(x ^ y).count("1") for x, y in zip(a, b))


def xor_repeating_crack(data: bytes, max_len: int = 16):
    """归一化汉明距离推密钥长度 + 逐字节频率分析。"""
    sizes = []
    for klen in range(1, min(max_len, len(data) // 4) + 1):
        blocks = [data[i * klen:(i + 1) * klen] for i in range(4)]
        if len(blocks[-1]) < klen:
            continue
        d = sum(_hamming(blocks[i], blocks[j]) for i in range(4) for j in range(i + 1, 4))
        sizes.append((d / (6 * klen), klen))
    results = []
    # 汉明距离候选 + 全部小长度兜底（短文本时距离法不稳）
    cand_lens = sorted({klen for _, klen in sorted(sizes)[:4]} |
                       set(range(1, min(max_len, len(data) // 4) + 1)))
    for klen in cand_lens:
        key = bytearray()
        for i in range(klen):
            col = data[i::klen]
            best_s, best_k = -1e18, 0
            for k in range(256):
                dec = bytes(b ^ k for b in col)
                sc = english_byte_score(dec)
                if sc > best_s:
                    best_s, best_k = sc, k
            key.append(best_k)
        plain = xor_bytes(data, bytes(key))
        txt = _bytes_to_text(plain)
        sc = english_byte_score(plain)
        results.append((bytes(key).decode("latin-1", "replace"), txt, sc))
    # 按英文评分降序，接近时优先更短密钥（避免取到密钥长度的倍数）
    results.sort(key=lambda x: (-x[2], len(x[0])))
    best = results[0][2] if results else 0
    results = [r for r in results if r[2] >= best - 5][:6]
    results.sort(key=lambda x: (-x[2], len(x[0])))
    return results


# ============================================================================
# 对称加解密（AES/DES/3DES/RC4/SM4）
# ============================================================================
def _normalize_key_iv(s: str, length: int):
    b = s.encode("utf-8", "replace")
    if len(b) >= length:
        return b[:length]
    return b + b"\0" * (length - len(b))


def symmetric_crypt(algo: str, mode: str, data: bytes, key: str, iv: str,
                    decrypt: bool, key_hex=False, in_b64=False):
    if in_b64 and decrypt:
        try:
            data = base64.b64decode(data + b"=" * (-len(data) % 4) if isinstance(data, bytes)
                                    else data + "=" * (-len(data) % 4))
        except Exception:
            pass
    kb = bytes.fromhex(key) if key_hex else key.encode()
    ivb = bytes.fromhex(iv) if key_hex and iv else (iv.encode() if iv else b"")
    algo = algo.upper()
    if algo == "RC4":
        from Crypto.Cipher import ARC4
        plain = ARC4.new(kb).decrypt(data) if decrypt else ARC4.new(kb).encrypt(data)
        return plain
    if algo == "SM4":
        from gmssl.sm4 import CryptSM4, SM4_DECRYPT, SM4_ENCRYPT
        c = CryptSM4()
        c.set_key(_normalize_key_iv(key, 16) if not key_hex else kb,
                  SM4_DECRYPT if decrypt else SM4_ENCRYPT)
        mode = mode.upper()
        if mode == "ECB":
            return c.crypt_ecb(data)
        return c.crypt_cbc(_normalize_key_iv(iv, 16) if not key_hex else ivb.ljust(16, b"\0"), data)
    from Crypto.Cipher import AES, DES, DES3
    table = {"AES": (AES, 16), "DES": (DES, 8), "3DES": (DES3, 24)}
    mod, klen = table[algo]
    if len(kb) not in (8, 16, 24, 32) and algo == "AES":
        kb = _normalize_key_iv(key, klen) if not key_hex else kb
    if algo == "DES":
        kb = kb[:8].ljust(8, b"\0")
    if algo == "3DES":
        if len(kb) < 24:
            kb = (kb * 3)[:24]
    mode = mode.upper()
    if mode == "ECB":
        c = mod.new(kb, mod.MODE_ECB)
        out = c.decrypt(data) if decrypt else c.encrypt(_pkcs7(data, mod.block_size))
    else:
        bs = mod.block_size
        ivb = ivb[:bs].ljust(bs, b"\0")
        c = mod.new(kb, {"CBC": mod.MODE_CBC, "CFB": mod.MODE_CFB,
                         "OFB": mod.MODE_OFB, "CTR": mod.MODE_CTR}[mode], ivb)
        if decrypt:
            out = c.decrypt(data)
        else:
            out = c.encrypt(_pkcs7(data, bs)) if mode == "CBC" else c.encrypt(data)
    if decrypt:
        out = _unpkcs7(out)
    return out


def _pkcs7(b: bytes, bs: int) -> bytes:
    p = bs - len(b) % bs
    return b + bytes([p]) * p


def _unpkcs7(b: bytes) -> bytes:
    if b and 1 <= b[-1] <= 16 and b[-b[-1]:] == bytes([b[-1]]) * b[-1]:
        return b[:-b[-1]]
    return b


# ============================================================================
# Base100（emoji）/ 敲击码 / 云影密码 / QWE键盘 / 当铺 / 元音
# ============================================================================
def base100_decode(text: str) -> str:
    out = bytearray()
    chars = [c for c in text if 0x1F400 <= ord(c) <= 0x1F4FF]
    for c in chars:
        out.append(ord(c) - 0x1F400)
    if not out:
        raise ValueError("未发现 Base100 emoji（U+1F400 起）")
    return _bytes_to_text(bytes(out))


def base100_encode(text: str) -> str:
    return "".join(chr(0x1F400 + b) for b in text.encode("utf-8"))


def tapcode_decode(text: str) -> str:
    grid = [["a", "b", "c", "d", "e"], ["f", "g", "h", "i", "j"],
            ["k", "l", "m", "n", "o"], ["p", "q", "r", "s", "t"],
            ["u", "v", "w", "x", "y"]]   # c/k 合并常见变体取 k 在原位
    nums = re.findall(r"\d+", text)
    dots = re.findall(r"[.\u00b7\u30fb]+[\s,/|]*[.\u00b7\u30fb]+", text)
    out = []
    if nums and len(nums) % 2 == 0:
        for i in range(0, len(nums), 2):
            r, c = int(nums[i]) - 1, int(nums[i + 1]) - 1
            if 0 <= r < 5 and 0 <= c < 5:
                out.append(grid[r][c])
    elif dots:
        for d in dots:
            parts = re.findall(r"[.\u00b7\u30fb]+", d)
            if len(parts) == 2:
                r, c = len(parts[0]) - 1, len(parts[1]) - 1
                if 0 <= r < 5 and 0 <= c < 5:
                    out.append(grid[r][c])
    if not out:
        raise ValueError("未识别敲击码（数字对或点对）")
    return "".join(out)


def yunying_decode(text: str) -> str:
    """云影/01248 密码：0 分隔，组内数字求和=字母序号。"""
    groups = re.split(r"[0\s]+", text.strip().strip("0"))
    out = []
    for g in groups:
        if not g:
            continue
        if not re.fullmatch(r"[1248]+", g):
            raise ValueError("含非 0/1/2/4/8 数字")
        v = sum(int(x) for x in g)
        if 1 <= v <= 26:
            out.append(chr(96 + v))
    return "".join(out)


def yunying_encode(text: str) -> str:
    out = []
    for c in text.lower():
        if c.isalpha():
            v = ord(c) - 96
            parts = []
            for n in (8, 4, 2, 1):
                if v >= n:
                    parts.append(str(n))
                    v -= n
            out.append("".join(parts))
    return "0".join(out)


def qwe_decode(text: str) -> str:
    """QWE 键盘替换：密文是键盘位，还原为 ABC 顺序字母。"""
    rows = "qwertyuiopasdfghjklzxcvbnm"
    mp = {rows[i]: ascii_lowercase[i] for i in range(26)}
    return "".join(mp.get(c.lower(), c) for c in text)


def qwe_encode(text: str) -> str:
    rows = "qwertyuiopasdfghjklzxcvbnm"
    mp = {ascii_lowercase[i]: rows[i] for i in range(26)}
    return "".join(mp.get(c.lower(), c) for c in text)


DANGPU = {"由": "0", "中": "1", "人": "2", "工": "3", "大": "4",
          "王": "5", "夫": "6", "井": "7", "羊": "8", "美": "9"}


def dangpu_decode(text: str) -> str:
    out = []
    for c in text:
        if c in DANGPU:
            out.append(DANGPU[c])
        elif c.isdigit():
            out.append(c)
    digits = "".join(out)
    if not digits:
        raise ValueError("未发现当铺密码汉字（由中人工大王夫井羊美）")
    return digits + "\n（数字串，通常需按手机键盘/ASCII 等继续转换）"


# ============================================================================
# JWT 解码 / 弱密钥爆破 / Flask session
# ============================================================================
def jwt_inspect(token: str):
    parts = token.strip().split(".")
    if len(parts) < 2:
        raise ValueError("非 JWT")

    def b64d(p):
        return base64.urlsafe_b64decode(p + "=" * (-len(p) % 4))

    header = json.loads(b64d(parts[0]))
    payload = json.loads(b64d(parts[1]))
    alg = header.get("alg", "")
    notes = []
    if alg.lower() == "none":
        notes.append("alg=none：服务端若未校验可直接伪造")
    cracked = None
    if alg.lower().startswith("hs") and len(parts) == 3:
        from .modules_text import WEAK_PASSWORDS
        hashes = {"HS256": hashlib.sha256, "HS384": hashlib.sha384, "HS512": hashlib.sha512}
        signing_input = ".".join(parts[:2]).encode()
        sig = b64d(parts[2])
        for w in WEAK_PASSWORDS + ["secret", "key", "jwt", "token", "123456", ""]:
            if hmac.new(w.encode(), signing_input, hashes.get(alg, hashlib.sha256)).digest() == sig:
                cracked = w
                break
        if cracked:
            notes.append(f"HS 弱密钥命中: {cracked!r}（可伪造任意 token）")
        else:
            notes.append("内置弱口令未命中，可用大字典继续爆破 HS 密钥")
    return header, payload, cracked, "; ".join(notes)


def flask_session_decode(cookie: str, wordlist=None):
    """Flask session：base64(payload).timestamp，首字符 . 表示 zlib 压缩。"""
    body = cookie.strip().split(".")[0]
    raw = base64.urlsafe_b64decode(body + "=" * (-len(body) % 4))
    if raw[:1] == b".":
        import zlib
        raw = zlib.decompress(raw[1:])
    payload = raw.decode("utf-8", errors="replace")
    cracked = None
    from .modules_text import WEAK_PASSWORDS
    words = list(WEAK_PASSWORDS)
    if wordlist:
        try:
            words += [w.strip() for w in open(wordlist, errors="ignore") if w.strip()]
        except Exception:
            pass
    signing = cookie.strip().rsplit(".", 1)[0].encode()
    sig_field = cookie.strip().split(".")[-1] if cookie.strip().count(".") >= 1 else ""
    try:
        want = base64.urlsafe_b64decode(sig_field + "=" * (-len(sig_field) % 4))
        for w in words:
            if hmac.new(w.encode(), signing, hashlib.sha1).digest() == want:
                cracked = w
                break
    except Exception:
        pass
    return payload, cracked


# ============================================================================
# 二维码生成
# ============================================================================
def qr_encode(text: str, out_path: str = None):
    import qrcode
    from .common import WORKSPACE
    if out_path is None:
        os.makedirs(WORKSPACE, exist_ok=True)
        out_path = os.path.join(WORKSPACE, "qrcode.png")
    img = qrcode.make(text)
    img.save(out_path)
    return out_path


# ============================================================================
# 自动特色编码探测（供 dispatcher 文本流调用），返回 [(名称, 文本, 分数)]
# ============================================================================
def detect_special(text: str):
    out = []

    def add(name, val):
        try:
            if val:
                out.append((name, val, readable_score(val)))
        except Exception:
            pass

    # 盲文
    if any(0x2800 <= ord(c) <= 0x28FF for c in text):
        try:
            add("盲文Braille", braille_decode(text))
        except Exception:
            pass
    # 兽音
    if all(c in ROAR_CHARS for c in text.replace(ROAR_HEAD, "").strip()) and \
            sum(c in ROAR_CHARS for c in text) >= 8:
        try:
            add("兽音译者", roar_decode(text))
        except Exception:
            pass
    # Base100
    if sum(1 for c in text if 0x1F400 <= ord(c) <= 0x1F4FF) >= 2:
        try:
            add("Base100", base100_decode(text))
        except Exception:
            pass
    # Base64 隐写（多行 base64）
    lines = [ln.strip() for ln in text.splitlines() if ln.strip()]
    if len(lines) >= 4 and all(re.fullmatch(r"[A-Za-z0-9+/=]{4,}", ln) for ln in lines[:20]):
        for name, val in base64_steg_extract(text):
            add("Base64隐写/" + name, val)
    # 云影
    if re.fullmatch(r"[01248\s]+", text.strip()) and "0" in text and len(text.strip()) > 3:
        try:
            add("云影01248", yunying_decode(text))
        except Exception:
            pass
    # JSFuck/AA/JJ（需要 node，可能耗时，仅在特征明显时）
    compact = re.sub(r"\s", "", text)
    if (("ﾟ" in text) or
            (len(compact) > 30 and set(compact) <= set("[](){}!+") and set(compact) >= set("[]!"))
            or ("$" in text and "~" in text and len(compact) < 4000)):
        try:
            kind, val = js_obfuscation_decode(text)
            add(kind, val)
        except Exception:
            pass
    # 单字节 XOR（输入为 hex 时）
    try:
        h = text.strip()
        # 只剥前导 0x / \x，不动中间的 0/x 字符
        h = re.sub(r"^(0x|\\x)+", "", h)
        h = re.sub(r"[\s\\x]", "", h)
        if len(h) % 2 == 1:
            h = h[:-1]
        if 16 <= len(h) <= 4096 and re.fullmatch(r"[0-9a-fA-F]+", h):
            for k, val, sc in xor_single_crack(bytes.fromhex(h))[:3]:
                if sc > 6:
                    add(f"单字节XOR(key=0x{k:02x})", val)
    except Exception:
        pass
    # 摩斯密码（.- 组合，空格分隔）
    try:
        compact = re.sub(r"\s", "", text)
        if (len(compact) >= 4 and set(compact) <= set(".-/")
                and compact.count("-") >= 2 and compact.count(".") >= 2
                and "/" in text or (compact.count(".") + compact.count("-")) >= 8):
            from .modules_text import morse_decode
            decoded = morse_decode(text)
            if decoded and readable_score(decoded) > 1:
                add("摩斯密码", decoded)
    except Exception:
        pass
    # Base62（短链/URL 常用字母表 0-9A-Za-z，纯字母数字且非 base64 特征）
    try:
        t62 = text.strip()
        if (10 <= len(t62) <= 200 and re.fullmatch(r"[0-9A-Za-z]+", t62)
                and "-" not in t62 and "_" not in t62
                and not re.fullmatch(r"[0-9a-fA-F]+", t62)):  # 排除纯 hex
            b62 = base62_decode(t62)
            if b62:
                add("Base62", _bytes_to_text(b62))
    except Exception:
        pass
    out.sort(key=lambda x: -x[2])
    return out


# ============================================================================
# Base62（URL/短链常用，0-9A-Za-z）
# ============================================================================
B62_ALPHA = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
_B62_MAP = {c: i for i, c in enumerate(B62_ALPHA)}


def base62_decode(s: str) -> bytes:
    """Base62 字符串解码为字节（大端）。"""
    n = 0
    for c in s.strip():
        if c not in _B62_MAP:
            raise ValueError(f"Base62 非法字符: {c!r}")
        n = n * 62 + _B62_MAP[c]
    # 转为字节
    length = (n.bit_length() + 7) // 8 if n else 0
    return n.to_bytes(length, "big") if n else b""


def base62_encode(data: bytes) -> str:
    """字节串编码为 Base62 字符串。"""
    n = int.from_bytes(data, "big") if data else 0
    if n == 0:
        return "0"
    out = []
    while n > 0:
        n, r = divmod(n, 62)
        out.append(B62_ALPHA[r])
    return "".join(reversed(out))


# ============================================================================
# 希尔密码 Hill Cipher（2x2 / 3x3，已知密钥矩阵加解密）
# ============================================================================
def _mat_mod_inv(mat, mod=26):
    """求 2x2 或 3x3 矩阵在 mod 下的逆矩阵。返回逆矩阵或 None。"""
    n = len(mat)
    det = 0
    # 计算行列式
    if n == 2:
        det = (mat[0][0] * mat[1][1] - mat[0][1] * mat[1][0]) % mod
    elif n == 3:
        det = (mat[0][0] * (mat[1][1] * mat[2][2] - mat[1][2] * mat[2][1])
               - mat[0][1] * (mat[1][0] * mat[2][2] - mat[1][2] * mat[2][0])
               + mat[0][2] * (mat[1][0] * mat[2][1] - mat[1][1] * mat[2][0])) % mod
    else:
        raise ValueError("仅支持 2x2 / 3x3")
    try:
        det_inv = pow(det, -1, mod)
    except ValueError:
        return None  # 行列式无逆，矩阵不可逆
    # 伴随矩阵
    adj = [[0] * n for _ in range(n)]
    if n == 2:
        adj[0][0] = mat[1][1]
        adj[0][1] = -mat[0][1]
        adj[1][0] = -mat[1][0]
        adj[1][1] = mat[0][0]
    else:
        for i in range(3):
            for j in range(3):
                minor = [mat[x][:j] + mat[x][j + 1:] for x in range(3) if x != i]
                cof = (minor[0][0] * minor[1][1] - minor[0][1] * minor[1][0])
                adj[j][i] = ((-1) ** (i + j) * cof) % mod
    return [[(det_inv * adj[i][j]) % mod for j in range(n)] for i in range(n)]


def hill_decrypt(ciphertext: str, key_matrix) -> str:
    """Hill 密码解密。key_matrix 为 n x n 整数矩阵（n=2 或 3）。"""
    n = len(key_matrix)
    inv = _mat_mod_inv(key_matrix, 26)
    if inv is None:
        raise ValueError("密钥矩阵在 mod 26 下不可逆")
    t = re.sub(r"[^a-zA-Z]", "", ciphertext).lower()
    if len(t) % n:
        t += "x" * (n - len(t) % n)
    out = []
    for i in range(0, len(t), n):
        vec = [ord(t[i + j]) - 97 for j in range(n)]
        dec = []
        for r in range(n):
            s = sum(inv[r][c] * vec[c] for c in range(n)) % 26
            dec.append(chr(s + 97))
        out.extend(dec)
    return "".join(out)


def hill_encrypt(plaintext: str, key_matrix) -> str:
    """Hill 密码加密。"""
    n = len(key_matrix)
    t = re.sub(r"[^a-zA-Z]", "", plaintext).lower()
    if len(t) % n:
        t += "x" * (n - len(t) % n)
    out = []
    for i in range(0, len(t), n):
        vec = [ord(t[i + j]) - 97 for j in range(n)]
        enc = []
        for r in range(n):
            s = sum(key_matrix[r][c] * vec[c] for c in range(n)) % 26
            enc.append(chr(s + 97))
        out.extend(enc)
    return "".join(out)


# ============================================================================
# 键盘密码：键盘坐标 / 键盘移位
# ============================================================================
# 标准 QWERTY 键盘（字母行）
_KEYBOARD_ROWS = ["qwertyuiop", "asdfghjkl", "zxcvbnm"]
# 键盘坐标：每个字母对应的(行, 列)
_KEYBOARD_POS = {}
for _ri, _row in enumerate(_KEYBOARD_ROWS):
    for _ci, _ch in enumerate(_row):
        _KEYBOARD_POS[_ch] = (_ri, _ci)


def keyboard_coord_decode(text: str) -> str:
    """键盘坐标密码：数字映射到 QWERTY 键盘位置字母。
    支持两种格式：
    1) 两位一组（最常见）：11 12 21 → (1,1)(1,2)(2,1)
    2) 单个数字交替行/列：1 1 1 2 2 1
    """
    nums = re.findall(r"\d+", text)
    if not nums:
        raise ValueError("键盘坐标未找到数字")
    # 格式1：每个数字恰好两位，直接拆成行/列
    if all(len(n) == 2 for n in nums) and len(nums) >= 1:
        pairs = [(int(n[0]), int(n[1])) for n in nums]
    elif len(nums) % 2 == 0:
        # 格式2：交替行/列
        pairs = [(int(nums[i]), int(nums[i + 1])) for i in range(0, len(nums), 2)]
    else:
        raise ValueError("键盘坐标格式无法识别")
    out = []
    for row, col in pairs:
        r, c = row - 1, col - 1
        if 0 <= r < len(_KEYBOARD_ROWS) and 0 <= c < len(_KEYBOARD_ROWS[r]):
            out.append(_KEYBOARD_ROWS[r][c])
        else:
            out.append("?")
    return "".join(out)


def keyboard_shift_decode(text: str, direction: str = "left") -> str:
    """键盘移位密码：密文是键盘上相邻位的字母，还原为正确字母。
    direction: 'left'=密文在右移后位置(左还原), 'right'=密文在左移后位置(右还原),
               'up'=下移还原, 'down'=上移还原。"""
    shift_map = {
        "left":  (0, -1),   # 密文字母是原字母右边那个 → 往左找
        "right": (0, 1),    # 密文字母是原字母左边那个 → 往右找
        "up":    (-1, 0),   # 密文字母是原字母下边那个 → 往上找
        "down":  (1, 0),    # 密文字母是原字母上边那个 → 往下找
    }
    dr, dc = shift_map.get(direction, (0, -1))
    out = []
    for c in text.lower():
        if c not in _KEYBOARD_POS:
            out.append(c)
            continue
        r, col = _KEYBOARD_POS[c]
        nr, nc = r + dr, col + dc  # 从密文位置偏移到明文位置
        if 0 <= nr < len(_KEYBOARD_ROWS) and 0 <= nc < len(_KEYBOARD_ROWS[nr]):
            out.append(_KEYBOARD_ROWS[nr][nc])
        else:
            out.append(c)
    return "".join(out)


# ============================================================================
# TEA / XTEA / XXTEA 解密（CTF 高频逆向算法）
# ============================================================================
def tea_decrypt(v0: int, v1: int, key: list, rounds: int = 32) -> tuple:
    """TEA 解密。key 为 4 个 32 位整数的列表。返回 (v0, v1) 明文。"""
    v0, v1 = v0 & 0xFFFFFFFF, v1 & 0xFFFFFFFF
    k0, k1, k2, k3 = key
    delta = 0x9E3779B9
    sum_ = (delta * rounds) & 0xFFFFFFFF
    for _ in range(rounds):
        v1 = (v1 - (((v0 << 4) + k2) ^ (v0 + sum_) ^ ((v0 >> 5) + k3))) & 0xFFFFFFFF
        v0 = (v0 - (((v1 << 4) + k0) ^ (v1 + sum_) ^ ((v1 >> 5) + k1))) & 0xFFFFFFFF
        sum_ = (sum_ - delta) & 0xFFFFFFFF
    return v0, v1


def xtea_decrypt(v0: int, v1: int, key: list, rounds: int = 32) -> tuple:
    """XTEA 解密。"""
    v0, v1 = v0 & 0xFFFFFFFF, v1 & 0xFFFFFFFF
    k = key
    delta = 0x9E3779B9
    sum_ = (delta * rounds) & 0xFFFFFFFF
    mask = 0xFFFFFFFF
    for _ in range(rounds):
        v1 = (v1 - (((v0 << 4) ^ (v0 >> 5)) + v0) ^ (sum_ + k[(sum_ >> 11) & 3])) & mask
        sum_ = (sum_ - delta) & mask
        v0 = (v0 - (((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum_ + k[sum_ & 3])) & mask
    return v0, v1


def xxtea_decrypt(data: bytes, key: bytes) -> bytes:
    """XXTEA 解密。data 为密文字节(8字节对齐)，key 为16字节。返回明文字节。"""
    import struct
    if len(data) % 8 != 0 or len(data) < 8:
        raise ValueError("XXTEA 密文长度需为 8 的倍数且 >= 8 字节")
    n = len(data) // 4
    v = list(struct.unpack("<%dI" % n, data))
    k = list(struct.unpack("<4I", key.ljust(16, b"\x00")[:16]))
    delta = 0x9E3779B9
    rounds = 6 + 52 // n
    mask = 0xFFFFFFFF
    sum_ = (delta * rounds) & mask
    y = v[0]
    for _ in range(rounds):
        e = (sum_ >> 2) & 3
        for p in range(n - 1, 0, -1):
            z = v[p - 1]
            mx = (((z >> 5) ^ (y << 2)) + ((y >> 3) ^ (z << 4))) ^ ((sum_ ^ y) + (k[(p & 3) ^ e] ^ z))
            v[p] = (v[p] - mx) & mask
            y = v[p]
        z = v[n - 1]
        mx = (((z >> 5) ^ (y << 2)) + ((y >> 3) ^ (z << 4))) ^ ((sum_ ^ y) + (k[(0 & 3) ^ e] ^ z))
        v[0] = (v[0] - mx) & mask
        y = v[0]
        sum_ = (sum_ - delta) & mask
    return struct.pack("<%dI" % n, *v)


# ============================================================================
# LCG (线性同余生成器) 预测
# ============================================================================
def lcg_crack(known_outputs: list):
    """已知 LCG 的若干连续输出（整数列表），反推 modulus/multiplier/increment。
    LCG: X(n+1) = (a * X(n) + c) mod m
    返回 (m, a, c, next_outputs) 或 None。
    需至少 5 个连续输出才能稳定反推。"""
    if len(known_outputs) < 5:
        return None
    import math
    xs = known_outputs
    # 差分法求 modulus: gcd of (X(i+1)-X(i))^2 的相邻差
    diffs = [xs[i + 1] - xs[i] for i in range(len(xs) - 1)]
    # t_i = diffs[i]^2 - diffs[i-1]*diffs[i+1]
    ts = []
    for i in range(1, len(diffs) - 1):
        ts.append(diffs[i] * diffs[i] - diffs[i - 1] * diffs[i + 1])
    m = 0
    for t in ts:
        m = math.gcd(m, abs(t))
    if m == 0:
        return None
    # 求 a: a ≡ diffs[1] * inv(diffs[0]) mod m
    try:
        a = (diffs[1] * pow(diffs[0], -1, m)) % m
    except ValueError:
        return None
    c = (xs[1] - a * xs[0]) % m
    # 生成后续输出验证
    nxt = []
    state = xs[-1]
    for _ in range(10):
        state = (a * state + c) % m
        nxt.append(state)
    return m, a, c, nxt


# ============================================================================
# MD5/SHA1 长度扩展攻击（基础实现：构造 padding）
# ============================================================================
def length_extension_padding(original_len: int, hash_name: str = "md5") -> bytes:
    """计算长度扩展攻击所需的填充字节。
    original_len: 原始消息(含已知前缀)的总字节长度。
    返回 padding 字节（可追加到原始消息后再接恶意后缀）。"""
    block = 64  # MD5/SHA1 都是 64 字节分组
    msg_len = original_len
    pad = b"\x80"
    # 填充到 56 mod 64
    pad_len = (56 - (msg_len + 1) % block) % block
    pad += b"\x00" * pad_len
    # 追加 64 位小端长度（位）
    bit_len = (msg_len * 8) & 0xFFFFFFFFFFFFFFFF
    pad += struct.pack("<Q", bit_len)
    return pad


def craft_length_extended_data(original_data: bytes, suffix: bytes) -> bytes:
    """构造长度扩展攻击的扩展数据：原始数据 + 填充 + 后缀。
    配合已知的 original_hash，可在不知道 secret 的情况下计算
    H(secret + original_data + padding + suffix)。"""
    pad = length_extension_padding(len(original_data))
    return original_data + pad + suffix


# ============================================================================
# 新约佛论禅（与佛论禅新版变种，使用不同密钥/IV）
# ============================================================================
def foyinjutsu_decode(text: str) -> str:
    """新约佛论禅解码。识别以"新约"或特定密文字母表开头的密文。
    与佛论禅使用固定 AES-CBC，新约佛论禅字母表略不同但算法一致。"""
    from .modules_text import _TUDOU_CHARS, _TUDOU_MARK, _TUDOU_INDEX, _TUDOU_MARKSET
    import zlib
    body = text
    # 定位前缀
    for head in ("新约：", "新约:", "新约佛论禅：", "新约佛论禅:"):
        if head in body:
            body = body.split(head, 1)[1]
            break
    else:
        body = "".join(c for c in text if c in _TUDOU_INDEX or c in _TUDOU_MARKSET)
    data = bytearray()
    i = 0
    while i < len(body):
        c = body[i]
        if c in _TUDOU_MARKSET and i + 1 < len(body):
            i += 1
            data.append(_TUDOU_INDEX[body[i]] + 128)
        elif c in _TUDOU_INDEX:
            data.append(_TUDOU_INDEX[c])
        i += 1
    if not data or len(data) % 16:
        raise ValueError("非新约佛论禅密文或数据损坏")
    from Crypto.Cipher import AES
    # 新约佛论禅使用不同的 key/iv（公开参数）
    key = b"XDXDtudou@KeyFansClub^_!!"
    iv = b"Potato@Key@_@=_="
    dec = AES.new(key, AES.MODE_CBC, iv).decrypt(bytes(data))
    pad = dec[-1]
    if 0 < pad <= 16 and dec[-pad] == pad:
        dec = dec[:-pad]
    for wbits in (-15, 15, 31):
        try:
            raw = zlib.decompress(dec, wbits)
            t = raw.decode("utf-16-le", errors="replace")
            if t and len(t) > 2:
                return t
        except Exception:
            pass
    # 直接 UTF-16LE
    t = dec.decode("utf-16-le", errors="replace")
    if t.strip():
        return t
    raise ValueError("新约佛论禅解密失败")
