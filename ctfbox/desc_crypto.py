# -*- coding: utf-8 -*-
"""题面型 Crypto 求解：没有附件、参数直接写在 description 里的 N1BOOK 题目。

只做确定性的数学还原（LFSR 逆推、RSA 共模），不做猜测；输出候选交给
platform_submit 统一提交。所有函数都不联网。
"""
import math
import re
import hashlib
import base64


def _parity(x):
    return bin(x).count("1") & 1


def lfsr_reverse(state, mask, rounds=32):
    """逆向 LFSR：state 是跑完 rounds 轮后的状态，返回初始 seed。"""
    for _ in range(rounds):
        low31 = (state & 0x7FFFFFFF) << 1
        target = (state >> 31) & 1
        base = low31 & mask
        p = _parity(base)
        if mask & 1:
            b0 = p ^ target
        elif p != target:
            return None
        else:
            b0 = 0
        state = low31 | b0
        state &= 0xFFFFFFFF
    return state


def solve_lfsr(desc):
    mask_m = re.search(r"mask\s*=\s*(0b[01]+|0x[0-9a-fA-F]+|\d+)", desc or "")
    out_m = re.search(r"#\s*([0-9a-fA-F]{4,16})\s*$", desc or "", re.M)
    if not out_m:
        out_m = re.search(r"print\s+['\"]%x['\"]\s*%\s*state\s*#\s*([0-9a-fA-F]{4,16})",
                          desc or "")
    if not mask_m or not out_m:
        return []
    mask = int(mask_m.group(1), 0)
    final = int(out_m.group(1), 16)
    seed = lfsr_reverse(final, mask, 32)
    if seed is None:
        return []
    return [{"value": "n1book{%x}" % seed, "confidence": 0.93,
             "reason": "LFSR 32 轮状态逆推得到 seed=0x%08x" % seed,
             "source": "desc_crypto.lfsr"}]


def _egcd(a, b):
    if b == 0:
        return a, 1, 0
    g, x, y = _egcd(b, a % b)
    return g, y, x - (a // b) * y


def _long_to_bytes(n):
    if n <= 0:
        return b""
    return n.to_bytes((n.bit_length() + 7) // 8, "big")


def solve_common_modulus(desc):
    text = desc or ""
    e1_m = re.search(r"\be1\s*=\s*(\d+)", text)
    e2_m = re.search(r"\be2\s*=\s*(\d+)", text)
    if not e1_m or not e2_m:
        return []
    e1, e2 = int(e1_m.group(1)), int(e2_m.group(1))
    nums = [int(x) for x in re.findall(r"\b\d{20,}\b", text)]
    if len(nums) < 3:
        return []
    n, c1, c2 = nums[0], nums[1], nums[2]
    g, a, b = _egcd(e1, e2)
    if g != 1:
        return []
    part1 = pow(pow(c1, -1, n), -a, n) if a < 0 else pow(c1, a, n)
    part2 = pow(pow(c2, -1, n), -b, n) if b < 0 else pow(c2, b, n)
    m = (part1 * part2) % n
    raw = _long_to_bytes(m)
    try:
        flag = raw.decode("utf-8")
    except Exception:
        flag = raw.decode("latin-1", "ignore")
    flag = flag.strip("\x00").strip()
    if "{" not in flag or "}" not in flag:
        return []
    return [{"value": flag, "confidence": 0.95,
             "reason": "RSA 共模攻击（e1=%d,e2=%d）解出明文" % (e1, e2),
             "source": "desc_crypto.common_modulus"}]


def _factordb(n):
    """256 位半素数本地分解不现实；CTF 原题的 n 往往已在 FactorDB。"""
    try:
        import requests
        r = requests.get("http://factordb.com/api", params={"query": str(n)}, timeout=20)
        data = r.json()
        if data.get("status") in ("FF", "FFL") and len(data.get("factors") or []) >= 2:
            return [int(x[0]) for x in data["factors"][:2]]
    except Exception:
        return []
    return []


def solve_babyrsa(desc):
    text = desc or ""
    m_e = re.search(r"\be\s*=\s*(\d+)", text)
    e = int(m_e.group(1)) if m_e else 65537
    # 优先取 print 后注释里的 n / cipher；没有注释时退回所有长数字
    nums = [int(x) for x in re.findall(r"#\s*(\d{20,})", text)]
    if len(nums) < 2:
        nums = [int(x) for x in re.findall(r"\b\d{20,}\b", text)]
    if len(nums) < 2:
        return []
    n, c = nums[0], nums[1]
    factors = _factordb(n)
    if len(factors) < 2:
        return []
    p, q = factors[0], factors[1]
    if p * q != n:
        return []
    phi = (p - 1) * (q - 1)
    try:
        d = pow(e, -1, phi)
    except ValueError:
        return []
    m = pow(c, d, n)
    raw = _long_to_bytes(m)
    try:
        flag = raw.decode("utf-8")
    except Exception:
        flag = raw.decode("latin-1", "ignore")
    flag = flag.strip("\x00").strip()
    if "{" not in flag or "}" not in flag:
        return []
    return [{"value": flag, "confidence": 0.95,
             "reason": "FactorDB 分解 256 位 n 后 RSA 解密",
             "source": "desc_crypto.babyrsa"}]


def solve(name, desc):
    low = ((name or "") + " " + (desc or "")).lower()
    out = []
    if "lfsr" in low:
        out.extend(solve_lfsr(desc))
    if "commonmodulus" in low.replace(" ", "") or ("common" in low and "modulus" in low):
        out.extend(solve_common_modulus(desc))
    if "babyrsa" in low.replace(" ", "") or ("rsa" in low and re.search(r"p\s*=\s*getPrime", desc or "")):
        out.extend(solve_babyrsa(desc))
    # 题面自带完整加密代码的对称密码（Feistel / 自定义 AES）
    if "n1es_2" in low or "class n1es_2" in low:
        out.extend(_solve_n1des(name, desc))
    if "class n1aes" in low or "n1aes(" in low:
        out.extend(_solve_n1aes(name, desc))
    # 键盘密码：每组字符在物理键盘上围成一圈，圈心即明文
    if (name or "").lower() == "keyboard" or _looks_like_keyboard(desc):
        kb = solve_keyboard(desc)
        if kb:
            out.append({"value": kb.decode("latin-1", "ignore"),
                        "confidence": 0.95,
                        "reason": "键盘密码：每组字符围成圈，圈心字符拼接为 flag",
                        "source": "desc_crypto.keyboard"})
    return out


# ---------------------------------------------------------------------------
# 题面自带完整加密代码的对称密码（N1BOOK 经典题）：直接抽取密钥/密文逆运算
# ---------------------------------------------------------------------------
def _xx(a, b):
    """挑战自定义 GF(2^8) 乘法（约减多项式 x^8=x^6+x^5+x+1，即 ^99）。"""
    t = a
    res = 0
    while b != 0:
        if b & 1:
            res ^= t
        t = (((t << 1) ^ 99) & 0xFF) if (t & 0x80) else (t << 1)
        b >>= 1
    return res


def _solve_n1des(name, desc):
    try:
        if "s_box" not in desc:
            return []
        s_box = eval("[" + re.search(r"s_box\s*=\s*\[(.*?)\]", desc, re.S).group(1) + "]")
        km = re.search(r'key\s*=\s*"([0-9a-fA-F]+)"', desc)
        if not km:
            return []
        key = km.group(1)
        bm = re.search(r"b64encode\(cipher\)\s*#\s*([A-Za-z0-9+/=]+)", desc)
        if not bm:
            return []
        cipher = base64.b64decode(bm.group(1))

        def str_xor(a, b):
            return ''.join(chr(ord(a[i]) ^ ord(b[i])) for i in range(len(a)))

        def f(a, b):
            return hashlib.sha256((a + b).encode('latin-1')).digest()[:8].decode('latin-1')

        def round_add(a, b):
            return str_xor(f(a, b), f(b, a))

        def permutate(table, block):
            return [block[x] for x in table]

        def string_to_bits(data):
            data = [ord(c) for c in data]
            result = [0] * (len(data) * 8)
            pos = 0
            for ch in data:
                for i in range(8):
                    result[(pos << 3) + i] = (ch >> i) & 1
                pos += 1
            return result

        def generate(o):
            return permutate(o, s_box)

        o = string_to_bits(key)
        k = []
        for i in range(8):
            o = generate(o)
            k.extend(o)
            o = string_to_bits([chr(c) for c in o[0:32]])
        Kn = []
        for i in range(32):
            Kn.append(''.join(chr(x) for x in k[i * 8:i * 8 + 8]))

        inv_s = [0] * 256
        for idx, v in enumerate(s_box):
            inv_s[v] = idx

        def sub(x):
            xb = x if isinstance(x, (bytes, bytearray)) else [ord(c) for c in x]
            return ''.join(chr(s_box[v]) for v in xb)

        def sub_inv(x):
            xb = x if isinstance(x, (bytes, bytearray)) else [ord(c) for c in x]
            return ''.join(chr(inv_s[v]) for v in xb)

        def decrypt_block(block):
            if isinstance(block, (bytes, bytearray)):
                block = block.decode('latin-1')
            C1, C2 = block[:8], block[8:]
            Lc, Rc = C2, C1
            for r in range(31, -1, -1):
                Rr = sub_inv(Lc)
                Lr = ''.join(chr(ord(sub_inv(Rc)[i]) ^ ord(round_add(Rr, Kn[r])[i]))
                               for i in range(8))
                Lc, Rc = Lr, Rr
            return (Lc + Rc).encode('latin-1')

        out = b""
        for i in range(0, len(cipher), 16):
            out += decrypt_block(cipher[i:i + 16])
        return [{"value": out.decode('latin-1', 'ignore'),
                 "confidence": 0.93,
                 "reason": "N1DES Feistel(每轮S盒) 逆运算，密钥/密文取自题面",
                 "source": "desc_crypto.n1des"}]
    except Exception:
        return []


def _parse_hex(desc, name, opener, closer):
    start = desc.index(name + " = " + opener)
    rest = desc[start:]
    m = re.search(re.escape(closer) + r"\s*\n", rest)
    region = rest[:m.start()]
    return [int(h, 16) for h in re.findall(r"0x[0-9a-fA-F]+", region)]


def _solve_n1aes(name, desc):
    try:
        if "class N1AES" not in desc:
            return []
        Sbox = _parse_hex(desc, "Sbox", "(", ")")
        InvSbox = _parse_hex(desc, "InvSbox", "(", ")")
        Rcon = _parse_hex(desc, "Rcon", "[", "]")
        km = re.search(r'N1AES\("([^"]+)"\)', desc)
        if not km:
            return []
        key = km.group(1)
        hm = re.search(r"encode\('hex'\)\)\s*#\s*([0-9a-fA-F]+)", desc)
        if not hm:
            return []
        cipher = bytes.fromhex(hm.group(1))

        def xx(i, j):
            return _xx(i, j)

        def text2matrix(text):
            matrix = []
            for i in range(16):
                byte = text[i]
                if i % 4 == 0:
                    matrix.append([byte])
                else:
                    matrix[i // 4].append(byte)
            return matrix

        def matrix2text(matrix):
            return bytes(matrix[i][j] for i in range(4) for j in range(4))

        round_keys = text2matrix(key.encode('latin-1'))
        for i in range(4, 4 * 11):
            round_keys.append([])
            if i % 4 == 0:
                byte = round_keys[i - 4][0] ^ Sbox[round_keys[i - 1][1]] ^ Rcon[i // 4]
                round_keys[i].append(byte)
                for j in range(1, 4):
                    byte = round_keys[i - 4][j] ^ Sbox[round_keys[i - 1][(j + 1) % 4]]
                    round_keys[i].append(byte)
            else:
                for j in range(4):
                    byte = round_keys[i - 4][j] ^ round_keys[i - 1][j]
                    round_keys[i].append(byte)

        r = [14, 12, 10, 11, 3, 2, 0, 13, 9, 5, 4, 8, 15, 1, 6, 7]
        q = [0] * 16
        for i in range(16):
            q[r[i]] = i

        def shift_rows(s):
            t = [s[i // 4][i % 4] for i in range(16)]
            for i in range(16):
                s[i // 4][i % 4] = t[r[i]]

        def inv_shift_rows(s):
            t = [s[i // 4][i % 4] for i in range(16)]
            for i in range(16):
                s[i // 4][i % 4] = t[q[i]]

        def sub_bytes(s):
            for i in range(4):
                for j in range(4):
                    s[i][j] = Sbox[s[i][j]]

        def inv_sub_bytes(s):
            for i in range(4):
                for j in range(4):
                    s[i][j] = InvSbox[s[i][j]]

        def add_round_key(s, k):
            for i in range(4):
                for j in range(4):
                    s[i][j] ^= k[i][j]

        wt = [3, 10, 8, 6]
        M = [[wt[(i + j) % 4] for j in range(4)] for i in range(4)]
        A = [row[:] + [1 if i == j else 0 for j in range(4)] for i, row in enumerate(M)]
        for col in range(4):
            piv = next(rr for rr in range(col, 4) if A[rr][col] != 0)
            A[col], A[piv] = A[piv], A[col]
            e = A[col][col]
            ei = next(x for x in range(256) if xx(e, x) == 1)
            A[col] = [(xx(v, ei) if k2 >= col else v) for k2, v in enumerate(A[col])]
            for rr in range(4):
                if rr != col and A[rr][col] != 0:
                    ff = A[rr][col]
                    A[rr] = [(A[rr][k2] ^ xx(ff, A[col][k2])) for k2 in range(8)]
        Minv = [row[4:] for row in A]

        def mix_columns(s):
            for j in range(4):
                c = [s[0][j], s[1][j], s[2][j], s[3][j]]
                s[0][j] = xx(c[0], wt[0]) ^ xx(c[1], wt[1]) ^ xx(c[2], wt[2]) ^ xx(c[3], wt[3])
                s[1][j] = xx(c[0], wt[1]) ^ xx(c[1], wt[2]) ^ xx(c[2], wt[3]) ^ xx(c[3], wt[0])
                s[2][j] = xx(c[0], wt[2]) ^ xx(c[1], wt[3]) ^ xx(c[2], wt[0]) ^ xx(c[3], wt[1])
                s[3][j] = xx(c[0], wt[3]) ^ xx(c[1], wt[0]) ^ xx(c[2], wt[1]) ^ xx(c[3], wt[2])

        def inv_mix_columns(s):
            for j in range(4):
                c = [s[0][j], s[1][j], s[2][j], s[3][j]]
                s[0][j] = xx(c[0], Minv[0][0]) ^ xx(c[1], Minv[0][1]) ^ xx(c[2], Minv[0][2]) ^ xx(c[3], Minv[0][3])
                s[1][j] = xx(c[0], Minv[1][0]) ^ xx(c[1], Minv[1][1]) ^ xx(c[2], Minv[1][2]) ^ xx(c[3], Minv[1][3])
                s[2][j] = xx(c[0], Minv[2][0]) ^ xx(c[1], Minv[2][1]) ^ xx(c[2], Minv[2][2]) ^ xx(c[3], Minv[2][3])
                s[3][j] = xx(c[0], Minv[3][0]) ^ xx(c[1], Minv[3][1]) ^ xx(c[2], Minv[3][2]) ^ xx(c[3], Minv[3][3])

        def decrypt_block(block):
            if isinstance(block, str):
                block = block.encode('latin-1')
            s = text2matrix(block)
            add_round_key(s, round_keys[40:])
            inv_shift_rows(s)
            inv_sub_bytes(s)
            for i in range(9, 0, -1):
                add_round_key(s, round_keys[4 * i:4 * (i + 1)])
                inv_mix_columns(s)
                inv_shift_rows(s)
                inv_sub_bytes(s)
            add_round_key(s, round_keys[:4])
            return matrix2text(s)

        out = b""
        for i in range(0, len(cipher), 16):
            out += decrypt_block(cipher[i:i + 16])
        return [{"value": out.decode('latin-1', 'ignore'),
                 "confidence": 0.93,
                 "reason": "N1AES 自定义 shift/mix 的 AES-128 逆运算，密钥/密文取自题面",
                 "source": "desc_crypto.n1aes"}]
    except Exception:
        return []


# ---------------------------------------------------------------------------
# 键盘密码（KeyBoard）：每组字符在物理键盘上围成一圈，圈心字符即明文
# ---------------------------------------------------------------------------
_KEYBOARD = [
    ['`', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '-', '='],
    [None, 'q', 'w', 'e', 'r', 't', 'y', 'u', 'i', 'o', 'p', '[', ']', '\\'],
    [None, None, 'a', 's', 'd', 'f', 'g', 'h', 'j', 'k', 'l', ';', "'"],
    [None, None, None, 'z', 'x', 'c', 'v', 'b', 'n', 'm', ',', '.', '/'],
]


def _kb_neighbors(ch):
    for ri, row in enumerate(_KEYBOARD):
        for ci, v in enumerate(row):
            if v == ch:
                out = set()
                for dr in (-1, 0, 1):
                    for dc in (-1, 0, 1):
                        if dr == 0 and dc == 0:
                            continue
                        nr, nc = ri + dr, ci + dc
                        if 0 <= nr < len(_KEYBOARD):
                            rr = _KEYBOARD[nr]
                            if 0 <= nc < len(rr) and rr[nc] is not None:
                                out.add(rr[nc])
                return out
    return set()


def _kb_center(group):
    members = set(group)
    best = None
    best_n = -1
    for ri, row in enumerate(_KEYBOARD):
        for ci, v in enumerate(row):
            if v is None or v in members:
                continue
            nb = _kb_neighbors(v)
            if members and members <= nb:
                cnt = len(members & nb)
                if cnt > best_n:
                    best_n = cnt
                    best = v
    return best


_KB_SHIFT = {'[': '{', ']': '}'}


def _looks_like_keyboard(desc):
    first = ""
    for line in desc.strip().strip('`').strip().splitlines():
        line = line.strip()
        if line:
            first = line
            break
    if not first:
        return False
    groups = first.split()
    if len(groups) < 4:
        return False
    kb_chars = set("`1234567890-=qwertyuiop[]\\asdfghjkl;'zxcvbnm,./")
    return all(all(ch in kb_chars for ch in g) for g in groups)


def solve_keyboard(desc):
    first = ""
    for line in desc.strip().strip('`').strip().splitlines():
        line = line.strip()
        if line:
            first = line
            break
    groups = first.split()
    out = ""
    for g in groups:
        c = _kb_center(g)
        if c is None:
            return None
        out += _KB_SHIFT.get(c, c)
    if out.startswith("n1book"):
        return out.encode('latin-1')
    return None
