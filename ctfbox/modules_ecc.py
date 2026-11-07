# -*- coding: utf-8 -*-
"""异常椭圆曲线 + 多维 HNP 攻击（纯 Python，不联网）。

适用题型：给出大量曲线坐标点、隐去 p/a/b 的 ECC 题。
攻击链（公开思路）：
  1. 由任意三点消去 a、b，得到行列式（p 的倍数），多组求 gcd 恢复 p；
  2. 代回恢复 a、b；曲线为异常曲线（#E = p）时，ECDLP 退化；
  3. 在 Q_p 上做 Hensel 提升，把点乘映射为模 p 的线性方程；
  4. 构造正交格：先 LLL 约化，再取右核、用 SNF 取饱和基；
  5. 再 LLL，最短向量按 mod 256 还原明文，提取 flag。

全部为整数/分数运算，不依赖 Sage 或第三方向量库；不执行附件代码。
"""
import math
import re
import time
from fractions import Fraction

from .common import scan_flags

POINT_RE = re.compile(r"\(\s*(\d{40,})\s*,\s*(\d{40,})\s*\)")
MIN_POINTS = 8
MAX_TEXT = 16 * 1024 * 1024


def looks_like(text: str) -> bool:
    """坐标点数量足够多才触发（避免 RSA/普通大整数文本误入重计算）。"""
    return bool(text) and len(text) <= MAX_TEXT and len(POINT_RE.findall(text)) >= MIN_POINTS


# ---------------------------------------------------------------- LLL
def _lll(rows, delta=Fraction(3, 4)):
    """Cohen LLL（整数输入，分数 Gram-Schmidt），返回约化基。"""
    m = len(rows)
    n = len(rows[0])
    y = [[int(v) for v in r] for r in rows]
    ystar = [[Fraction(0)] * n for _ in range(m)]
    mu = [[Fraction(0)] * m for _ in range(m)]
    g = [Fraction(0)] * m
    half = Fraction(1, 2)

    def dot(a, b):
        return sum(x * b[i] for i, x in enumerate(a))

    for i in range(m):
        ystar[i] = [Fraction(v) for v in y[i]]
        for j in range(i):
            mu[i][j] = dot(y[i], ystar[j]) / g[j]
            ystar[i] = [ystar[i][z] - mu[i][j] * ystar[j][z] for z in range(n)]
        g[i] = dot(ystar[i], ystar[i])
    k = 1
    while k < m:
        if abs(mu[k][k - 1]) > half:
            q = (mu[k][k - 1] + half).__floor__()
            y[k] = [y[k][z] - q * y[k - 1][z] for z in range(n)]
            for z in range(k - 1):
                mu[k][z] -= q * mu[k - 1][z]
            mu[k][k - 1] -= q
        if g[k] >= (delta - mu[k][k - 1] ** 2) * g[k - 1]:
            for l in range(k - 2, -1, -1):
                if abs(mu[k][l]) > half:
                    q = (mu[k][l] + half).__floor__()
                    y[k] = [y[k][z] - q * y[l][z] for z in range(n)]
                    for z in range(l):
                        mu[k][z] -= q * mu[l][z]
                    mu[k][l] -= q
            k += 1
        else:
            nu = mu[k][k - 1]
            alpha = g[k] + nu * nu * g[k - 1]
            beta = g[k - 1] / alpha
            mu[k][k - 1] = nu * beta
            g[k] = g[k] * beta
            g[k - 1] = alpha
            y[k], y[k - 1] = y[k - 1], y[k]
            mu[k][:k - 1], mu[k - 1][:k - 1] = mu[k - 1][:k - 1], mu[k][:k - 1]
            for i in range(k + 1, m):
                xi = mu[i][k]
                mu[i][k] = mu[i][k - 1] - nu * xi
                mu[i][k - 1] = mu[k][k - 1] * mu[i][k] + xi
            k = max(k - 1, 1)
    return y


# ---------------------------------------------------------------- 格饱和
def _snf_saturate(rows):
    """用 SNF（含列变换的逆矩阵）把有理零空间基饱和成整数核格。"""
    A = [[int(v) for v in row] for row in rows]
    m = len(A)
    n = len(A[0])
    tinv = [[1 if i == j else 0 for j in range(n)] for i in range(n)]

    def swap_cols(i, j):
        if i == j:
            return
        for r in range(m):
            A[r][i], A[r][j] = A[r][j], A[r][i]
        tinv[i], tinv[j] = tinv[j], tinv[i]

    def col_add(dst, src, q):
        if not q:
            return
        for r in range(m):
            A[r][dst] += q * A[r][src]
        rd, rs = tinv[dst], tinv[src]
        for z in range(n):
            rs[z] -= q * rd[z]

    def row_add(dst, src, q):
        if not q:
            return
        for z in range(n):
            A[dst][z] += q * A[src][z]

    for k in range(min(m, n)):
        while True:
            best = None
            for i in range(k, m):
                for j in range(k, n):
                    v = A[i][j]
                    if v and (best is None or abs(v) < best[0]):
                        best = (abs(v), i, j)
            if best is None:
                return [row[:] for row in tinv[:m]]
            _, pi, pj = best
            if pi != k:
                A[k], A[pi] = A[pi], A[k]
            swap_cols(k, pj)
            pivot = A[k][k]
            restart = False
            for i in range(k + 1, m):
                if A[i][k]:
                    row_add(i, k, -(A[i][k] // pivot))
                    if A[i][k]:
                        A[k], A[i] = A[i], A[k]
                        restart = True
                        break
            if restart:
                continue
            for j in range(k + 1, n):
                if A[k][j]:
                    col_add(j, k, -(A[k][j] // pivot))
                    if A[k][j]:
                        swap_cols(k, j)
                        restart = True
                        break
            if restart:
                continue
            pivot = A[k][k]
            bad = None
            for i in range(k + 1, m):
                for j in range(k + 1, n):
                    if A[i][j] % pivot:
                        bad = i
                        break
                if bad is not None:
                    break
            if bad is not None:
                row_add(k, bad, 1)
                continue
            break
    return [row[:] for row in tinv[:m]]


# ---------------------------------------------------------------- 数论
def _is_probable_prime(n: int) -> bool:
    if n < 2:
        return False
    small = (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37)
    for q in small:
        if n % q == 0:
            return n == q
    d, s = n - 1, 0
    while d % 2 == 0:
        d //= 2
        s += 1
    for a in small:
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(s - 1):
            x = x * x % n
            if x == n - 1:
                break
        else:
            return False
    return True


def _recover_curve(points):
    X = [p[0] for p in points]
    E = [y * y - x * x * x for x, y in points]
    ds = []
    for i in range(len(points) - 2):
        d = (X[i] * (E[i + 1] - E[i + 2])
             - X[i + 1] * (E[i] - E[i + 2])
             + X[i + 2] * (E[i] - E[i + 1]))
        if d:
            ds.append(d)
    p = 0
    for d in ds:
        p = math.gcd(p, abs(d))
    for q in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47):
        while p % q == 0:
            p //= q
    if p.bit_length() < 128 or not _is_probable_prime(p):
        raise ValueError("无法从坐标恢复素数 p")
    a = (E[0] - E[1]) * pow(X[0] - X[1], -1, p) % p
    b = (E[0] - a * X[0]) % p
    for x, y in points:
        if (y * y - (x * x * x + a * x + b)) % p:
            raise ValueError("坐标不在同一条曲线上")
    return p, a, b


# ---------------------------------------------------------------- Qp / HNP
class _Qp:
    """相对精度 2 的 p 进数：p^v * u，u 为模 p^2 的单位。"""
    __slots__ = ("v", "u", "p")

    def __init__(self, p, v, u=0):
        self.p = p
        self.v = v
        self.u = u % (p * p) if v is not None else 0
        if v is not None:
            while self.u % p == 0:
                if self.u == 0:
                    self.v = None
                    break
                self.u //= p
                self.v += 1

    def __bool__(self):
        return self.v is not None

    def __eq__(self, other):
        return (self.v == other.v and self.u == other.u) if isinstance(other, _Qp) else False

    def __neg__(self):
        return _Qp(self.p, None) if not self else _Qp(self.p, self.v, -self.u)

    def __add__(self, other):
        if not self:
            return other
        if not other:
            return self
        p = self.p
        if self.v < other.v:
            d = other.v - self.v
            return _Qp(p, self.v, self.u + (other.u * pow(p, d, p * p) if d < 2 else 0))
        if other.v < self.v:
            d = self.v - other.v
            return _Qp(p, other.v, other.u + (self.u * pow(p, d, p * p) if d < 2 else 0))
        return _Qp(p, self.v, self.u + other.u)

    def __sub__(self, other):
        return self + (-other)

    def __mul__(self, other):
        if not self or not other:
            return _Qp(self.p, None)
        return _Qp(self.p, self.v + other.v, self.u * other.u)

    def __truediv__(self, other):
        if not other:
            raise ZeroDivisionError
        p = self.p
        return _Qp(p, self.v - other.v, self.u * pow(other.u, -1, p * p))


def _qp(p, x):
    return _Qp(p, 0, x)


def _point_add(P, Q, aq):
    if P is None:
        return Q
    if Q is None:
        return P
    x1, y1 = P
    x2, y2 = Q
    if x1 == x2 and y1 == -y2:
        return None
    if P == Q:
        lam = (_qp(aq.p, 3) * x1 * x1 + aq) / (_qp(aq.p, 2) * y1)
    else:
        lam = (y2 - y1) / (x2 - x1)
    x3 = lam * lam - x1 - x2
    return (x3, lam * (x1 - x3) - y1)


def _point_mul(k, P, a):
    R = None
    Q = P
    while k:
        if k & 1:
            R = _point_add(R, Q, a)
        Q = _point_add(Q, Q, a)
        k >>= 1
    return R


def _hensel_y(x, y, a, b, p):
    m = p * p
    f = (y * y - (x * x * x + a * x + b)) % m
    return (y - f * pow(2 * y, -1, m)) % m


def _hnp_values(points, p, a, b):
    aq = _qp(p, a)
    out = []
    for x, y in points:
        y2 = _hensel_y(x, y, a, b, p)
        R = _point_mul(p, (_qp(p, x % (p * p)), _qp(p, y2)), aq)
        if R is None:
            raise ValueError("p*P 为单位元，Qp 提升失败")
        rx, ry = R
        t = (-rx) / ry
        if t.v != 1:
            raise ValueError("Qp 提升后的赋值异常")
        out.append(t.u % p)
    return out


# ---------------------------------------------------------------- 主流程
def _nullspace(rows, n):
    A = [[Fraction(v) for v in row] for row in rows]
    m = len(A)
    pivots = []
    r = 0
    for c in range(n):
        p = next((i for i in range(r, m) if A[i][c]), None)
        if p is None:
            continue
        A[r], A[p] = A[p], A[r]
        pv = A[r][c]
        A[r] = [v / pv for v in A[r]]
        for i in range(m):
            if i != r and A[i][c]:
                q = A[i][c]
                A[i] = [A[i][z] - q * A[r][z] for z in range(n)]
        pivots.append(c)
        r += 1
        if r == m:
            break
    free = [c for c in range(n) if c not in pivots]
    basis = []
    for f in free:
        v = [Fraction(0)] * n
        v[f] = Fraction(1)
        for i, pc in enumerate(pivots):
            v[pc] = -A[i][f]
        basis.append(v)
    return basis


def _clear_den(vectors):
    out = []
    for v in vectors:
        den = 1
        for x in v:
            den = math.lcm(den, x.denominator)
        row = [int(x * den) for x in v]
        g = 0
        for x in row:
            g = math.gcd(g, abs(x))
        out.append([x // (g or 1) for x in row])
    return out


def _extract_flags(rows):
    found = []
    for row in rows:
        for sign in (1, -1):
            raw = bytes((sign * v) % 256 for v in row)
            for fl in scan_flags(raw, strong_only=True):
                if fl not in found:
                    found.append(fl)
            text = "".join(chr(b) for b in raw if 32 <= b < 127)
            for fl in scan_flags(text.encode("ascii", "ignore"), strong_only=True):
                if fl not in found:
                    found.append(fl)
    return found


def attack(text: str, time_budget: float = 180.0) -> dict:
    """对坐标文本执行异常曲线 HNP 攻击。不可用时抛 ValueError。"""
    t0 = time.time()
    pairs = POINT_RE.findall(text or "")
    if len(pairs) < MIN_POINTS:
        raise ValueError("坐标点不足 %d 个" % MIN_POINTS)
    points = [(int(a), int(b)) for a, b in pairs]
    p, a, b = _recover_curve(points)
    hs = _hnp_values(points, p, a, b)
    k = len(hs)
    inv_hk = pow(hs[-1], -1, p)
    M = [[0] * k for _ in range(k)]
    for i in range(k - 1):
        M[i][i] = 1
        M[i][k - 1] = (-hs[i] * inv_hk) % p
    M[k - 1][k - 1] = p

    red = _lll(M)

    def try_subset(rows):
        basis = _clear_den(_nullspace(rows, k))
        sat = _snf_saturate(basis)
        return _extract_flags(_lll(sat))

    flags = []
    for subset in (red[:k - 3], red[3:]):
        flags = try_subset(subset)
        if flags:
            break
    return {
        "flags": flags,
        "points": k,
        "p_bits": p.bit_length(),
        "elapsed": round(time.time() - t0, 1),
    }


def analyze_text(text: str, rep, time_budget: float = 180.0) -> bool:
    """供 dispatcher 调用：命中则把证据和 flag 写入 Report。"""
    if not looks_like(text):
        return False
    try:
        res = attack(text, time_budget=time_budget)
    except Exception as exc:
        rep.add("info", "ECC 异常曲线分析跳过", str(exc)[:160])
        return False
    rep.add("ok", "ECC 异常曲线",
            "恢复 p（%d bit），%d 个坐标点，耗时 %.1fs；"
            "攻击链：行列式求 p → Qp/Hensel → 正交格 SNF + LLL"
            % (res["p_bits"], res["points"], res["elapsed"]))
    for fl in res["flags"]:
        rep.add("flag", "异常曲线 + 多维 HNP 还原 flag", fl)
    if not res["flags"]:
        rep.add("info", "ECC 异常曲线", "格已约化但未还原出 flag，需人工复核")
    return bool(res["flags"])
