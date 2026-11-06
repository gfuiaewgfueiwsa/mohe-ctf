# -*- coding: utf-8 -*-
"""RAC 第二步（前半）—— Assemble 之脚本库匹配引擎。

扫描 scripts/library/ 下的 88 个自包含脚本，静态解析：
  1. 文件头注释（脚本名称 / 方向 / 简介 / 用法 / 依赖）
  2. argparse 参数表（ast 解析 add_argument 调用）
  3. PARAMS 风格参数字典（顶层大写常量 = {...}，值为 None 视为必填）

然后按「题型方向 × 参数覆盖率 × 关键词命中 × 依赖可用性」评分匹配，
返回 top-N 候选脚本供 runner 依序尝试。

frozen 打包后 scripts 数据被构建脚本归位到 exe 同级（与 tools/samples 一起），
因此定位顺序为：exe 同级 scripts/library → _MEIPASS/scripts/library → 开发态工程根 scripts/library
（与 ctfbox/ui_scripts.py 的 library_root 口径一致）。
"""
import ast
import os
import re
import sys
import importlib.util
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from ..common import APP_DIR


def scripts_root() -> str:
    """定位脚本库目录：打包后 exe 同级 → _MEIPASS → 开发态工程根。"""
    candidates = [os.path.join(APP_DIR, "scripts", "library")]
    meipass = getattr(sys, "_MEIPASS", None)
    if meipass:
        candidates.append(os.path.join(meipass, "scripts", "library"))
    candidates.append(os.path.join(
        os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
        "scripts", "library"))
    for c in candidates:
        if os.path.isdir(c):
            return c
    return candidates[0]


SCRIPTS_ROOT = scripts_root()

CATEGORIES = ("crypto", "misc", "web", "pwn", "reverse", "forensics", "utils")

# 脚本头「依赖: pip install xxx yyy」里 pip 包名 → import 模块名映射
PIP_TO_MODULE = {
    "pycryptodome": "Crypto", "pycryptodomex": "Cryptodome", "pwntools": "pwn",
    "opencv-python": "cv2", "opencv-python-headless": "cv2", "pillow": "PIL",
    "python-registry": "Registry", "python-evtx": "Evtx", "pyelftools": "elftools",
    "scapy": "scapy", "requests": "requests", "paramiko": "paramiko",
    "numpy": "numpy", "gmpy2": "gmpy2", "qrcode": "qrcode", "gmssl": "gmssl",
    "itsdangerous": "itsdangerous", "flask": "flask", "angr": "angr",
    "matplotlib": "matplotlib", "capstone": "capstone", "cryptography": "cryptography",
    "z3-solver": "z3", "ecdsa": "ecdsa", "sympy": "sympy",
}

RE_HEADER = {
    "title": re.compile(r"^\s*#\s*脚本名称[:：]\s*(.+?)\s*$", re.M),
    "direction": re.compile(r"^\s*#\s*方向[:：]\s*(.+?)\s*$", re.M),
    "brief": re.compile(r"^\s*#\s*简介[:：]\s*(.+?)\s*$", re.M),
    "usage": re.compile(r"^\s*#\s*用法[:：]\s*(.+?)\s*$", re.M),
    "deps": re.compile(r"^\s*#\s*依赖[:：]\s*(.+?)\s*$", re.M),
}
DIRECTION_MAP = {  # 脚本头「方向」标签 → library 子目录名
    "crypto": "crypto", "misc": "misc", "web": "web", "pwn": "pwn",
    "reverse": "reverse", "forensics": "forensics", "utils": "utils",
}


@dataclass
class ScriptEntry:
    path: str
    name: str = ""
    category: str = ""            # library 子目录（crypto/misc/web/pwn/reverse/forensics/utils）
    title: str = ""
    direction: str = ""
    brief: str = ""
    usage: str = ""
    deps: List[str] = field(default_factory=list)             # pip 包名
    deps_ok: bool = True
    missing_deps: List[str] = field(default_factory=list)
    args: Dict[str, dict] = field(default_factory=dict)       # argparse: name -> {required, default, metavar}
    params_keys: List[str] = field(default_factory=list)      # PARAMS 字典键
    params_required: List[str] = field(default_factory=list)  # 其中默认值 None（必填）的键
    has_selftest: bool = False

    @property
    def needed_params(self) -> List[str]:
        """脚本必需的参数键（argparse required + PARAMS 必填，小写去重）。"""
        out = [a.strip("-").lower() for a, v in self.args.items() if v.get("required")]
        out += [k.lower() for k in self.params_required]
        return sorted(set(out))

    def as_dict(self):
        return {
            "name": self.name, "path": self.path, "category": self.category,
            "title": self.title, "brief": self.brief[:200], "deps": self.deps,
            "deps_ok": self.deps_ok, "missing_deps": self.missing_deps,
            "args": list(self.args.keys()), "params_keys": self.params_keys,
            "needed_params": self.needed_params, "has_selftest": self.has_selftest,
        }


def _check_deps(deps: List[str]):
    ok, missing = True, []
    for pkg in deps:
        mod = PIP_TO_MODULE.get(pkg.lower(), pkg.lower().replace("-", "_"))
        try:
            if importlib.util.find_spec(mod) is None:
                ok, _ = False, missing.append(pkg)
        except Exception:
            ok = False
    return ok, missing


def parse_script(path: str, category: str) -> Optional[ScriptEntry]:
    """静态解析一个脚本：头部注释 + argparse + PARAMS。解析失败返回 None。"""
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            src = f.read()
        if len(src) > 2_000_000:
            return None
        entry = ScriptEntry(path=path, name=os.path.splitext(os.path.basename(path))[0],
                            category=category)
        for key, pat in RE_HEADER.items():
            m = pat.search(src)
            if m:
                setattr(entry, key, m.group(1).strip())
        # 方向标签归一化（如 "Crypto（密码学 / RSA）" → crypto）
        d = entry.direction.lower()
        for tag, cat in DIRECTION_MAP.items():
            if tag in d:
                entry.category = cat
                break
        # 依赖检查
        dep_line = entry.deps or ""
        pkgs = [t for t in re.findall(r"[A-Za-z0-9_\-.]+", dep_line)
                if t.lower() not in ("pip", "install", "python", "需要", "可选")]
        entry.deps = pkgs
        entry.deps_ok, entry.missing_deps = _check_deps(pkgs)
        entry.has_selftest = "--selftest" in src
        # ast 解析
        try:
            tree = ast.parse(src, filename=path)
        except SyntaxError:
            tree = None
        if tree is not None:
            for node in ast.walk(tree):
                # add_argument("--n", required=True, default=...) / add_argument("path")
                if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) \
                        and node.func.attr == "add_argument" and node.args:
                    a0 = node.args[0]
                    if isinstance(a0, ast.Constant) and isinstance(a0.value, str):
                        name = a0.value
                        info = {"required": False, "default": None, "metavar": ""}
                        for kw in node.keywords:
                            if kw.arg == "required" and isinstance(kw.value, ast.Constant):
                                info["required"] = bool(kw.value.value)
                            elif kw.arg == "default" and isinstance(kw.value, ast.Constant):
                                info["default"] = kw.value.value
                            elif kw.arg == "metavar" and isinstance(kw.value, ast.Constant):
                                info["metavar"] = str(kw.value.value)
                        entry.args[name] = info
                # 顶层大写常量 dict（PARAMS 风格）。判定条件收紧：
                # 常量名含 PARAM，或字典值以 None 为主（参数占位）——
                # 排除字母频率表/字符映射表（值为数字/字符串，如 xor_single_byte 的 FREQ）
                if isinstance(node, ast.Assign):
                    for t in node.targets:
                        if isinstance(t, ast.Name) and t.id.isupper() and \
                                isinstance(node.value, ast.Dict) and node.value.keys:
                            keys = [k.value for k in node.value.keys
                                    if isinstance(k, ast.Constant) and isinstance(k.value, str)]
                            if not keys or len(keys) < 2:
                                continue
                            consts = [v.value for v in node.value.values
                                      if isinstance(v, ast.Constant)]
                            none_ratio = (sum(1 for v in consts if v is None)
                                          / max(1, len(consts)))
                            is_params = ("PARAM" in t.id.upper()) or (none_ratio >= 0.5)
                            if not is_params:
                                continue
                            req = []
                            for kv, vv in zip(node.value.keys, node.value.values):
                                if isinstance(kv, ast.Constant) and isinstance(kv.value, str) \
                                        and isinstance(vv, ast.Constant) and vv.value is None:
                                    req.append(kv.value)
                            entry.params_keys = keys
                            entry.params_required = req
        return entry
    except Exception:
        return None


class ScriptIndex:
    """脚本库索引：build() 一次，match() 多次。"""

    def __init__(self, root: str = None):
        self.root = root or scripts_root()
        self.entries: List[ScriptEntry] = []
        self._built = False

    def build(self, log_cb=None) -> int:
        self.entries = []
        if not os.path.isdir(self.root):
            if log_cb:
                log_cb(f"[!] 脚本库目录不存在: {self.root}")
            return 0
        for cat in CATEGORIES:
            cdir = os.path.join(self.root, cat)
            if not os.path.isdir(cdir):
                continue
            for fn in sorted(os.listdir(cdir)):
                if not fn.lower().endswith(".py"):
                    continue
                e = parse_script(os.path.join(cdir, fn), cat)
                if e:
                    self.entries.append(e)
        self._built = True
        if log_cb:
            log_cb(f"[+] 脚本库索引完成: {len(self.entries)} 个可执行脚本")
        return len(self.entries)

    def match(self, task, top_n: int = 5) -> List[tuple]:
        """按任务卡评分匹配，返回 [(score, ScriptEntry)] 降序。"""
        if not self._built:
            self.build()
        results = []
        tparams = set(task.params.keys())
        # 别名扩展：装配器用 ARG_ALIASES 把任务参数映射到脚本参数（ciphertext→-s/data/ct...），
        # 匹配评分必须用同一张映射，否则"参数能填进去"的脚本反而拿不到交集分
        tparams_exp = set(tparams)
        from .assembler import ARG_ALIASES as _ALIASES
        for _tk, _aliases in _ALIASES.items():
            if _tk in tparams:
                tparams_exp.update(_aliases)
        tkws = set(task.keywords) | set(tparams_exp)
        tlow = (task.description or "").lower()
        for e in self.entries:
            score = 0.0
            # 1) 题型方向匹配
            if task.category != "unknown":
                if e.category == task.category:
                    score += 25
                elif e.category == "utils":
                    score += 5
                else:
                    score += 6  # 其他类别弱加权（不直接为 0，防分类偏差漏配）
            # 2) argparse 必填参数覆盖（主导分）
            needed = e.needed_params
            if needed:
                covered = sum(1 for k in needed if k in tparams_exp)
                cover = covered / len(needed)
                score += 30.0 * cover
                if cover >= 1.0:
                    score += 8   # 全参数就绪 bonus
            # 2b) PARAMS 字典风格脚本：任务参数与字典键交集越大越相关
            #     （PARAMS 全 None 不代表"缺一不可"，只代表"有则填入"，如 rsa_all_in_one）
            if e.params_keys:
                ekeys = {k.lower() for k in e.params_keys}
                overlap = len(ekeys & tparams_exp)
                if overlap:
                    score += min(12 * overlap, 28)
                # RSA 强信号：任务给出 n+c（或 n+e+c），脚本也支持 → 大幅加权
                if {"n", "c"} <= (ekeys & tparams_exp):
                    score += 12
            elif task.category == "crypto" and \
                    ({"n", "e", "c"} & tparams_exp):
                score += 3       # 无参数接口的 crypto 脚本遇到 RSA 参数给一点线索分
            # 2c) argparse 参数（可选 + 位置）与任务参数别名扩展后的交集
            #     按"任务参数主键"计数：ciphertext 能映射到脚本的 -s/--text/data 等任一别名
            #     即视为该主键被支持（硬信号，权重高于泛词命中）
            _SKIP_ARGS = {"selftest", "verbose", "debug", "quiet", "out", "o",
                          "h", "help", "top", "enc", "dec"}
            opt_names = {a.strip("-").lower() for a in e.args
                         if a.strip("-").lower() not in _SKIP_ARGS}
            covered_keys = {t for t in tparams if t in opt_names}
            for _tk, _aliases in _ALIASES.items():
                if _tk in tparams and (set(_aliases) & opt_names):
                    covered_keys.add(_tk)
            if covered_keys:
                score += min(10 * len(covered_keys), 24)
            # 3) 关键词命中（脚本名/标题/简介 vs 任务关键词）
            etext = f"{e.name} {e.title} {e.brief}".lower()
            # RSA 术语强信号：题目同时给出 n 和 c 时，名字/简介明确含 rsa 的脚本优先
            if {"n", "c"} <= tparams and "rsa" in etext:
                score += 15
            hits = 0
            for kw in tkws:
                if kw and kw.lower() in etext:
                    hits += 1
            score += min(hits * 4, 10)
            # 4) 任务描述中的英文术语直接出现在脚本简介（如 wiener）
            tok_hits = 0
            for tok in set(re.findall(r"[a-z_]{4,}", tlow)):
                if tok in etext:
                    tok_hits += 1
                    if tok_hits >= 4:
                        break
            score += min(tok_hits * 2, 8)
            # 5) 依赖不可用软惩罚（多数脚本有纯 Python 回退；仍保留候选由执行验证）
            if not e.deps_ok:
                score -= 12
            if score <= 3:
                continue
            results.append((score, e))
        results.sort(key=lambda x: -x[0])
        return results[:top_n]
