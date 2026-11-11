# -*- coding: utf-8 -*-
"""RAC 附属自动化 —— RPA 会话自动化（步骤表驱动的 HTTP 会话）。

用途：授权靶场中的重复性浏览器动作自动化——自动登录、带 Cookie 连续请求、
自动提交 flag、自动抽取响应中的 token/CSRF 值供后续步骤使用。

步骤表（JSON 数组，每步一个动作）：
  [
    {"action": "get",  "url": "/login.php"},
    {"action": "post", "url": "/login.php",
     "data": {"username": "{user}", "password": "{pass}", "csrf": "{csrf}"}},
    {"action": "submit_flag", "url": "/api/submit", "data": {"flag": "{flag}"}},
    {"action": "sleep", "seconds": 1}
  ]

  - 变量占位：{name}，来自 vars 字典；响应中的 csrf/token/flag 自动回填 vars
  - 相对 url 自动拼 base_url；data 支持 dict（表单）或字符串（原始体）
  - headers 可选每步覆盖；expect_status 可校验；expect_flag=true 时扫描响应

仅用于 CTF 比赛、靶场与已授权目标。
"""
import json
import re
import time
from typing import Callable, Dict, List

try:
    import requests
    _HAVE_REQUESTS = True
except Exception:
    _HAVE_REQUESTS = False

from ..common import scan_flags_text
from ..versioning import APP_VERSION

RE_INPUT_TOKEN = re.compile(
    r"<input[^>]+name=[\"']?(csrf[_\w]*|token|_token|authenticity_token)[\"']?[^>]+value=[\"']([^\"']+)[\"']", re.I)
RE_META_TOKEN = re.compile(
    r"<meta[^>]+name=[\"'](?:csrf-token|csrf)[\"'][^>]+content=[\"']([^\"']+)[\"']", re.I)
RE_ASSIGN_TOKEN = re.compile(
    r"(?:csrf|token|_token)\s*[=:]\s*[\"']([A-Za-z0-9_\-.:/+=]{16,})[\"']", re.I)

MAX_STEPS = 200


def _fill(text: str, vars: Dict) -> str:
    """{name} 占位替换（未定义的保持原样）。"""
    def sub(m):
        k = m.group(1)
        return str(vars.get(k, m.group(0)))
    return re.sub(r"\{([A-Za-z_][A-Za-z0-9_]*)\}", sub, str(text))


def _extract_vars(text: str, vars: Dict) -> None:
    """从响应文本自动抽取 csrf/token 回填 vars（不覆盖已有值）。"""
    for pat in (RE_META_TOKEN, RE_ASSIGN_TOKEN):
        m = pat.search(text or "")
        if m:
            for g in m.groups():
                if g and "csrf" not in vars and "token" not in vars:
                    vars.setdefault("csrf", g)
                    vars.setdefault("token", g)
            return
    for m in RE_INPUT_TOKEN.finditer(text or ""):
        val = m.group(2)
        if val and len(val) >= 8:
            vars.setdefault(m.group(1).lower(), val)
            vars.setdefault("csrf", val)
            return


def parse_steps(text: str) -> List[Dict]:
    """解析步骤表 JSON（宽容：容错 ```json 包裹）。"""
    t = (text or "").strip()
    t = re.sub(r"^```(?:json)?\s*|\s*```$", "", t, flags=re.M)
    steps = json.loads(t)
    if not isinstance(steps, list):
        raise ValueError("步骤表必须是 JSON 数组")
    return steps[:MAX_STEPS]


def run_steps(base_url: str, steps: List[Dict], vars: Dict = None,
              timeout: float = 20.0, log: Callable = print,
              cancel_check: Callable = None) -> Dict:
    """顺序执行步骤表。返回 {"steps": [...], "vars": {...}, "flags": [...]}。"""
    if not _HAVE_REQUESTS:
        raise RuntimeError("requests 未安装")
    vars = dict(vars or {})
    session = requests.Session()
    session.headers.update({
        "User-Agent": "MoHe-CTF-RAC/%s" % APP_VERSION,
        "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
    })
    base = (base_url or "").rstrip("/")
    out = {"steps": [], "vars": vars, "flags": []}

    for i, st in enumerate(steps, 1):
        if cancel_check and cancel_check():
            log("[!] 已取消")
            break
        action = (st.get("action") or "").lower()
        url = _fill(st.get("url", "/"), vars)
        if url.startswith("http"):
            full = url
        else:
            full = base + (url if url.startswith("/") else "/" + url)
        rec = {"i": i, "action": action, "url": full, "status": None,
               "ok": False, "flags": []}
        try:
            if action == "sleep":
                sec = float(st.get("seconds", 1))
                log(f"[{i}] sleep {sec}s")
                time.sleep(min(sec, 30))
                rec["ok"] = True
            elif action in ("get", "open"):
                r = session.get(full, timeout=timeout, verify=False,
                                allow_redirects=True)
                rec["status"] = r.status_code
                rec["ok"] = True
                log(f"[{i}] GET {full} → {r.status_code} ({len(r.content)}B)")
                _extract_vars(r.text, vars)
            elif action in ("post", "submit", "submit_flag"):
                data = st.get("data")
                if isinstance(data, dict):
                    data = {k: _fill(v, vars) for k, v in data.items()}
                    kwargs = {"data": data}
                else:
                    kwargs = {"data": _fill(data or "", vars)}
                hdrs = st.get("headers") or {}
                if hdrs:
                    kwargs["headers"] = {k: _fill(v, vars) for k, v in hdrs.items()}
                r = session.post(full, timeout=timeout, verify=False,
                                 allow_redirects=True, **kwargs)
                rec["status"] = r.status_code
                rec["ok"] = True
                log(f"[{i}] POST {full} → {r.status_code} ({len(r.content)}B)")
                _extract_vars(r.text, vars)
            elif action in ("set", "set_var"):
                k, v = st.get("name", ""), st.get("value", "")
                vars[k] = _fill(v, vars)
                rec["ok"] = True
                log(f"[{i}] 设置变量 {k} = {str(v)[:60]}")
            elif action in ("print", "log"):
                log(f"[{i}] {st.get('text', '')}")
                rec["ok"] = True
            else:
                rec["error"] = f"未知动作 {action!r}（支持 get/post/sleep/set/print）"
                log(f"[{i}] [!] {rec['error']}")
            # 响应处理
            resp_text = ""
            if rec.get("status") is not None:
                resp_text = getattr(r, "text", "") or ""
                exp = st.get("expect_status")
                if exp and rec["status"] != int(exp):
                    log(f"    [!] 状态码 {rec['status']} ≠ 期望 {exp}")
                if st.get("expect_flag"):
                    fs = scan_flags_text(resp_text)
                    if fs:
                        rec["flags"] = fs
                        out["flags"] = list(dict.fromkeys(out["flags"] + fs))
                        log(f"    [!!!] 响应中发现 flag: {'; '.join(fs)}")
                else:
                    fs = scan_flags_text(resp_text)
                    if fs:
                        out["flags"] = list(dict.fromkeys(out["flags"] + fs))
                        log(f"    [*] 响应中出现 flag 形态串: {fs[0][:60]}")
                snippet = resp_text.strip()[:200].replace("\n", " ")
                if snippet:
                    log(f"    | {snippet}")
            # 响应体保存
            save = st.get("save_as")
            if save and resp_text:
                vars[save] = resp_text
        except Exception as e:
            rec["error"] = f"{type(e).__name__}: {e}"
            log(f"[{i}] [!] {rec['error']}")
        out["steps"].append(rec)
    return out
