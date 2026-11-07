# -*- coding: utf-8 -*-
"""CTFd / PolarCTF 平台客户端（纯 requests，不依赖浏览器）。

支持的闭环：
  登录态导入（Cookie 文件/浏览器 Cookie 字符串）→ 题目列表/详情/附件
  → ctfd-whale 动态实例开机 → 一键梭哈 → 提交 flag。

只访问用户在命令行显式指定的平台域名；不做目标发现、不做批量扫描。
"""
import json
import os
import re
import time
from urllib.parse import urljoin, urlparse

import requests

from ..common import WORKSPACE

POLARCTF_BASE = "https://www.polarctf.com"
_UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
       "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36")


class PlatformError(RuntimeError):
    pass


def _slug(base):
    host = urlparse(base).netloc or base
    return re.sub(r"[^A-Za-z0-9_.-]", "_", host)


def state_path(base):
    return os.path.join(WORKSPACE, "platform", _slug(base) + ".json")


def parse_cookie_input(value):
    """接受 JSON 文件、Playwright cookie 列表、{name: value} 字典或 Cookie 头字符串。"""
    raw = value
    if os.path.isfile(value):
        with open(value, "r", encoding="utf-8-sig") as fp:
            raw = fp.read()
    raw = (raw or "").strip()
    if not raw:
        raise PlatformError("Cookie 为空")
    cookies = []
    if raw.startswith("["):
        for item in json.loads(raw):
            if isinstance(item, dict) and item.get("name"):
                cookies.append({"name": item["name"], "value": item.get("value", ""),
                                "domain": item.get("domain", ""),
                                "path": item.get("path", "/")})
    elif raw.startswith("{"):
        obj = json.loads(raw)
        if "cookies" in obj and isinstance(obj["cookies"], list):
            return parse_cookie_input(json.dumps(obj["cookies"]))
        for name, value in obj.items():
            if name in ("base", "user", "saved_at"):
                continue
            cookies.append({"name": name, "value": str(value), "domain": "", "path": "/"})
    else:
        for part in raw.split(";"):
            if "=" not in part:
                continue
            name, value = part.split("=", 1)
            cookies.append({"name": name.strip(), "value": value.strip(),
                            "domain": "", "path": "/"})
    if not cookies:
        raise PlatformError("未从输入中解析到 Cookie")
    return cookies


class CTFdPlatform:
    def __init__(self, base=POLARCTF_BASE, timeout=30, log=None):
        self.base = (base or POLARCTF_BASE).rstrip("/")
        self.timeout = timeout
        self.log = log or (lambda _m: None)
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": _UA, "Accept": "application/json"})
        self.user = None

    # ---- 登录态 ---------------------------------------------------------
    def load(self):
        path = state_path(self.base)
        if not os.path.isfile(path):
            return False
        try:
            with open(path, "r", encoding="utf-8") as fp:
                data = json.load(fp)
        except Exception:
            return False
        self._apply_cookies(data.get("cookies") or [])
        self.user = data.get("user")
        return True

    def save(self):
        path = state_path(self.base)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        payload = {"base": self.base, "user": self.user,
                   "saved_at": time.strftime("%Y-%m-%d %H:%M:%S"),
                   "cookies": [{"name": c.name, "value": c.value,
                                "domain": c.domain, "path": c.path}
                               for c in self.session.cookies]}
        with open(path, "w", encoding="utf-8") as fp:
            json.dump(payload, fp, ensure_ascii=False, indent=1)
        return path

    def _apply_cookies(self, cookies):
        for c in cookies:
            domain = c.get("domain") or ""
            if not domain:
                domain = urlparse(self.base).hostname
            try:
                self.session.cookies.set(c["name"], c.get("value", ""),
                                         domain=domain, path=c.get("path") or "/")
            except Exception:
                pass

    def import_cookies(self, value):
        cookies = parse_cookie_input(value)
        self._apply_cookies(cookies)
        me = self.me()
        if not me:
            raise PlatformError("Cookie 已导入，但 /api/v1/users/me 未返回登录用户；"
                                "请确认 Cookie 未过期、且包含 session 字段")
        self.user = me.get("name") or me.get("id")
        path = self.save()
        return {"user": self.user, "state": path}

    def login_password(self, name, password):
        page = self.session.get(urljoin(self.base, "/login"), timeout=self.timeout)
        if page.status_code != 200:
            raise PlatformError("登录页不可达：HTTP %s" % page.status_code)
        mo = re.search(r'name=["\']nonce["\'][^>]*value=["\']([^"\']+)', page.text)
        if not mo:
            mo = re.search(r'id=["\']nonce["\'][^>]*value=["\']([^"\']+)', page.text)
        data = {"name": name, "password": password, "_submit": "Submit"}
        if mo:
            data["nonce"] = mo.group(1)
        resp = self.session.post(urljoin(self.base, "/login"), data=data,
                                 timeout=self.timeout, allow_redirects=True)
        me = self.me()
        if not me:
            raise PlatformError("登录失败：用户名/密码错误，或平台要求验证码（HTTP %s）"
                                % resp.status_code)
        self.user = me.get("name") or me.get("id")
        path = self.save()
        return {"user": self.user, "state": path}

    def me(self):
        try:
            r = self.session.get(urljoin(self.base, "/api/v1/users/me"),
                                 timeout=self.timeout)
            body = r.json()
            if r.status_code == 200 and body.get("success"):
                return body.get("data") or {}
        except Exception:
            pass
        return None

    # ---- 题目 -----------------------------------------------------------
    def list_challenges(self, category="", unsolved_only=True, include_hidden=False):
        r = self.session.get(urljoin(self.base, "/api/v1/challenges"),
                             params={"money": 0}, timeout=self.timeout)
        body = r.json()
        if r.status_code != 200 or not body.get("success"):
            raise PlatformError("题目列表获取失败：HTTP %s" % r.status_code)
        out = []
        for item in body.get("data") or []:
            if category and str(item.get("category", "")).upper() != category.upper():
                continue
            if unsolved_only and item.get("solved_by_me"):
                continue
            if not include_hidden and item.get("state") and \
                    item.get("state") not in ("visible", "hidden"):
                continue
            out.append(item)
        return out

    def challenge(self, cid):
        r = self.session.get(urljoin(self.base, "/api/v1/challenges/%s" % cid),
                             timeout=self.timeout)
        body = r.json()
        if r.status_code != 200 or not body.get("success"):
            raise PlatformError("题目 %s 详情获取失败：HTTP %s" % (cid, r.status_code))
        return body.get("data") or {}

    def download_files(self, detail, dest_dir):
        saved = []
        files = detail.get("files") or []
        if not files:
            return saved
        os.makedirs(dest_dir, exist_ok=True)
        for url in files:
            full = urljoin(self.base + "/", url)
            try:
                r = self.session.get(full, timeout=self.timeout, stream=True)
                if r.status_code != 200:
                    continue
                name = os.path.basename(urlparse(full).path) or ("file_%d" % len(saved))
                name = re.sub(r"[^A-Za-z0-9_.\-\u4e00-\u9fff]", "_", name)[:120]
                path = os.path.join(dest_dir, name)
                with open(path, "wb") as fp:
                    for chunk in r.iter_content(65536):
                        fp.write(chunk)
                saved.append(path)
            except Exception as exc:
                self.log("[!] 附件下载失败 %s: %s" % (full, exc))
        return saved

    # ---- ctfd-whale 动态实例 -------------------------------------------
    def wait_ready(self, url, timeout=120, poll=3):
        """whale 返回 user_access 时容器常仍在启动；等到 HTTP 真正可用再开打。"""
        deadline = time.time() + max(0, timeout)
        last = ""
        while time.time() < deadline:
            try:
                r = self.session.get(url, timeout=min(10, self.timeout))
                text = (r.text or "")[:4000]
                last = "HTTP %s %s" % (r.status_code, re.sub(r"<[^>]+>", " ", text)[:120])
                booting = ("启动中" in text or "starting" in text.lower()
                           or "Please wait" in text)
                if r.status_code < 500 and not booting:
                    return {"ready": True, "status": r.status_code, "probe": last}
            except Exception as exc:
                last = str(exc)[:160]
            time.sleep(poll)
        return {"ready": False, "status": 0, "probe": last}

    def _token(self):
        try:
            r = self.session.get(urljoin(self.base, "/token"), timeout=self.timeout)
            data = r.json()
            tok = data.get("data")
            if isinstance(tok, dict):
                tok = tok.get("nonce") or tok.get("csrf_nonce") or ""
            return tok or ""
        except Exception:
            return ""

    def _whale_url(self, cid):
        return urljoin(self.base, "/api/v1/plugins/ctfd-whale/container") + \
            "?challenge_id=%s" % cid

    def instance(self, cid):
        try:
            r = self.session.get(self._whale_url(cid), timeout=self.timeout,
                                 headers={"Accept": "application/json"})
            body = r.json()
            if r.status_code == 200 and body.get("success"):
                return body.get("data") or {}
        except Exception:
            pass
        return {}

    def boot(self, cid, wait=120, poll=3):
        info = self.instance(cid)
        if info.get("user_access"):
            return info
        tok = self._token()
        headers = {"Accept": "application/json", "Content-Type": "application/json",
                   "X-Requested-With": "XMLHttpRequest"}
        if tok:
            headers["CSRF-Token"] = tok
        r = self.session.post(self._whale_url(cid), json={}, timeout=self.timeout,
                              headers=headers)
        if r.status_code >= 400:
            raise PlatformError("实例开机请求失败：HTTP %s %s"
                                % (r.status_code, (r.text or "")[:200]))
        deadline = time.time() + max(0, wait)
        while True:
            info = self.instance(cid)
            if info.get("user_access"):
                return info
            if time.time() >= deadline:
                break
            time.sleep(poll)
        raise PlatformError("实例 %s 秒内未就绪：%s" % (wait, json.dumps(info, ensure_ascii=False)[:300]))

    # ---- 提交 -----------------------------------------------------------
    def submit(self, cid, flag):
        tok = self._token()
        headers = {"Content-Type": "application/json", "Accept": "application/json",
                   "X-Requested-With": "XMLHttpRequest"}
        if tok:
            headers["CSRF-Token"] = tok
        r = self.session.post(urljoin(self.base, "/api/v1/challenges/attempt"),
                              json={"challenge_id": int(cid),
                                    "submission": str(flag).strip()},
                              timeout=self.timeout, headers=headers)
        try:
            body = r.json()
        except Exception:
            raise PlatformError("提交响应非 JSON：HTTP %s" % r.status_code)
        data = body.get("data") or {}
        return {"status": data.get("status") or ("ok" if body.get("success") else "error"),
                "message": data.get("message") or "",
                "raw": body}
