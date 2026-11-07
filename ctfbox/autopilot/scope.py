# -*- coding: utf-8 -*-
"""Web 目标地址校验（v3.7.0 起不再做逐目标授权判断）。

授权判断统一由启动时的《软件责任说明》承担（ctfbox/responsibility.py）：
用户在进入软件前已确认对使用的目标拥有合法授权。本模块只做地址合法性校验
与目标类型标注：
  1. 只允许 http/https 绝对地址；
  2. 拒绝带用户名口令的 URL；
  3. 主机类型（loopback/private/public/domain）仅作标注，不做白名单/私网阻断。
不跟随跨域重定向；不提供批量公网扫描入口。
"""
import ipaddress
from urllib.parse import urlsplit

LOOPBACK_HOSTS = {"127.0.0.1", "::1", "localhost"}


class ScopeError(ValueError):
    """目标地址不合法。"""


class ScopeGuard:
    def __init__(self, authorized: bool = True, allow_hosts=None, allow_private: bool = False):
        # 旧参数保留仅为调用兼容；授权已上移到启动责任说明，不再参与拦截。
        self.authorized = bool(authorized)
        self.allow_hosts = {h.lower() for h in (allow_hosts or []) if h}
        self.allow_private = bool(allow_private)

    def host_allowed(self, host: str) -> bool:
        """显式白名单匹配；仅用于标注/兼容，不再作为放行条件。"""
        host = (host or "").lower().rstrip(".")
        if host in self.allow_hosts:
            return True
        for pat in self.allow_hosts:
            if pat.startswith("*."):
                root = pat[2:].rstrip(".")
                if root and (host == root or host.endswith("." + root)):
                    return True
        return False

    def check(self, url: str) -> dict:
        if not isinstance(url, str) or len(url) > 2048:
            raise ScopeError("URL 非法或过长")
        parts = urlsplit(url.strip())
        if parts.scheme not in ("http", "https"):
            raise ScopeError("只接受 http/https 绝对地址")
        if parts.username or parts.password:
            raise ScopeError("不接受带凭据的 URL")
        host = (parts.hostname or "").lower().rstrip(".")
        if not host:
            raise ScopeError("URL 缺少主机名")
        kind = "public"
        if host in LOOPBACK_HOSTS:
            kind = "loopback"
        else:
            try:
                ip = ipaddress.ip_address(host)
                if ip.is_loopback:
                    kind = "loopback"
                elif ip.is_private or ip.is_link_local:
                    kind = "private"
                else:
                    kind = "public"
            except ValueError:
                kind = "domain"
        return {"url": url, "host": host, "kind": kind, "scheme": parts.scheme,
                "port": parts.port or (443 if parts.scheme == "https" else 80)}
