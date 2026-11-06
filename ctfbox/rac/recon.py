# -*- coding: utf-8 -*-
"""RAC 附属自动化 —— 侦察自动化（Recon）。

对已授权靶机/靶场批量收集：
  1. TCP 端口扫描（socket 并发，内置 CTF 高频端口表）
  2. HTTP 探测（状态码 / Server / 标题 / 跳转，requests）
  3. 目录探测（内置 60+ 敏感路径字典，仅 HEAD/GET 判状态码）

纯标准库 + requests 实现，零新依赖。仅用于已授权目标。
"""
import re
import socket
import ipaddress
import concurrent.futures as cf
from typing import Callable, Dict, List

try:
    import requests
    _HAVE_REQUESTS = True
except Exception:
    _HAVE_REQUESTS = False

requests.get  # 引用避免 lint 误报

DEFAULT_PORTS = [
    21, 22, 23, 25, 53, 80, 81, 88, 110, 135, 139, 143, 443, 445, 873,
    1080, 1433, 1521, 2222, 2375, 2379, 3000, 3306, 3389, 4444, 5000,
    5432, 5555, 5900, 5984, 6379, 6666, 7001, 7002, 8000, 8001, 8008,
    8009, 8010, 8020, 8080, 8081, 8088, 8089, 8161, 8443, 8848, 8888,
    9000, 9001, 9090, 9200, 9999, 10000, 10250, 11211, 27017, 27018,
    28017, 50000, 61616,
]
RE_TITLE = re.compile(r"<title[^>]*>(.*?)</title>", re.I | re.S)

DIR_DICT = [
    "/robots.txt", "/sitemap.xml", "/.git/HEAD", "/.git/config", "/.svn/entries",
    "/.env", "/.DS_Store", "/backup.zip", "/www.zip", "/web.zip", "/site.zip",
    "/backup.tar.gz", "/1.zip", "/flag.txt", "/flag.php", "/flag", "/readme.txt",
    "/readme.md", "/admin/", "/admin.php", "/admin/login.php", "/login.php",
    "/manager/html", "/phpmyadmin/", "/pma/", "/actuator", "/actuator/env",
    "/actuator/heapdump", "/swagger-ui.html", "/swagger/", "/api-docs",
    "/v2/api-docs", "/druid/", "/druid/index.html", "/console/", "/jetty/",
    "/server-status", "/info.php", "/test.php", "/phpinfo.php", "/shell.php",
    "/upload/", "/uploads/", "/static/", "/debug/", "/api/", "/index.php.bak",
    "/index.bak", "/WEB-INF/web.xml", "/config.php.bak", "/database.sql",
    "/db.sql", "/dump.sql", "/.htaccess", "/crossdomain.xml", "/graphql",
    "/solr/", "/jenkins/", "/nacos/", "/eureka/", "/kibana/", "/grafana/",
]


def parse_ports(spec: str) -> List[int]:
    """端口说明解析："22,80,8000-8100" → 端口列表（上限 2048 个）。"""
    ports = set()
    for part in re.split(r"[,;\s]+", spec or ""):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            try:
                a, b = part.split("-", 1)
                for p in range(int(a), min(int(b), 65535) + 1):
                    ports.add(p)
            except Exception:
                continue
        else:
            try:
                ports.add(int(part))
            except Exception:
                continue
    out = sorted(p for p in ports if 1 <= p <= 65535)
    return out[:2048]


def parse_targets(spec: str) -> List[str]:
    """目标解析：IP/域名/网段(/24 上限)/URL，每行一个，去重。"""
    targets = []
    for line in re.split(r"[\r\n;]+", spec or ""):
        line = line.strip()
        if not line:
            continue
        if "/" in line and not line.startswith("http"):
            try:
                net = ipaddress.ip_network(line, strict=False)
                if net.num_addresses <= 256:
                    targets += [str(h) for h in net.hosts()]
                continue
            except Exception:
                pass
        targets.append(line)
    return list(dict.fromkeys(targets))


def tcp_scan(host: str, ports: List[int], timeout: float = 1.5,
             workers: int = 100) -> List[int]:
    """并发 TCP 连接扫描，返回开放端口列表。"""
    open_ports = []

    def probe(p):
        try:
            with socket.create_connection((host, p), timeout=timeout):
                return p
        except Exception:
            return None

    with cf.ThreadPoolExecutor(max_workers=max(1, workers)) as ex:
        for r in ex.map(probe, ports):
            if r:
                open_ports.append(r)
    return sorted(open_ports)


def http_probe(url: str, timeout: float = 8.0) -> Dict:
    """HTTP 存活探测：状态码/Server/标题/跳转。失败返回 {"ok": False}。"""
    if not _HAVE_REQUESTS:
        return {"url": url, "ok": False, "error": "requests 未安装"}
    out = {"url": url, "ok": False, "status": None, "server": "",
           "title": "", "redirect": ""}
    try:
        r = requests.get(url, timeout=timeout, verify=False, allow_redirects=True)
        out["ok"] = True
        out["status"] = r.status_code
        out["server"] = r.headers.get("Server", "")
        m = RE_TITLE.search(r.text or "")
        if m:
            out["title"] = re.sub(r"\s+", " ", m.group(1)).strip()[:120]
        if r.history:
            out["redirect"] = r.url
    except Exception as e:
        out["error"] = str(e)[:150]
    return out


def dir_scan(base: str, timeout: float = 6.0, words: List[str] = None,
             log: Callable = None) -> List[Dict]:
    """目录探测：对 base URL 尝试敏感路径，返回非 404 结果。"""
    if not _HAVE_REQUESTS:
        return []
    base = base.rstrip("/")
    hits = []
    session = requests.Session()
    session.headers.update({"User-Agent": "CTFToolbox-RAC/2.4"})

    def probe(w):
        url = base + w
        try:
            r = session.get(url, timeout=timeout, verify=False, allow_redirects=False)
            if r.status_code not in (404, 400) and r.status_code < 500:
                return {"path": w, "status": r.status_code,
                        "length": len(r.content or b"")}
        except Exception:
            return None
        return None

    with cf.ThreadPoolExecutor(max_workers=8) as ex:
        for r in ex.map(probe, words or DIR_DICT):
            if r:
                hits.append(r)
                if log:
                    log(f"      [dir] {r['path']} → {r['status']} ({r['length']}B)")
    return hits


def recon_run(targets_spec: str, port_spec: str = "", do_tcp: bool = True,
              do_http: bool = True, do_dir: bool = False,
              timeout: float = 1.5, log: Callable = print,
              cancel_check: Callable = None) -> Dict:
    """侦察编排：多目标 → TCP 扫描 → 对开放 Web 端口 HTTP 探测/目录探测。"""
    targets = parse_targets(targets_spec)
    ports = parse_ports(port_spec) if port_spec else DEFAULT_PORTS
    report = {"targets": [], "time": __import__("time").strftime("%Y-%m-%d %H:%M:%S")}
    log(f"[Recon] 目标 {len(targets)} 个，端口表 {len(ports)} 个")
    for i, t in enumerate(targets, 1):
        if cancel_check and cancel_check():
            log("[!] 已取消")
            break
        host = t
        if t.startswith("http"):
            m = re.match(r"https?://([^/:]+)", t)
            host = m.group(1) if m else t
        log(f"[{i}/{len(targets)}] {t}")
        entry = {"target": t, "open_ports": [], "http": [], "dirs": []}
        if do_tcp:
            try:
                open_ports = tcp_scan(host, ports, timeout=timeout)
                entry["open_ports"] = open_ports
                log(f"    [TCP] 开放: {open_ports if open_ports else '(无)'}")
            except Exception as e:
                log(f"    [TCP] 扫描失败: {e}")
        web_ports = [p for p in entry["open_ports"] if p in (80, 443, 8080, 8000, 8001, 8008, 8081, 8888, 8443, 9000, 3000, 5000, 7001)]
        if do_http and web_ports:
            for p in web_ports:
                scheme = "https" if p in (443, 8443) else "http"
                url = f"{scheme}://{host}:{p}"
                pr = http_probe(url)
                entry["http"].append(pr)
                if pr.get("ok"):
                    log(f"    [HTTP] {url} → {pr['status']}  Server={pr['server'] or '?'}  标题={pr['title'] or '?'}")
                if do_dir and pr.get("ok"):
                    entry["dirs"] = dir_scan(url, log=log)
        elif do_http and not entry["open_ports"] and t.startswith("http"):
            pr = http_probe(t)
            entry["http"].append(pr)
            if pr.get("ok"):
                log(f"    [HTTP] {t} → {pr['status']}  标题={pr['title'] or '?'}")
            if do_dir and pr.get("ok"):
                entry["dirs"] = dir_scan(t, log=log)
        report["targets"].append(entry)
    return report


def report_text(report: Dict) -> str:
    """侦察结果 → 文本报告。"""
    lines = [f"RAC 侦察报告  {report.get('time', '')}", "=" * 56]
    for t in report.get("targets", []):
        lines.append(f"目标: {t['target']}")
        lines.append(f"  开放端口: {t['open_ports'] or '(无)'}")
        for h in t.get("http", []):
            if h.get("ok"):
                lines.append(f"  HTTP {h['url']} → {h['status']}  Server={h['server'] or '?'}  标题={h['title'] or '?'}")
            elif h.get("error"):
                lines.append(f"  HTTP {h['url']} → 失败: {h['error']}")
        for d in t.get("dirs", []):
            lines.append(f"  DIR  {d['path']} → {d['status']} ({d['length']}B)")
        lines.append("")
    return "\n".join(lines)
