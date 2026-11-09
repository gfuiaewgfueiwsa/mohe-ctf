# -*- coding: utf-8 -*-
"""Web/Pwn 辅助：HTTP 探测、内置端口扫描、目录扫描、sqlmap 调用、exp 模板。
仅允许对靶场环境或获得书面授权的目标使用。"""
import os
import re
import sys
import socket
import socket as _sock
import subprocess
import threading
import queue
from concurrent.futures import ThreadPoolExecutor, as_completed

try:
    import requests
    requests.packages.urllib3.disable_warnings()
except Exception:
    requests = None

from . import toolsmgr
from .common import WORKSPACE

TOP_PORTS = [21, 22, 23, 25, 53, 80, 81, 110, 111, 135, 139, 143, 389, 443, 445,
             465, 587, 623, 873, 990, 993, 995, 1080, 1099, 1433, 1521, 1883,
             2049, 2181, 2375, 2376, 3000, 3001, 3128, 3306, 3389, 4000, 4040,
             4369, 4443, 4848, 5000, 5432, 5601, 5672, 5900, 5984, 6000, 6379,
             6443, 7001, 7002, 7077, 8000, 8009, 8010, 8069, 8080, 8081, 8089,
             8161, 8200, 8443, 8500, 8530, 8686, 8800, 8848, 8888, 9000, 9001,
             9043, 9090, 9092, 9100, 9200, 9300, 9418, 9443, 9999, 10000, 10250,
             11211, 15672, 16010, 19000, 27017, 28017, 50000, 50070, 61616]

PORT_SERVICE = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 80: "HTTP",
    443: "HTTPS", 445: "SMB", 3306: "MySQL", 3389: "RDP", 6379: "Redis",
    8080: "HTTP-Proxy", 8443: "HTTPS-Alt", 5432: "PostgreSQL", 1433: "MSSQL",
    1521: "Oracle", 27017: "MongoDB", 9200: "Elasticsearch", 11211: "Memcached",
    5900: "VNC", 2181: "ZooKeeper", 8848: "Nacos", 7001: "WebLogic",
}

DIR_WORDS = [
    "admin", "login", "index", "index.php", "index.html", "robots.txt",
    ".git/HEAD", ".git/config", ".svn/entries", ".env", "flag", "flag.txt",
    "backup", "backup.zip", "backup.sql", "db.sql", "www.zip", "web.zip",
    "1.zip", "test", "test.php", "phpinfo.php", "info.php", "admin.php",
    "admin/login.php", "manager", "manager/html", "console", "actuator",
    "actuator/env", "swagger-ui.html", "v2/api-docs", "api", "upload",
    "uploads", "config", "config.php", "config.json", "shell.php", "cmd.php",
    ".DS_Store", "crossdomain.xml", "web.config", "server-status",
    "phpmyadmin", "pma", "mysql", "adminer.php", "install", "install.php",
    "register", "user", "users", "api/user", "debug", "status", "metrics",
    "druid", "druid/index.html", "nacos", "struts", "struts2", "jenkins",
    ".well-known/security.txt", "sitemap.xml", "composer.json",
]

def http_probe(url: str, log=print):
    if requests is None:
        log("[!] requests 未安装")
        return
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    try:
        r = requests.get(url, timeout=10, verify=False, allow_redirects=True,
                         headers={"User-Agent": "Mozilla/5.0 魔盒-CTF"})
        title = ""
        m = re.search(r"<title[^>]*>(.*?)</title>", r.text, re.I | re.S)
        if m:
            title = m.group(1).strip()[:100]
        log(f"[+] {r.url}")
        log(f"    状态码: {r.status_code}  长度: {len(r.content)}  Server: {r.headers.get('Server','?')}")
        log(f"    Title: {title}")
        interesting = {k: v for k, v in r.headers.items()
                       if k.lower() in ("server", "x-powered-by", "set-cookie", "www-authenticate",
                                        "x-frame-options", "access-control-allow-origin")}
        for k, v in interesting.items():
            log(f"    {k}: {v}")
        return r
    except Exception as e:
        log(f"[!] 探测失败: {e}")
        return None

def port_scan(host: str, ports=None, log=print, workers=8, timeout=2.0, cancel_event=None):
    import time
    from .process_runner import run_command, TaskCancelled, TaskTimeout
    cancel = cancel_event or threading.Event()
    target_ports = _parse_ports(ports) if ports else TOP_PORTS
    if not host or host.startswith("-") or any(char.isspace() for char in host):
        raise ValueError("无效的单目标主机名")
    if cancel.is_set():
        raise TaskCancelled()
    nmap = toolsmgr.get_tool("nmap")
    if nmap:
        log("[*] 调用 nmap 进行单目标限速扫描，可使用停止检测取消。")
        cmd = [nmap, "-Pn", "-sT", "-sV", "--version-light", "--max-rate", "20", "--max-retries", "1", "-p",
               ",".join(str(port) for port in target_ports), host]
        result = run_command(cmd, log=log, cancel_event=cancel, timeout=180)
        if result.returncode:
            raise RuntimeError(f"nmap 退出码 {result.returncode}")
        return
    log("[*] 未检测到 nmap，使用内置低并发 socket 扫描器")
    deadline = time.monotonic() + 180
    addresses = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    family, socktype, proto, _, address = addresses[0]
    open_ports = []

    def one(port):
        if cancel.is_set():
            return None
        endpoint = (address[0], port, *address[2:])
        try:
            with socket.socket(family, socktype, proto) as connection:
                connection.settimeout(timeout)
                if connection.connect_ex(endpoint) == 0:
                    return port
        except OSError:
            return None
        return None

    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = [executor.submit(one, port) for port in target_ports]
        for future in as_completed(futures):
            if cancel.is_set() or time.monotonic() >= deadline:
                for pending in futures:
                    pending.cancel()
                if cancel.is_set():
                    raise TaskCancelled()
                raise TaskTimeout()
            port = future.result()
            if port:
                open_ports.append(port)
                log(f"[+] {host}:{port:<6} OPEN  {PORT_SERVICE.get(port, '')}")
    log(f"[*] 扫描完成，开放端口: {sorted(open_ports)}")

def _parse_ports(value):
    text = ",".join(map(str, value)) if isinstance(value, (list, tuple)) else str(value)
    ports = set()
    for part in text.split(","):
        part = part.strip()
        if not part:
            raise ValueError("端口不能为空")
        ends = part.split("-")
        if len(ends) > 2 or any(not item.isdecimal() for item in ends):
            raise ValueError("端口格式示例：80,443,8000-8100")
        first, last = int(ends[0]), int(ends[-1])
        if not 1 <= first <= last <= 65535:
            raise ValueError("端口必须位于 1–65535，范围起点不得大于终点")
        if last - first >= 1024:
            raise ValueError("单次最多探测 1024 个端口")
        ports.update(range(first, last + 1))
        if len(ports) > 1024:
            raise ValueError("单次最多探测 1024 个端口")
    return sorted(ports)

def dir_scan(url: str, log=print, workers=20, extra_words=None):
    if requests is None:
        log("[!] requests 未安装")
        return
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    base = url.rstrip("/")
    words = DIR_WORDS + (extra_words or [])
    found = []

    def one(word):
        u = base + "/" + word.lstrip("/")
        try:
            r = requests.get(u, timeout=8, verify=False,
                             headers={"User-Agent": "Mozilla/5.0 魔盒-CTF"}, allow_redirects=False)
            if r.status_code in (200, 301, 302, 401, 403):
                return r.status_code, u, len(r.content)
        except Exception:
            return None
        return None

    with ThreadPoolExecutor(max_workers=workers) as ex:
        futs = [ex.submit(one, w) for w in dict.fromkeys(words)]
        for fut in as_completed(futs):
            res = fut.result()
            if res:
                code, u, ln = res
                found.append((code, u))
                log(f"[{code}] {u}  ({ln}B)")
    log(f"[*] 目录扫描完成，命中 {len(found)} 条")

def sqlmap_run(url: str, log=print, extra=None):
    sm = toolsmgr.get_tool("sqlmap")
    if not sm:
        log("[!] 未安装 sqlmap，请先在工具中心下载")
        return
    from .common import external_python
    py = external_python()
    if not py:
        log("[!] 打包环境运行 sqlmap 需要系统安装 Python（python.org），或使用源码版 魔盒-CTF")
        return
    args = [py, sm, "-u", url, "--batch", "--random-agent",
            "--level", "2", "--risk", "1"]
    if extra:
        args += extra
    log("[*] " + " ".join(args))
    p = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                         text=True, encoding="utf-8", errors="replace", bufsize=1,
                         cwd=os.path.dirname(sm))
    for line in p.stdout:
        log(line.rstrip())
    p.wait()
    log(f"[*] sqlmap 退出码 {p.returncode}")

PWN_TEMPLATE = '''#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *
import sys

context(arch="amd64", os="linux", log_level="debug")
elf = ELF("./{binary}")
# libc = ELF("./libc.so.6")

REMOTE = len(sys.argv) > 1 and sys.argv[1] == "r"
if REMOTE:
    io = remote("{host}", {port})
else:
    io = process(elf.path)
    # gdb.attach(io, """
    # b *main
    # c
    # """)

# ====== exploit 开始 ======
payload = b"A" * 0x40
# io.sendline(payload)
# ==========================

io.interactive()
'''

def make_exp(binary_name="pwn", host="127.0.0.1", port=9999):
    fp = os.path.join(WORKSPACE, "pwn_exp.py")
    with open(fp, "w", encoding="utf-8") as f:
        f.write(PWN_TEMPLATE.format(binary=binary_name, host=host, port=port))
    return fp
