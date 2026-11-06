# -*- coding: utf-8 -*-
"""本地 TCP 闭环测试：验证 ret2win 发送与 flag 抓取。"""
import socket, threading, sys, os, time
sys.path.insert(0, r"D:\工具合集软件\_源码_v2.4")
from ctfbox import pwnrun
from ctfbox.common import Report

HOST, PORT = "127.0.0.1", 19107
flag = b"flag{ret2win_9137}"


def server():
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((HOST, PORT))
    srv.listen(5)
    srv.settimeout(20)
    try:
        for _ in range(3):
            conn, _ = srv.accept()
            conn.sendall(b"welcome\n")
            time.sleep(0.2)
            try:
                data = conn.recv(4096)
            except Exception:
                data = b""
            if len(data) >= 60:
                conn.sendall(b"ok\n" + flag + b"\n")
            else:
                conn.sendall(b"nope\n")
            conn.close()
    finally:
        srv.close()


t = threading.Thread(target=server, daemon=True)
t.start()
time.sleep(0.5)

dummy = os.path.join(os.environ["TEMP"], "dummy_pwn_target")
with open(dummy, "wb") as f:
    f.write(b"\x7fELF" + b"\x00" * 64)

rep = Report(dummy)
res = pwnrun.exploit(dummy, HOST, PORT, offset=64, win_addr=0x401136, report=rep,
                     log=lambda m: print(m))
print("RESULT:", res.get("ok"), res.get("offset"), res.get("flags"))
assert res.get("ok") and res.get("flags") == ["flag{ret2win_9137}"]
print("PWN_SMOKE=PASS")
