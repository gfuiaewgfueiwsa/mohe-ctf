# -*- coding: utf-8 -*-
"""流量分析增强：协议统计、HTTP 对象提取、DNS 隧道特征、文件还原、TCP 流重组。

独立入口 analyze() 供「赛事专项」页/CLI 使用；enhance() 把结果桥接进常规
pcap 分析报告。全程离线，只读抓包文件。
"""
import base64
import binascii
import gzip
import hashlib
import math
import os
import re
import zlib
from collections import Counter, defaultdict
from urllib.parse import parse_qs, unquote_plus, urlsplit

from . import util

try:
    from scapy.all import (DNS, ICMP, IP, IPv6, PcapNgReader, PcapReader, Raw,
                           TCP, UDP)
except Exception:
    PcapReader = None
    DNS = None

HTTP_REQ = re.compile(
    rb"(?m)^(GET|POST|PUT|HEAD|OPTIONS|PATCH|DELETE|CONNECT|TRACE) "
    rb"(\S+) HTTP/1\.[01]\r\n")
HTTP_RESP = re.compile(rb"(?m)^HTTP/1\.[01] (\d{3})[^\r\n]*\r\n")
HTTP_START = re.compile(
    rb"(?m)^(?:HTTP/1\.[01] \d{3}[^\r\n]*|(?:GET|POST|PUT|HEAD|OPTIONS|PATCH|DELETE|"
    rb"CONNECT|TRACE) \S+ HTTP/1\.[01])\r\n")

MAGIC = [
    ("png", b"\x89PNG\r\n\x1a\n", b"IEND\xaeB`\x82", 8 * 1024 * 1024),
    ("jpg", b"\xff\xd8\xff", b"\xff\xd9", 8 * 1024 * 1024),
    ("gif", b"GIF8", b"\x00\x3b", 4 * 1024 * 1024),
    ("pdf", b"%PDF-", b"%%EOF", 16 * 1024 * 1024),
    ("zip", b"PK\x03\x04", b"PK\x05\x06", 20 * 1024 * 1024),
    ("rar", b"Rar!\x1a\x07", b"", 20 * 1024 * 1024),
    ("7z", b"7z\xbc\xaf\x27\x1c", b"", 20 * 1024 * 1024),
    ("sqlite", b"SQLite format 3\x00", b"", 20 * 1024 * 1024),
    ("elf", b"\x7fELF", b"", 20 * 1024 * 1024),
    ("pe", b"MZ", b"", 20 * 1024 * 1024),
]

EXT_CTYPE = {
    "image/png": ".png", "image/jpeg": ".jpg", "image/gif": ".gif",
    "application/pdf": ".pdf", "application/zip": ".zip",
    "application/x-rar-compressed": ".rar", "application/octet-stream": ".bin",
    "text/html": ".html", "text/plain": ".txt", "application/json": ".json",
    "application/javascript": ".js", "text/css": ".css", "image/webp": ".webp",
    "application/x-7z-compressed": ".7z", "application/vnd.android.package-archive": ".apk",
}

ENCODED_LABEL = re.compile(r"^[A-Za-z0-9+/=_-]{10,}$")
HEX_LABEL = re.compile(r"^[0-9a-fA-F]{16,}$")
B32_LABEL = re.compile(r"^[A-Z2-7=]{16,}$")


def _reader(path):
    if path.lower().endswith(".pcapng"):
        return PcapNgReader(path)
    return PcapReader(path)


def _unpack_ip(pkt):
    if IP in pkt:
        return pkt[IP], "IPv4"
    if IPv6 in pkt:
        return pkt[IPv6], "IPv6"
    return None, ""


def _reassemble(segments):
    if not segments:
        return b"", {"gaps": 0, "missing": 0, "overlap": 0}
    base = min(segments)
    out = bytearray()
    expected = base
    gaps = 0
    missing = 0
    overlap = 0
    for seq in sorted(segments):
        payload = segments[seq]
        if seq > expected:
            gaps += 1
            missing += seq - expected
            expected = seq
        if seq < expected:
            skip = expected - seq
            if skip >= len(payload):
                continue
            overlap += skip
            payload = payload[skip:]
            seq = expected
        out += payload
        expected = seq + len(payload)
    return bytes(out), {"gaps": gaps, "missing": missing, "overlap": overlap}


def _dechunk(body):
    """返回 (decoded, consumed)；不完整时 consumed 指向已解析位置。"""
    out = bytearray()
    pos = 0
    while True:
        line_end = body.find(b"\r\n", pos)
        if line_end < 0:
            return bytes(out), len(body)
        try:
            size = int(body[pos:line_end].split(b";")[0].strip(), 16)
        except Exception:
            return bytes(out), pos
        pos = line_end + 2
        if size == 0:
            end = body.find(b"\r\n", pos)
            return bytes(out), (end + 2 if end >= 0 else len(body))
        if pos + size > len(body):
            out += body[pos:]
            return bytes(out), len(body)
        out += body[pos:pos + size]
        pos += size
        if body[pos:pos + 2] == b"\r\n":
            pos += 2


def _decode_content(body, encoding, content_type=""):
    enc = (encoding or "").lower()
    if "gzip" in enc:
        try:
            return gzip.decompress(body), "gzip"
        except Exception:
            try:
                return zlib.decompress(body, 16 + zlib.MAX_WBITS), "gzip"
            except Exception:
                return body, "gzip-failed"
    if "deflate" in enc:
        for wbits in (zlib.MAX_WBITS, -zlib.MAX_WBITS):
            try:
                return zlib.decompress(body, wbits), "deflate"
            except Exception:
                continue
        return body, "deflate-failed"
    if "br" in enc:
        try:
            import brotli
            return brotli.decompress(body), "br"
        except Exception:
            return body, "br-failed"
    return body, ""


def _parse_headers(raw):
    headers = {}
    lines = raw.split(b"\r\n")
    for line in lines[1:]:
        if b":" not in line:
            continue
        k, v = line.split(b":", 1)
        headers[k.decode("latin-1").strip().lower()] = v.decode("latin-1").strip()
    return headers


def _parse_http(data, flow, ts):
    """解析方向流内的 HTTP 消息，返回 (messages, consumed_end)。"""
    messages = []
    pos = 0
    limit = len(data)
    guard = 0
    while pos < limit and guard < 2000:
        guard += 1
        start = HTTP_START.search(data, pos)
        if not start:
            break
        pos = start.start()
        head_end = data.find(b"\r\n\r\n", pos)
        if head_end < 0:
            break
        first_line_end = data.find(b"\r\n", pos)
        if first_line_end < 0:
            break
        first_line = data[pos:first_line_end].decode("latin-1", "replace")
        headers = _parse_headers(data[pos:head_end + 4])
        body_start = head_end + 4
        m_resp = HTTP_RESP.match(data, pos)
        m_req = HTTP_REQ.match(data, pos)
        if not m_resp and not m_req:
            pos = start.end()
            continue
        is_resp = bool(m_resp)
        status = int(m_resp.group(1)) if m_resp else 0
        method = path = ""
        if m_req:
            method = m_req.group(1).decode("latin-1")
            path = m_req.group(2).decode("latin-1", "replace")
        body = b""
        consumed = body_start
        if "chunked" in headers.get("transfer-encoding", "").lower():
            body, used = _dechunk(data[body_start:])
            consumed = body_start + used
        elif headers.get("content-length", "").isdigit():
            length = int(headers["content-length"])
            available = min(length, max(0, limit - body_start))
            body = data[body_start:body_start + available]
            consumed = body_start + available
            if available < length:
                consumed = limit
        elif is_resp and (status in (204, 304) or status < 200):
            consumed = body_start
        elif is_resp:
            # 无长度：按 Connection: close 语义取剩余，遇到下一条消息则截断
            nxt = HTTP_START.search(data, body_start)
            consumed = nxt.start() if nxt else limit
            body = data[body_start:consumed]
        messages.append({
            "flow": flow, "ts": ts, "is_response": is_resp, "status": status,
            "method": method, "path": path, "headers": headers,
            "header_raw": data[pos:head_end + 4][:8192],
            "body": body, "first_line": first_line,
        })
        if consumed <= pos:
            consumed = head_end + 4
        pos = consumed
        if len(body) >= limit - body_start:
            break
    return messages


def _basic_auth(headers):
    auth = headers.get("authorization", "")
    if auth.lower().startswith("basic "):
        try:
            raw = base64.b64decode(auth.split(" ", 1)[1]).decode("utf-8", "replace")
            return raw
        except Exception:
            return ""
    return ""


def _form_fields(body, ctype):
    fields = []
    try:
        if "application/x-www-form-urlencoded" in ctype:
            text = body.decode("utf-8", "replace")
            for key, values in parse_qs(text, keep_blank_values=True).items():
                for value in values:
                    fields.append((key, value))
        elif "application/json" in ctype:
            import json
            obj = json.loads(body.decode("utf-8", "replace"))
            if isinstance(obj, dict):
                for key, value in obj.items():
                    if isinstance(value, (str, int, float)):
                        fields.append((str(key), str(value)))
    except Exception:
        pass
    return fields


def _entropy(text):
    if not text:
        return 0.0
    counts = Counter(text)
    total = float(len(text))
    return -sum((c / total) * math.log2(c / total) for c in counts.values())


def _try_decode_label(label):
    """把 DNS 标签按 hex / base32 / base64url 尝试解码成可读文本。"""
    raw = label.strip(".-_")
    if not raw:
        return ""
    candidates = []
    if HEX_LABEL.match(raw) and len(raw) % 2 == 0:
        try:
            candidates.append(bytes.fromhex(raw))
        except Exception:
            pass
    if B32_LABEL.match(raw):
        try:
            padded = raw.upper() + "=" * ((8 - len(raw) % 8) % 8)
            candidates.append(base64.b32decode(padded))
        except Exception:
            pass
    if ENCODED_LABEL.match(raw):
        try:
            padded = raw.replace("-", "+").replace("_", "/")
            padded += "=" * ((4 - len(padded) % 4) % 4)
            candidates.append(base64.b64decode(padded))
        except Exception:
            pass
    for blob in candidates:
        try:
            text = blob.decode("utf-8")
        except Exception:
            continue
        if text and sum(ch.isprintable() for ch in text) / float(len(text)) > 0.85:
            return text
    return ""


def _carve_stream(data, outdir, index, result, per_stream_limit=20 * 1024 * 1024):
    carved = []
    if not data:
        return carved
    for ext, magic, end_mark, max_size in MAGIC:
        start = 0
        while True:
            start = data.find(magic, start)
            if start < 0 or len(carved) >= 80:
                break
            if ext == "pe":
                if len(data) < start + 0x40:
                    break
                import struct
                e_lfanew = struct.unpack_from("<I", data, start + 0x3c)[0]
                if data[start + e_lfanew:start + e_lfanew + 4] != b"PE\x00\x00":
                    start += 2
                    continue
            end = -1
            if end_mark:
                mark = data.find(end_mark, start + len(magic))
                if mark >= 0:
                    end = mark + len(end_mark)
            if end < 0:
                end = min(len(data), start + max_size)
            if end - start < 128:
                start += len(magic)
                continue
            blob = data[start:end]
            digest = hashlib.sha256(blob).hexdigest()
            if any(item["sha256"] == digest for item in carved):
                start = end
                continue
            name = "carved_%03d_%s.%s" % (index, digest[:10], ext)
            path = os.path.join(outdir, name)
            os.makedirs(outdir, exist_ok=True)
            with open(path, "wb") as fp:
                fp.write(blob)
            item = {"type": ext, "offset": start, "size": len(blob),
                    "sha256": digest, "path": path}
            carved.append(item)
            util.flag_scan(blob if len(blob) < 4 * 1024 * 1024 else blob[:4 * 1024 * 1024],
                           "还原文件 %s" % name, result)
            start = end if end > start else start + len(magic)
    return carved


def _render(result):
    data = result["data"]
    lines = ["# 流量深度分析报告", ""]
    lines.append("- 抓包：`%s`" % data.get("path", ""))
    lines.append("- 数据包：%s，字节：%s" % (
        data.get("packets", 0), util.human_size(data.get("bytes", 0))))
    stats = data.get("protocols") or {}
    lines.append("- 协议：%s" % ", ".join("%s=%s" % (k, v) for k, v in stats.items()))
    lines.append("- TCP 流：%s，HTTP 对象：%s，还原文件：%s，DNS 疑似隧道：%s" % (
        len(data.get("tcp_streams") or []), len(data.get("http_objects") or []),
        len(data.get("carved") or []), len(data.get("dns_tunnels") or [])))
    lines.append("")
    lines.append("## 发现")
    for item in result["findings"]:
        lines.append("- [%s] %s" % (item["level"], item["title"]))
        if item["detail"]:
            for line in item["detail"].splitlines()[:15]:
                lines.append("  - %s" % line)
    if data.get("tcp_streams"):
        lines.append("")
        lines.append("## TCP 流 Top")
        lines.append("| 流 | 包 | 字节 | 缺口 | 重传 | 时长 |")
        lines.append("| --- | --- | --- | --- | --- | --- |")
        for item in data["tcp_streams"][:20]:
            lines.append("| %s | %s | %s | %s | %s | %ss |" % (
                item["flow"], item["packets"], item["bytes"], item["gaps"],
                item.get("retrans", 0), item["duration"]))
    if data.get("http_objects"):
        lines.append("")
        lines.append("## HTTP 对象")
        lines.append("| 状态 | URL | 类型 | 大小 | 文件 |")
        lines.append("| --- | --- | --- | --- | --- |")
        for item in data["http_objects"][:30]:
            lines.append("| %s | %s | %s | %s | %s |" % (
                item.get("status", ""), util.short(item.get("url", ""), 80),
                item.get("content_type", ""), util.human_size(item.get("size", 0)),
                item.get("path", "")))
    if data.get("carved"):
        lines.append("")
        lines.append("## 文件还原")
        for item in data["carved"][:30]:
            lines.append("- %s (%s, %s)" % (
                item["path"], item["type"], util.human_size(item["size"])))
    if data.get("dns_tunnels"):
        lines.append("")
        lines.append("## DNS 隧道特征")
        for item in data["dns_tunnels"]:
            lines.append("- 域名 `%s`：score=%s，查询=%s，唯一=%s，平均长度=%.1f，"
                         "编码标签=%.0f%%，TXT=%sB" % (
                             item["domain"], item["score"], item["queries"],
                             item["unique"], item["avg_len"],
                             item["encoded_ratio"] * 100, item["txt_bytes"]))
    lines.append("")
    lines.append("## 备注")
    for note in result["notes"]:
        lines.append("- %s" % note)
    return "\n".join(lines)


def analyze(path: str, outdir: str = "", log=None, max_stream_mb: int = 20) -> dict:
    log = log or (lambda m: None)
    outdir = outdir or util.case_dir("traffic", path)
    result = util.make_result("traffic", outdir)
    result["data"]["path"] = os.path.abspath(path)
    if PcapReader is None:
        result["ok"] = False
        util.add(result, "warn", "scapy 未安装，无法解析抓包", "pip install scapy")
        return util.finish(result, _render(result))
    if not os.path.isfile(path):
        result["ok"] = False
        util.add(result, "warn", "抓包文件不存在", path)
        return util.finish(result, _render(result))

    proto = Counter()
    endpoints = Counter()
    endpoint_bytes = Counter()
    segments = defaultdict(dict)
    flow_packets = Counter()
    flow_bytes = Counter()
    flow_times = {}
    flow_retrans = Counter()
    flow_conflicts = Counter()
    dns_queries = []
    dns_txt = []
    packets = 0
    total_bytes = 0
    first_ts = None
    last_ts = None
    max_size = max(1, int(max_stream_mb)) * 1024 * 1024

    try:
        reader = _reader(path)
        for pkt in reader:
            packets += 1
            try:
                ts = float(pkt.time)
            except Exception:
                ts = 0.0
            if first_ts is None:
                first_ts = ts
            last_ts = ts
            total_bytes += len(pkt)
            ip, family = _unpack_ip(pkt)
            if ip is None:
                if pkt.haslayer("ARP"):
                    proto["ARP"] += 1
                continue
            proto[family] += 1
            src, dst = ip.src, ip.dst
            endpoints[src] += 1
            endpoints[dst] += 1
            endpoint_bytes[src] += len(pkt)
            if TCP in pkt:
                t = pkt[TCP]
                proto["TCP"] += 1
                flow = (src, int(t.sport), dst, int(t.dport))
                flow_packets[flow] += 1
                flow_bytes[flow] += len(pkt)
                flow_times.setdefault(flow, [ts, ts])[1] = ts
                payload = bytes(t.payload)
                if payload:
                    if t.seq in segments[flow]:
                        flow_retrans[flow] += 1
                        if segments[flow][t.seq] != payload:
                            flow_conflicts[flow] += 1
                    segments[flow][t.seq] = payload
                flags = int(t.flags)
                if flags & 0x02:
                    proto["TCP-SYN"] += 1
                if flags & 0x01:
                    proto["TCP-FIN"] += 1
                if flags & 0x04:
                    proto["TCP-RST"] += 1
                if payload[:3] in (b"GET", b"POS", b"PUT", b"HEA", b"OPT", b"DEL") \
                        or payload.startswith(b"HTTP/"):
                    proto["HTTP"] += 1
                if payload[:2] == b"\x16\x03":
                    proto["TLS"] += 1
            elif UDP in pkt:
                u = pkt[UDP]
                proto["UDP"] += 1
                flow = (src, int(u.sport), dst, int(u.dport))
                flow_times.setdefault(flow, [ts, ts])[1] = ts
                payload = bytes(u.payload)
                if DNS is not None and (u.dport == 53 or u.sport == 53):
                    proto["DNS"] += 1
                    try:
                        dns = pkt[DNS]
                        if dns.qd:
                            name = dns.qd.qname.decode("utf-8", "ignore").rstrip(".")
                            qtype = int(dns.qd.qtype)
                            dns_queries.append({"name": name, "qtype": qtype,
                                                "ts": ts, "src": src, "dst": dst})
                            if dns.qr == 1 and dns.an:
                                an = dns.an
                                guard = 0
                                while an is not None and guard < 100:
                                    guard += 1
                                    if int(getattr(an, "type", 0)) == 16:
                                        rdata = getattr(an, "rdata", b"")
                                        if isinstance(rdata, list):
                                            rdata = b"".join(rdata)
                                        dns_txt.append({"name": name,
                                                        "data": bytes(rdata)})
                                    an = getattr(an, "payload", None)
                                    if an is not None and not hasattr(an, "type"):
                                        break
                    except Exception:
                        if payload:
                            util.flag_scan(payload, "DNS 载荷", result)
                elif u.dport in (67, 68):
                    proto["DHCP"] += 1
                else:
                    proto["UDP-other"] += 1
            elif ICMP in pkt:
                proto["ICMP"] += 1

        reader.close()
    except Exception as exc:
        result["notes"].append("抓包读取中断：%s" % exc)

    result["data"].update({
        "packets": packets, "bytes": total_bytes,
        "protocols": dict(proto.most_common()),
        "duration": round((last_ts - first_ts), 3) if first_ts else 0,
        "top_endpoints": [{"ip": ip, "packets": c, "bytes": endpoint_bytes[ip]}
                          for ip, c in endpoints.most_common(20)],
    })
    if not packets:
        result["ok"] = False
        util.add(result, "warn", "抓包为空或格式不受支持", path)
        return util.finish(result, _render(result))

    util.add(result, "info", "协议分布",
             ", ".join("%s=%s" % (k, v) for k, v in proto.most_common(20)))
    util.add(result, "info", "最活跃端点 Top10",
             "\n".join("%s  包=%s  字节=%s" % (ip, c, util.human_size(endpoint_bytes[ip]))
                       for ip, c in endpoints.most_common(10)))

    # ---- TCP 重组 ----
    streams = []
    stream_index = 0
    carves_dir = os.path.join(outdir, "carved")
    http_msgs = []
    all_streams_for_http = {}
    for flow, segs in segments.items():
        data, meta = _reassemble(segs)
        if not data:
            continue
        times = flow_times.get(flow, [0, 0])
        item = {
            "flow": "%s:%s -> %s:%s" % flow,
            "packets": flow_packets[flow], "bytes": len(data),
            "gaps": meta["gaps"], "missing": meta["missing"],
            "overlap": meta["overlap"], "retrans": flow_retrans[flow],
            "conflicts": flow_conflicts[flow],
            "duration": round(max(0.0, times[1] - times[0]), 3),
        }
        streams.append(item)
        if len(data) <= max_size:
            all_streams_for_http[flow] = data
        looks_http = bool(HTTP_START.match(data[:200])) or b"HTTP/1." in data[:4096]
        if looks_http:
            msgs = _parse_http(data, flow, times[0])
            http_msgs.extend(msgs)
        if len(data) >= 64:
            carved = _carve_stream(data, carves_dir, stream_index, result)
            stream_index += 1
            for c in carved:
                result["data"].setdefault("carved", []).append(c)
                util.add_artifact(result, c["path"])
        if len(data) < max_size and (looks_http or len(data) < 2 * 1024 * 1024):
            name = "streams/stream_%03d_%s_%s.bin" % (
                stream_index, re.sub(r"\W+", "_", flow[0])[:24], flow[1])
            path_out = util.save_bytes(outdir, name, data)
            util.add_artifact(result, path_out)
        util.flag_scan(data, "TCP 流 %s" % item["flow"], result)

    streams.sort(key=lambda x: x["bytes"], reverse=True)
    result["data"]["tcp_streams"] = streams[:100]
    result["data"]["tcp_stream_count"] = len(streams)
    if streams:
        util.add(result, "info", "TCP 流重组 %d 条" % len(streams),
                 "\n".join("%s 包=%s 字节=%s 缺口=%s 重传=%s" % (
                     s["flow"], s["packets"], s["bytes"], s["gaps"], s["retrans"])
                     for s in streams[:15]))
    bad = [s for s in streams if s["gaps"] or s["retrans"]]
    if bad:
        util.add(result, "info", "存在缺口/重传的流 %d 条" % len(bad),
                 "\n".join("%s 缺口=%s 缺失=%sB 重传=%s 冲突=%s" % (
                     s["flow"], s["gaps"], s["missing"], s["retrans"],
                     s["conflicts"]) for s in bad[:15]))

    # ---- HTTP 对象 ----
    http_dir = os.path.join(outdir, "http_objects")
    objects = []
    requests_by_flow = defaultdict(list)
    responses = []
    for msg in http_msgs:
        if msg["is_response"]:
            responses.append(msg)
        else:
            requests_by_flow[msg["flow"]].append(msg)
    seen = set()
    response_index = Counter()
    for msg in responses:
        flow = msg["flow"]
        reqs = requests_by_flow.get((flow[2], flow[3], flow[0], flow[1]), [])
        idx = response_index[flow]
        response_index[flow] += 1
        req = reqs[idx] if idx < len(reqs) else None
        headers = msg["headers"]
        ctype = headers.get("content-type", "").split(";")[0].strip()
        body, enc = _decode_content(msg["body"], headers.get("content-encoding", ""), ctype)
        url = req["path"] if req else ""
        if req and req["method"] == "CONNECT":
            url = req["path"]
        digest = hashlib.sha256(body).hexdigest() if body else ""
        if body and digest not in seen:
            seen.add(digest)
            ext = EXT_CTYPE.get(ctype.lower(), "")
            if not ext:
                for key, val in EXT_CTYPE.items():
                    if key.split("/")[-1] in ctype.lower():
                        ext = val
                        break
            if not ext:
                ext = ".bin"
            base = re.sub(r"[^\w.\-]+", "_", os.path.basename(unquote_plus(
                urlsplit(url).path)) or "object")[:48] or "object"
            path_out = os.path.join(http_dir, "%03d_%s%s" % (len(objects), base, ext))
            os.makedirs(http_dir, exist_ok=True)
            with open(path_out, "wb") as fp:
                fp.write(body)
            item = {"flow": "%s:%s -> %s:%s" % flow, "url": url,
                    "method": req["method"] if req else "",
                    "status": msg["status"], "content_type": ctype,
                    "encoding": enc, "size": len(body), "sha256": digest,
                    "path": path_out}
            objects.append(item)
            util.add_artifact(result, path_out)
            util.flag_scan(body if len(body) < 4 * 1024 * 1024 else body[:4 * 1024 * 1024],
                           "HTTP 对象 %s" % url, result)
        req_auth = _basic_auth(headers)
        if req_auth:
            util.add(result, "warn", "HTTP Basic 凭据", req_auth)
        for cookie in (headers.get("set-cookie", ""), headers.get("cookie", "")):
            if cookie:
                for flag in re.findall(r"flag\{[^}]{1,200}\}", cookie):
                    util.flag_hit(result, flag, "HTTP Cookie")
        if req:
            fields = _form_fields(req["body"], req["headers"].get("content-type", ""))
            for key, value in fields:
                if key.lower() in ("pass", "pwd", "password", "token", "secret", "flag"):
                    util.add(result, "warn", "HTTP 表单敏感字段",
                             "%s = %s" % (key, util.short(value, 160)))
                util.flag_scan(value, "HTTP 表单 %s" % key, result)
            auth = _basic_auth(req["headers"])
            if auth:
                util.add(result, "warn", "HTTP Basic 凭据", auth)
    result["data"]["http_objects"] = objects
    if objects:
        util.add(result, "ok", "HTTP 对象提取 %d 个" % len(objects),
                 "\n".join("%s %s %s %s" % (
                     o["status"], util.short(o["url"], 60), o["content_type"],
                     util.human_size(o["size"])) for o in objects[:30]))
    if http_msgs:
        util.add(result, "info", "HTTP 消息 %d 条（请求 %d / 响应 %d）" % (
            len(http_msgs), len(http_msgs) - len(responses), len(responses)))

    # ---- DNS 隧道特征 ----
    domains = defaultdict(list)
    for q in dns_queries:
        labels = [x for x in q["name"].split(".") if x]
        if len(labels) >= 2:
            base = ".".join(labels[-2:]).lower()
            domains[base].append((q, labels))
    tunnels = []
    decoded_dir = os.path.join(outdir, "dns_decoded")
    for domain, items in domains.items():
        names = [q["name"] for q, _ in items]
        unique = len(set(names))
        avg_len = sum(len(n) for n in names) / float(len(names) or 1)
        encoded = 0
        longest_label = 0
        entropies = []
        decoded_parts = []
        for q, labels in items:
            body_labels = labels[:-2] if len(labels) > 2 else labels
            longest_label = max([longest_label] + [len(x) for x in body_labels])
            if any(ENCODED_LABEL.match(x) and _entropy(x) >= 3.0 for x in body_labels):
                encoded += 1
            entropies.extend(_entropy(x) for x in body_labels if x)
            for label in body_labels:
                text = _try_decode_label(label)
                if text:
                    decoded_parts.append(text)
        enc_ratio = encoded / float(len(items) or 1)
        avg_entropy = sum(entropies) / float(len(entropies) or 1)
        txt_items = [t for t in dns_txt if t["name"].lower().endswith("." + domain)
                     or t["name"].lower() == domain]
        txt_bytes = sum(len(t["data"]) for t in txt_items)
        qtypes = sorted(set(q["qtype"] for q, _ in items))
        score = 0
        if unique >= 10:
            score += 2
        if unique >= 40:
            score += 1
        if avg_len >= 35:
            score += 2
        if encoded >= 5 and enc_ratio >= 0.5:
            score += 2
        if avg_entropy >= 3.5:
            score += 1
        if txt_bytes >= 512:
            score += 2
        if longest_label >= 40:
            score += 1
        if 16 in qtypes or 10 in qtypes or 255 in qtypes:
            score += 1
        if score < 4 and unique < 15:
            continue
        entry = {"domain": domain, "score": score, "queries": len(items),
                 "unique": unique, "avg_len": round(avg_len, 1),
                 "encoded_ratio": round(enc_ratio, 3),
                 "avg_entropy": round(avg_entropy, 2),
                 "longest_label": longest_label, "txt_bytes": txt_bytes,
                 "qtypes": qtypes, "decoded_chars": sum(len(x) for x in decoded_parts)}
        tunnels.append(entry)
        if score >= 4:
            util.add(result, "warn", "DNS 疑似隧道：%s" % domain,
                     "score=%s 查询=%s 唯一=%s 平均长度=%.1f 编码标签=%.0f%% "
                     "TXT=%sB 类型=%s" % (
                         score, len(items), unique, avg_len, enc_ratio * 100,
                         txt_bytes, qtypes), entry)
        if decoded_parts:
            decoded = "".join(decoded_parts)
            path_out = util.save_text(decoded_dir, "decoded_%s.txt" % domain,
                                      decoded[:4 * 1024 * 1024])
            util.add_artifact(result, path_out)
            entry["decoded_path"] = path_out
            util.flag_scan(decoded, "DNS 解码 %s" % domain, result)
            util.add(result, "ok", "DNS 标签解码：%s" % domain,
                     "解出 %d 字符，样本：%s" % (
                         len(decoded), util.short(decoded, 200)))
        low_names = " ".join(names).lower()
        for tool in ("dnscat", "iodine", "dns2tcp"):
            if tool in low_names:
                util.add(result, "warn", "DNS 隧道工具特征：%s" % tool,
                         "域名样本：%s" % util.short(names[0], 120))
    tunnels.sort(key=lambda x: x["score"], reverse=True)
    result["data"]["dns_tunnels"] = tunnels
    result["data"]["dns_queries"] = len(dns_queries)
    result["data"]["dns_txt_records"] = len(dns_txt)
    if dns_queries:
        util.add(result, "info", "DNS 查询 %d 条 / TXT 应答 %d 条" % (
            len(dns_queries), len(dns_txt)),
            "\n".join(sorted({q["name"] for q in dns_queries})[:60]))
    txt_blob = b"".join(t["data"] for t in dns_txt)
    if txt_blob:
        util.flag_scan(txt_blob, "DNS TXT 拼接", result)
        path_out = util.save_text(outdir, "dns_txt.bin",
                                  txt_blob.decode("latin-1", "replace"))
        with open(path_out, "wb") as fp:
            fp.write(txt_blob)
        util.add_artifact(result, path_out)

    result["data"]["http_objects_count"] = len(objects)
    result["data"]["carved_count"] = len(result["data"].get("carved") or [])
    result["summary"] = "包 %s，TCP 流 %s，HTTP 对象 %s，还原文件 %s，DNS 疑似隧道 %s" % (
        packets, len(streams), len(objects), result["data"]["carved_count"],
        len(tunnels))
    for flag in result["data"].get("flags") or []:
        pass
    return util.finish(result, _render(result))


def enhance(path, report, outdir):
    """把深度分析结果合并进常规流量报告（dispatcher 调用）。"""
    if PcapReader is None:
        return None
    try:
        result = analyze(path, os.path.join(outdir, "traffic_deep"),
                         log=lambda m: report.add("info", "流量深度", m))
    except Exception as exc:
        report.add("info", "流量深度分析跳过", str(exc)[:200])
        return None
    level_map = {"flag": "flag", "warn": "warn", "ok": "ok", "info": "info"}
    for item in result.get("findings") or []:
        report.add(level_map.get(item["level"], "info"), item["title"], item["detail"])
    for path_out in result.get("artifacts") or []:
        report.extracted.append(path_out)
    return result
