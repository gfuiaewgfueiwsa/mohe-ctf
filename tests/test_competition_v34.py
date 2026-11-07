# -*- coding: utf-8 -*-
"""v3.5.0 赛事专项测试：内存/流量/移动/代码审计/基线/日志/攻防验证。

所有测试只使用自建数据、现有 APK fixture 或本机只读信息；
不访问公网、不发送攻击请求、不执行生成的加固脚本。
"""
import base64
import gzip
import json
import os
import shutil
import struct
import subprocess
import sys
import tempfile
import time
import unittest
import zlib

from ctfbox.competition import (baseline, codeaudit, defense, logtime,
                                memory, mobile, traffic, util)


def _write(path, text, mode="w"):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    if mode == "wb":
        with open(path, "wb") as fp:
            fp.write(text)
    else:
        with open(path, "w", encoding="utf-8") as fp:
            fp.write(text)


def _png_bytes():
    def chunk(tag, data):
        return (struct.pack(">I", len(data)) + tag + data +
                struct.pack(">I", zlib.crc32(tag + data) & 0xffffffff))
    header = chunk(b"IHDR", struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0))
    text = chunk(b"tEXt", b"Comment\x00" + b"mohe-v34-" + b"A" * 180)
    body = chunk(b"IDAT", zlib.compress(b"\x00\xff\x00\x00"))
    return (b"\x89PNG\r\n\x1a\n" + header + text + body +
            chunk(b"IEND", b""))


class V34Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="mohe_v34_")

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def out(self, name):
        path = os.path.join(self.tmp, "out_" + name)
        os.makedirs(path, exist_ok=True)
        return path

    def titles(self, result):
        return [f["title"] for f in result.get("findings") or []]


class TestLogTime(V34Base):
    def _linux_log(self):
        lines = [
            "Nov  7 10:00:01 web01 sshd[100]: Failed password for root from 203.0.113.5 port 5001 ssh2",
            "Nov  7 10:00:20 web01 sshd[101]: Failed password for root from 203.0.113.5 port 5002 ssh2",
            "Nov  7 10:00:40 web01 sshd[102]: Failed password for root from 203.0.113.5 port 5003 ssh2",
            "Nov  7 10:01:00 web01 sshd[103]: Failed password for root from 203.0.113.5 port 5004 ssh2",
            "Nov  7 10:01:20 web01 sshd[104]: Failed password for root from 203.0.113.5 port 5005 ssh2",
            "Nov  7 10:01:40 web01 sshd[105]: Failed password for root from 203.0.113.5 port 5006 ssh2",
            "Nov  7 10:03:00 web01 sshd[110]: Accepted password for root from 203.0.113.5 port 5007 ssh2",
            "Nov  7 10:04:00 web01 sudo: alice : TTY=pts/1 ; PWD=/home/alice ; USER=root ; COMMAND=/bin/bash -i",
            "Nov  7 10:05:00 web01 useradd[500]: new user: name=evil, UID=0, GID=0, home=/root",
            "Nov  7 10:06:00 web01 kernel: [UFW BLOCK] IN=eth0 OUT= SRC=198.51.100.9 DST=10.0.0.2 DPT=22",
        ]
        path = os.path.join(self.tmp, "auth.log")
        _write(path, "\n".join(lines) + "\n")
        now = time.time()
        os.utime(path, (now, now))
        return path

    def test_linux_auth_log_findings_and_timeline(self):
        path = self._linux_log()
        result = logtime.analyze(path, self.out("logtime"), platform="linux")
        titles = self.titles(result)
        self.assertTrue(result["ok"])
        self.assertEqual(result["data"]["platform"], "linux")
        self.assertIn("疑似 SSH 暴力破解（10 分钟 >=5 次）", titles)
        self.assertIn("SSH 失败后登录成功（疑似爆破成功）", titles)
        self.assertIn("可疑 sudo 命令 1 条", titles)
        self.assertIn("用户/组变更 1 条", titles)
        self.assertIn("防火墙拦截 1 条", titles)
        self.assertGreaterEqual(result["data"]["events"], 9)
        timeline = result["data"]["timeline_path"]
        self.assertTrue(os.path.isfile(timeline))
        with open(timeline, "r", encoding="utf-8-sig") as fp:
            head = fp.readline().strip()
        self.assertIn("time", head)
        self.assertIn("action", head)
        self.assertTrue(os.path.isfile(os.path.join(
            result["outdir"], "artifacts", "report.md")))

    def test_windows_event_xml_parser_and_analysis(self):
        def xml(eid, stamp, data):
            fields = "".join("<Data Name=\"%s\">%s</Data>" % (k, v)
                             for k, v in data.items())
            return (
                '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">'
                "<System><Provider Name=\"Microsoft-Windows-Security-Auditing\"/>"
                "<EventID>%s</EventID><Level>0</Level>"
                "<TimeCreated SystemTime=\"%s\"/>"
                "<Computer>dc01.ctf.local</Computer><Channel>Security</Channel>"
                "</System><EventData>%s</EventData></Event>" % (eid, stamp, fields))

        parsed = logtime._xml_event(xml("4625", "2026-11-07T10:00:00.0000000Z", {
            "TargetUserName": "admin", "IpAddress": "198.51.100.7",
            "LogonType": "3", "Status": "0xc000006d"}))
        self.assertEqual(parsed["event_id"], "4625")
        self.assertEqual(parsed["data"]["TargetUserName"], "admin")
        simple = logtime._simplify_windows(parsed, "Security.evtx")
        self.assertEqual(simple["action"], "登录失败")
        self.assertEqual(simple["user"], "admin")
        self.assertEqual(simple["ip"], "198.51.100.7")
        self.assertIn("LogonType=3", simple["detail"])

        events = []
        for i in range(6):
            event = logtime._simplify_windows(logtime._xml_event(xml(
                "4625", "2026-11-07T10:0%d:00.0000000Z" % i, {
                    "TargetUserName": "admin", "IpAddress": "198.51.100.7",
                    "LogonType": "3"})), "Security.evtx")
            events.append(event)
        ok = logtime._simplify_windows(logtime._xml_event(xml(
            "4624", "2026-11-07T10:05:00.0000000Z", {
                "TargetUserName": "admin", "IpAddress": "198.51.100.7",
                "LogonType": "3"})), "Security.evtx")
        events.append(ok)
        for eid, stamp, data in (
                ("1102", "2026-11-07T10:06:00.0000000Z", {"SubjectUserName": "admin"}),
                ("7045", "2026-11-07T10:07:00.0000000Z", {
                    "ServiceName": "evil", "ImagePath": "C:\\evil.exe"}),
                ("4688", "2026-11-07T10:08:00.0000000Z", {
                    "NewProcessName": "C:\\Windows\\System32\\cmd.exe",
                    "CommandLine": "powershell -enc SQBFAFgA"})):
            events.append(logtime._simplify_windows(
                logtime._xml_event(xml(eid, stamp, data)), "Security.evtx"))
        result = util.make_result("logtime", self.out("evtx"))
        logtime._analyze_events_windows(events, result)
        titles = self.titles(result)
        self.assertIn("疑似暴力破解（10 分钟内 >=5 次失败）", titles)
        self.assertIn("失败后登录成功（疑似爆破成功）", titles)
        self.assertIn("日志被清空（反取证）", titles)
        self.assertIn("服务/计划任务安装", titles)
        self.assertIn("可疑进程命令行 1 条", titles)

    def test_evtx_magic_detection(self):
        path = os.path.join(self.tmp, "fake.evtx")
        _write(path, b"ElfFile\x00" + b"\x00" * 64, mode="wb")
        self.assertTrue(logtime._is_evtx(path))


class TestMemory(V34Base):
    def _image(self):
        path = os.path.join(self.tmp, "mem.raw")
        blob = (b"MEMORY-IMAGE-V34 " + b"flag{memory_strings_v34}" +
                b" http://evil.example/mem " + b"\x00" + b"B" * 4096)
        _write(path, blob, mode="wb")
        return path

    def test_quick_strings_and_missing_image(self):
        image = self._image()
        result = util.make_result("memory", self.out("strings"))
        memory.quick_strings(image, result, max_scan_mb=1)
        self.assertIn("flag{memory_strings_v34}", result["data"]["flags"])
        self.assertTrue(any("evil.example" in u for u in result["data"]["strings"]["urls"]))
        missing = memory.analyze(os.path.join(self.tmp, "missing.raw"),
                                 self.out("missing"))
        self.assertFalse(missing["ok"])
        self.assertIn("内存镜像不存在", self.titles(missing))

    def test_volatility_plugin_parsing_with_mock(self):
        image = self._image()
        rows = {
            "windows.pslist": [
                {"PID": 4, "PPID": 0, "ImageFileName": "System"},
                {"PID": 1234, "PPID": 999, "ImageFileName": "mimikatz.exe"},
            ],
            "windows.pstree": [],
            "windows.cmdline": [{
                "PID": 1234, "Process": "powershell.exe",
                "Args": "powershell -enc SQBFAFgA flag{vol_mock_flag}"}],
            "windows.netscan": [{
                "Proto": "TCPv4", "LocalAddr": "10.0.0.5", "LocalPort": 4444,
                "ForeignAddr": "203.0.113.9", "ForeignPort": 443,
                "State": "ESTABLISHED", "Owner": "evil.exe", "PID": 1234}],
            "windows.hashdump": [{
                "Username": "Administrator", "RID": 500,
                "LMHash": "aad3b435b51404eeaad3b435b51404ee",
                "NTHash": "31d6cfe0d16ae931b73c59d7e0c089c0"}],
        }
        fake_info = {"available": True, "path": "", "kind": "module-bootstrap",
                     "python": "python", "version": "test"}
        old_find, old_run = util.find_volatility, util.run_cmd

        def fake_run(cmd, timeout=120, cwd="", input_data=None, env=None, check=False):
            joined = " ".join(str(x) for x in cmd)
            if "banners" in joined:
                return {"rc": 0, "stdout": "Windows 10 22H2 (build 19045)",
                        "stderr": "", "elapsed": 0.01, "timeout": False}
            out = ""
            for plugin in ("windows.pslist", "windows.pstree", "windows.cmdline",
                           "windows.netscan", "windows.hashdump", "windows.cachedump",
                           "windows.lsadump", "windows.malfind"):
                if plugin in joined:
                    out = "\n".join(json.dumps(row) for row in rows.get(plugin, []))
                    break
            if "windows.registry.printkey" in joined:
                out = json.dumps({"Name": "Updater",
                                  "Data": "C:\\Users\\Public\\evil.exe"})
            return {"rc": 0, "stdout": out, "stderr": "",
                    "elapsed": 0.01, "timeout": False}

        util.find_volatility = lambda: fake_info
        util.run_cmd = fake_run
        try:
            result = memory.analyze(image, self.out("mock"), max_scan_mb=1)
        finally:
            util.find_volatility, util.run_cmd = old_find, old_run
        titles = self.titles(result)
        self.assertTrue(result["ok"], result.get("notes"))
        self.assertEqual(result["data"]["os"], "windows")
        self.assertEqual(len(result["data"]["plugins"]), 13)
        self.assertEqual(result["data"]["process_count"], 2)
        self.assertIn("可疑进程 1 个", titles)
        self.assertIn("可疑命令行 1 条", titles)
        self.assertIn("外联连接 1 条", titles)
        self.assertTrue(any("凭据导出" in t for t in titles))
        self.assertIn("flag{vol_mock_flag}", result["data"]["flags"])
        self.assertIn("flag{memory_strings_v34}", result["data"]["flags"])


class TestTraffic(V34Base):
    @staticmethod
    def _tcp(src, sport, dst, dport, seq, payload, ts):
        from scapy.all import Ether, IP, TCP, Raw
        pkt = (Ether() / IP(src=src, dst=dst) /
               TCP(sport=sport, dport=dport, seq=seq, flags="PA") / Raw(payload))
        pkt.time = ts
        return pkt

    @staticmethod
    def _dns_query(name, txid, sport, ts):
        from scapy.all import DNS, DNSQR, Ether, IP, UDP
        pkt = (Ether() / IP(src="10.0.0.4", dst="10.0.0.53") /
               UDP(sport=sport, dport=53) /
               DNS(id=txid, rd=1, qd=DNSQR(qname=name, qtype="TXT")))
        pkt.time = ts
        return pkt

    def _pcap(self):
        from scapy.all import wrpcap
        png = _png_bytes()
        packets = []
        t = 1000.0

        req = b"GET /secret.png HTTP/1.1\r\nHost: ctf.local\r\n\r\n"
        first, second = req[:12], req[12:]
        packets.append(self._tcp("10.0.0.1", 40000, "10.0.0.2", 80,
                                 5000 + len(first), second, t + 0.02))
        packets.append(self._tcp("10.0.0.1", 40000, "10.0.0.2", 80,
                                 5000, first, t + 0.01))

        gz = gzip.compress(png)
        head = (b"HTTP/1.1 200 OK\r\nContent-Type: image/png\r\n"
                b"Content-Encoding: gzip\r\nContent-Length: " +
                str(len(gz)).encode() + b"\r\n\r\n")
        response = head + gz
        cut = 40
        packets.append(self._tcp("10.0.0.2", 80, "10.0.0.1", 40000,
                                 9000 + cut, response[cut:], t + 0.12))
        packets.append(self._tcp("10.0.0.2", 80, "10.0.0.1", 40000,
                                 9000, response[:cut], t + 0.11))

        form = b"user=admin&password=flag{http_form_v34}"
        req2 = (b"POST /login HTTP/1.1\r\nHost: ctf.local\r\n"
                b"Content-Type: application/x-www-form-urlencoded\r\n"
                b"Authorization: Basic " + base64.b64encode(b"admin:secret") +
                b"\r\nContent-Length: " + str(len(form)).encode() + b"\r\n\r\n" + form)
        packets.append(self._tcp("10.0.0.1", 40001, "10.0.0.2", 80,
                                 6000, req2, t + 0.2))
        chunk_body = b"flag{chunked_body_v34}"
        chunked = (("%x" % len(chunk_body)).encode() + b"\r\n" + chunk_body +
                   b"\r\n0\r\n\r\n")
        resp2 = (b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n"
                 b"Set-Cookie: session=flag{cookie_v34}; Path=/\r\n"
                 b"Transfer-Encoding: chunked\r\n\r\n" + chunked)
        packets.append(self._tcp("10.0.0.2", 80, "10.0.0.1", 40001,
                                 7000, resp2, t + 0.21))

        packets.append(self._tcp("10.0.0.3", 50000, "10.0.0.9", 8080,
                                 8000, png, t + 0.3))

        for i in range(12):
            text = "flag{dns_label_%02d}" % i
            label = base64.b32encode(text.encode()).decode().rstrip("=")
            packets.append(self._dns_query(
                label + ".evil.example", 100 + i, 41000 + i, t + 0.4 + i * 0.01))
        txt_name = "answer.evil.example"
        packets.append(self._dns_query(txt_name, 200, 42000, t + 0.6))
        from scapy.all import DNS, DNSQR, DNSRR, Ether, IP, UDP
        dns_resp = (Ether() / IP(src="10.0.0.53", dst="10.0.0.4") /
                    UDP(sport=53, dport=42000) /
                    DNS(id=200, qr=1, aa=1, rd=1,
                        qd=DNSQR(qname=txt_name, qtype="TXT"),
                        an=DNSRR(rrname=txt_name, type="TXT", ttl=60,
                                 rdata=b"flag{dns_txt_v34}")))
        dns_resp.time = t + 0.61
        packets.append(dns_resp)

        path = os.path.join(self.tmp, "sample.pcap")
        wrpcap(path, packets)
        return path, png

    def test_pcap_http_dns_carve_and_reassembly(self):
        pcap, png = self._pcap()
        result = traffic.analyze(pcap, self.out("traffic"))
        data = result["data"]
        self.assertTrue(result["ok"])
        self.assertGreaterEqual(data["packets"], 20)
        self.assertIn("TCP", data["protocols"])
        self.assertIn("DNS", data["protocols"])
        self.assertGreaterEqual(data["tcp_stream_count"], 4)
        streams = data["tcp_streams"]
        self.assertTrue(all(s["gaps"] == 0 for s in streams), streams)

        objects = data["http_objects"]
        png_obj = next((o for o in objects if o["url"] == "/secret.png"), None)
        self.assertIsNotNone(png_obj)
        self.assertEqual(png_obj["encoding"], "gzip")
        self.assertEqual(png_obj["size"], len(png))
        with open(png_obj["path"], "rb") as fp:
            self.assertEqual(fp.read(), png)

        carved = data.get("carved") or []
        self.assertTrue(any(c["type"] == "png" for c in carved))
        flags = data.get("flags") or []
        self.assertIn("flag{http_form_v34}", flags)
        self.assertIn("flag{chunked_body_v34}", flags)
        self.assertIn("flag{cookie_v34}", flags)
        self.assertIn("flag{dns_txt_v34}", flags)
        self.assertTrue(any(f.startswith("flag{dns_label_") for f in flags))
        tunnels = data.get("dns_tunnels") or []
        tunnel = next((t for t in tunnels if t["domain"] == "evil.example"), None)
        self.assertIsNotNone(tunnel)
        self.assertGreaterEqual(tunnel["score"], 4)
        self.assertTrue(any("HTTP Basic 凭据" in t for t in self.titles(result)))

    def test_reassemble_and_dechunk_units(self):
        data, meta = traffic._reassemble({100: b"world", 95: b"hello"})
        self.assertEqual(data, b"helloworld")
        self.assertEqual(meta["gaps"], 0)
        data, meta = traffic._reassemble({100: b"world", 110: b"!"})
        self.assertEqual(data, b"world!")
        self.assertEqual(meta["gaps"], 1)
        self.assertEqual(meta["missing"], 5)
        decoded, _ = traffic._dechunk(b"4\r\nwiki\r\n5\r\npedia\r\n0\r\n\r\n")
        self.assertEqual(decoded, b"wikipedia")


class TestCodeAudit(V34Base):
    def _sources(self):
        root = os.path.join(self.tmp, "src")
        _write(os.path.join(root, "vuln.php"), """<?php
$id = $_GET['id'];
$sql = "SELECT * FROM users WHERE id=$id";
$res = mysqli_query($conn, $sql);
eval($_POST['cmd']);
?>
""")
        _write(os.path.join(root, "Vuln.java"), """public class Vuln {
  void run(HttpServletRequest request) throws Exception {
    String cmd = request.getParameter("cmd");
    Runtime.getRuntime().exec(cmd);
    java.io.ObjectInputStream ois =
        new java.io.ObjectInputStream(request.getInputStream());
    ois.readObject();
  }
}
""")
        _write(os.path.join(root, "vuln.py"), """import os
import pickle
name = request.args.get("name")
os.system("ping " + name)
pickle.loads(request.data)
""")
        return root

    def test_php_java_python_taint_and_evidence(self):
        result = codeaudit.analyze(self._sources(), self.out("audit"))
        self.assertTrue(result["ok"])
        self.assertEqual(result["data"]["files"], 3)
        self.assertEqual(result["data"]["php_files"], 1)
        self.assertEqual(result["data"]["java_files"], 1)
        self.assertEqual(result["data"]["python_files"], 1)
        rules = result["data"]["by_rule"]
        for rule in ("php-eval", "php-sql", "sql-concat", "java-cmd",
                     "java-deser", "py-shell", "py-pickle"):
            self.assertIn(rule, rules, rules)
        warn = [f for f in result["findings"] if f["level"] == "warn"]
        self.assertTrue(warn)
        php_sql = next(f for f in warn if f["data"].get("rule") == "php-sql")
        self.assertTrue(php_sql["data"]["tainted"])
        self.assertIn("vuln.php:", php_sql["detail"])
        self.assertIn("污点链", php_sql["detail"])
        self.assertTrue(os.path.isfile(os.path.join(
            result["outdir"], "artifacts", "report.md")))

    def test_unsupported_target(self):
        bad = os.path.join(self.tmp, "note.txt")
        _write(bad, "nothing")
        result = codeaudit.analyze(bad, self.out("audit_bad"))
        self.assertFalse(result["ok"])
        self.assertIn("不支持的文件类型", self.titles(result))


class TestMobile(V34Base):
    def test_real_apk_fixture(self):
        apk = os.path.abspath(os.path.join(
            os.path.dirname(__file__), "fixtures", "Test-debug.apk"))
        self.assertTrue(os.path.isfile(apk), apk)
        result = mobile.analyze(apk, self.out("mobile"), decompile="off")
        self.assertTrue(result["ok"])
        manifest = result["data"]["manifest"]
        self.assertEqual(manifest["package"], "org.t0t0.androguard.test")
        self.assertEqual(manifest["version_name"], "1.0")
        exported = [c for c in manifest["components"] if c.get("exported")]
        self.assertTrue(exported)
        self.assertEqual(exported[0]["name"], ".TestActivity")
        self.assertGreater(result["data"]["dex_strings"], 0)
        certs = result["data"]["certs"]
        self.assertTrue(certs)
        self.assertIn("Android Debug", certs[0]["subject"])
        self.assertTrue(certs[0]["debug_cert"])
        self.assertIn("APK 使用 Android Debug 证书签名", self.titles(result))
        self.assertTrue(os.path.isfile(os.path.join(
            result["outdir"], "artifacts", "AndroidManifest.xml")))


class TestBaseline(V34Base):
    def _rootfs(self):
        root = os.path.join(self.tmp, "rootfs")
        _write(os.path.join(root, "etc", "passwd"),
               "root:x:0:0:root:/root:/bin/bash\n"
               "backdoor:x:0:0::/root:/bin/bash\n")
        _write(os.path.join(root, "etc", "shadow"),
               "root:$6$abcdefgh$abcdefghijklmnopqrstuv:19000:0:99999:7:::\n"
               "backdoor::19000:0:99999:7:::\n")
        _write(os.path.join(root, "etc", "group"), "root:x:0:\n")
        _write(os.path.join(root, "etc", "login.defs"),
               "PASS_MAX_DAYS 999\nPASS_MIN_LEN 8\nPASS_MIN_DAYS 0\n")
        _write(os.path.join(root, "etc", "ssh", "sshd_config"),
               "PermitRootLogin yes\nPasswordAuthentication yes\n"
               "X11Forwarding yes\nMaxAuthTries 10\n")
        _write(os.path.join(root, "etc", "sudoers"),
               "root ALL=(ALL) NOPASSWD: ALL\n")
        _write(os.path.join(root, "etc", "sysctl.conf"),
               "net.ipv4.ip_forward = 1\n")
        _write(os.path.join(root, "etc", "systemd", "system",
                            "multi-user.target.wants", "telnetd.service"),
               "[Unit]\nDescription=telnet\n")
        _write(os.path.join(root, "etc", "selinux", "config"),
               "SELINUX=disabled\n")
        return root

    def test_linux_offline_checks_and_generated_scripts(self):
        result = baseline.analyze(self._rootfs(), self.out("baseline"),
                                  platform="linux", generate_scripts=True)
        self.assertTrue(result["ok"])
        checks = {c["id"]: c for c in result["data"]["checks"]}
        self.assertEqual(checks["linux-empty-pw"]["status"], "fail")
        self.assertEqual(checks["linux-ssh-root"]["status"], "warn")
        self.assertEqual(checks["linux-sudo-nopass"]["status"], "warn")
        self.assertEqual(checks["linux-risky-svc"]["status"], "warn")
        self.assertEqual(checks["linux-firewall"]["status"], "warn")
        self.assertEqual(checks["linux-offline"]["status"], "unverified")
        scripts = result["data"]["scripts"]
        self.assertEqual(len(scripts), 4)
        for path in scripts.values():
            self.assertTrue(os.path.isfile(path), path)
        self.assertTrue(os.path.isfile(os.path.join(
            result["outdir"], "artifacts", "README_scripts.txt")))
        self.assertTrue(all(c.get("ok") is not False for c in
                            result["data"]["script_checks"].values()))

    def test_compare_baseline_results(self):
        before = baseline.analyze(self._rootfs(), self.out("before"),
                                  platform="linux", generate_scripts=False)
        with open(os.path.join(before["outdir"], "artifacts", "result.json"),
                  "r", encoding="utf-8") as fp:
            data = json.load(fp)
        for check in data["data"]["checks"]:
            if check["status"] in ("fail", "warn"):
                check["status"] = "pass"
        data["summary"] = "加固后测试数据"
        after_path = os.path.join(self.tmp, "after.json")
        with open(after_path, "w", encoding="utf-8") as fp:
            json.dump(data, fp, ensure_ascii=False)
        before_path = os.path.join(before["outdir"], "artifacts", "result.json")
        result = defense.compare(before_path, after_path, self.out("compare"))
        self.assertTrue(result["ok"])
        self.assertGreater(result["data"]["improved"], 0)
        self.assertEqual(result["data"]["regressed"], 0)
        self.assertTrue(os.path.isfile(result["data"]["report"]))
        with open(result["data"]["report"], "r", encoding="utf-8") as fp:
            report = fp.read()
        self.assertIn("加固前后对比报告", report)
        self.assertIn("改善", report)


class TestDefense(V34Base):
    def test_checklist_and_probes_generated_not_sent(self):
        result = defense.analyze("https://staging.example.invalid",
                                 self.out("defense"), profile="both",
                                 vendor="unit-test")
        self.assertTrue(result["ok"])
        data = result["data"]
        self.assertEqual(data["waf_checks"], len(defense.WAF_CHECKS))
        self.assertEqual(data["ngfw_checks"], len(defense.NGFW_CHECKS))
        self.assertEqual(data["http_cases"], len(defense.PROBES))
        self.assertEqual(data["ngfw_cases"], len(defense.NGFW_PROBES))
        for key in ("checklist", "test_cases", "http_template",
                    "report_template", "readme"):
            self.assertTrue(os.path.isfile(data[key]), key)
        with open(data["test_cases"], "r", encoding="utf-8") as fp:
            cases = json.load(fp)
        self.assertIn("不会发送", cases["warning"])
        self.assertTrue(cases["http_probes"])
        for probe in cases["http_probes"]:
            self.assertNotIn("{{canary}}", probe["path"])
        with open(data["http_template"], "r", encoding="utf-8") as fp:
            http_text = fp.read()
        self.assertIn("YOUR-AUTHORIZED-STAGING-HOST", http_text)
        self.assertIn("仅生成，未发送", http_text)
        notes = "\n".join(result["notes"])
        self.assertIn("不联网", notes)
        self.assertIn("不含绕过", notes)
        with open(data["report_template"], "r", encoding="utf-8") as fp:
            template = fp.read()
        self.assertIn("加固前证据", template)
        self.assertIn("回滚验证", template)
        self.assertIn("签署", template)
        self.assertIn("仅生成", result["summary"])

    def test_waf_only_profile(self):
        result = defense.analyze("", self.out("defense_waf"), profile="waf")
        self.assertTrue(result["ok"])
        self.assertEqual(result["data"]["ngfw_checks"], 0)
        self.assertEqual(result["data"]["http_cases"], len(defense.PROBES))


class TestCli(V34Base):
    def test_cli_defense_and_compare(self):
        from ctfbox.competition import cli
        code = cli.main(["defense", "--profile", "waf",
                         "--out", self.out("cli_defense")])
        self.assertEqual(code, 0)
        before = baseline.analyze(self._rootfs(), self.out("cli_before"),
                                  platform="linux", generate_scripts=False)
        with open(os.path.join(before["outdir"], "artifacts", "result.json"),
                  "r", encoding="utf-8") as fp:
            data = json.load(fp)
        for check in data["data"]["checks"]:
            if check["status"] in ("fail", "warn"):
                check["status"] = "pass"
        after_path = os.path.join(self.tmp, "cli_after.json")
        with open(after_path, "w", encoding="utf-8") as fp:
            json.dump(data, fp, ensure_ascii=False)
        before_path = os.path.join(before["outdir"], "artifacts", "result.json")
        code = cli.main(["compare", "--before", before_path,
                         "--after", after_path, "--out", self.out("cli_compare")])
        self.assertEqual(code, 0)

    def _rootfs(self):
        return TestBaseline._rootfs(self)


class TestIntegration(V34Base):
    def test_dispatcher_codeaudit_hook(self):
        from ctfbox.dispatcher import Dispatcher
        path = os.path.join(self.tmp, "vuln.php")
        _write(path, "<?php\n"
                     "$id = $_GET['id'];\n"
                     "$sql = \"SELECT * FROM users WHERE id=$id\";\n"
                     "mysqli_query($conn, $sql);\n"
                     "eval($_POST['x']);\n")
        rep = Dispatcher(log_cb=lambda m: None).run(path)
        titles = "\n".join(f.title for f in rep.findings)
        self.assertIn("可控输入进入危险汇聚点", titles)
        self.assertIn("vuln.php", titles + self._detail(rep))

    def _detail(self, rep):
        return "\n".join(f.detail for f in rep.findings)

    def test_dispatcher_apk_hook(self):
        from ctfbox.dispatcher import Dispatcher
        apk = os.path.join(os.path.dirname(__file__), "fixtures", "Test-debug.apk")
        rep = Dispatcher(log_cb=lambda m: None).run(apk)
        titles = "\n".join(f.title for f in rep.findings)
        self.assertIn("Android Debug 证书签名", titles)
        self.assertIn("DEX 字符串", titles)

    def test_main_comp_routing(self):
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        env = dict(os.environ, PYTHONIOENCODING="utf-8")
        proc = subprocess.run(
            [sys.executable, os.path.join(root, "main.py"), "--comp", "defense",
             "--profile", "waf", "--out", self.out("main_comp"), "--ctf-only",
             "--accept-responsibility"],
            capture_output=True, env=env, cwd=root, timeout=120)
        self.assertEqual(proc.returncode, 0, proc.stderr.decode("utf-8", "replace"))
        data = json.loads(proc.stdout.decode("utf-8", "replace"))
        self.assertEqual(data["kind"], "defense")
        self.assertTrue(data["ok"])
        self.assertTrue(os.path.isfile(os.path.join(
            self.out("main_comp"), "artifacts", "report.md")))


if __name__ == "__main__":
    unittest.main()
