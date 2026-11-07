# -*- coding: utf-8 -*-
"""v3.6.0 首层判型与白名单脚本自动调用测试（离线、不联网、不执行样本）。"""
import os
import shutil
import tempfile
import unittest
import zipfile

from ctfbox.autopilot import scriptlib, triage
from ctfbox.autopilot.tools import scriptrun


def _info(category, ftype="", ext="", size=0, entropy=4.0, is_text=False):
    return {"category": category, "ftype": ftype, "ext": ext,
            "size": size, "entropy": entropy, "is_text": is_text}


class TriageBase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="mohe_triage_")

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def write(self, name, data):
        path = os.path.join(self.tmp, name)
        with open(path, "wb") as fp:
            fp.write(data)
        return path


class TestTextTriage(TriageBase):
    def test_php_source(self):
        raw = b"<?php system($_GET['cmd']); ?>"
        path = self.write("index.php", raw)
        t = triage.file_triage(path, _info("text", "PHP", ".php", is_text=True),
                               raw, hints=["命令执行"], meta={"name": "rce"})
        self.assertEqual(t.subtype, "web_source")
        self.assertIn("deep_text", t.stages)
        self.assertNotIn("codes", t.stages)

    def test_hash(self):
        raw = b"5d41402abc4b2a76b9719d911017c592"
        path = self.write("hash.txt", raw)
        t = triage.file_triage(path, _info("text", "ASCII", ".txt", is_text=True), raw)
        self.assertEqual(t.subtype, "hash")
        self.assertIn("hash", t.stages)
        self.assertIn("hash_identify", t.scripts)

    def test_xor_hint(self):
        raw = b"cipher text with key 0x42"
        path = self.write("xor.txt", raw)
        t = triage.file_triage(path, _info("text", "ASCII", ".txt", is_text=True),
                               raw, hints=["异或"])
        self.assertEqual(t.subtype, "xor")
        self.assertIn("xor", t.stages)
        self.assertIn("xor_repeating_key", t.scripts)

    def test_encoding_hint(self):
        raw = b"5L2g5aW977yMZmxhZ3thfQ=="
        path = self.write("enc.txt", raw)
        t = triage.file_triage(path, _info("text", "ASCII", ".txt", is_text=True),
                               raw, hints=["base64 编码"])
        self.assertEqual(t.subtype, "encoding")
        self.assertIn("base_family_decode", t.scripts)

    def test_pixel_matrix(self):
        rows = "\n".join("01010101" for _ in range(10))
        raw = rows.encode()
        path = self.write("matrix.txt", raw)
        t = triage.file_triage(path, _info("text", "ASCII", ".txt", is_text=True), raw)
        self.assertIn("pixel_matrix_qr", t.scripts)


class TestBinaryTriage(TriageBase):
    def test_png(self):
        raw = b"\x89PNG\r\n\x1a\n" + b"\x00" * 64
        path = self.write("x.png", raw)
        t = triage.file_triage(path, _info("image", "PNG", ".png", entropy=7.4), raw)
        self.assertEqual(t.subtype, "png")
        self.assertIn("stego_image", t.stages)
        self.assertIn("lsb_stego_png", t.scripts)

    def test_pcap_dns(self):
        raw = b"\xd4\xc3\xb2\xa1" + b"\x00" * 256
        path = self.write("t.pcap", raw)
        t = triage.file_triage(path, _info("capture", "PCAP", ".pcap"), raw,
                               hints=["dns 隧道外带"])
        self.assertIn("deep_traffic", t.stages)
        self.assertIn("pcap_dns_exfil", t.scripts)

    def test_pyc(self):
        raw = b"\x42\x0d\x0d\x0a" + b"\x00" * 64
        path = self.write("a.pyc", raw)
        t = triage.file_triage(path, _info("executable", "Python bytecode", ".pyc"), raw)
        self.assertEqual(t.subtype, "pyc")
        self.assertIn("deep_reverse", t.stages)
        self.assertIn("pyc_magic_repair", t.scripts)

    def test_elf_pwn(self):
        raw = b"\x7fELF\x02\x01\x01\x00" + b"/bin/sh\x00gets\x00system\x00"
        path = self.write("pwn", raw)
        t = triage.file_triage(path, _info("executable", "ELF", "", size=len(raw)), raw)
        self.assertEqual(t.subtype, "elf_pwn")
        self.assertIn("pwn_static", t.stages)
        self.assertIn("checksec_binary", t.scripts)
        self.assertNotIn("decompile", t.stages)

    def test_elf_reverse(self):
        raw = b"\x7fELF\x02\x01\x01\x00" + b"Correct\x00Wrong\x00flag{\x00"
        path = self.write("rev", raw)
        t = triage.file_triage(path, _info("executable", "ELF", "", size=len(raw)), raw)
        self.assertEqual(t.subtype, "elf_reverse")
        self.assertIn("deep_reverse", t.stages)
        self.assertIn("decompile", t.stages)

    def test_unknown_binary(self):
        raw = bytes(range(256)) * 8
        path = self.write("blob.bin", raw)
        t = triage.file_triage(path, _info("unknown", "data", ".bin",
                                           size=len(raw), entropy=7.99), raw)
        self.assertIn("deep_unknown", t.stages)
        self.assertIn("xor", t.stages)
        self.assertIn("file_carver", t.scripts)

    def test_docx_archive(self):
        path = os.path.join(self.tmp, "a.docx")
        with zipfile.ZipFile(path, "w") as zf:
            zf.writestr("word/document.xml", "<w:document/>")
        with open(path, "rb") as fp:
            raw = fp.read()
        t = triage.file_triage(path, _info("archive", "ZIP", ".docx"), raw)
        self.assertEqual(t.subtype, "docx")
        self.assertIn("archive", t.stages)
        self.assertIn("docx_hidden_extract", t.scripts)


class FakeSession:
    deep = False

    def __init__(self, **kw):
        self.forms = []
        self.targets = []
        self.param_hints = []
        self.serialized = []
        self.serialized_hints = {}
        self.tech = []
        self.tokens = []
        self.home_text = ""
        self.login_required = False
        self.php_sources = []
        self.__dict__.update(kw)


class TestWebTriage(unittest.TestCase):
    def test_upload_only(self):
        session = FakeSession(forms=[{
            "action": "/upload.php", "method": "POST",
            "fields": {"file": "", "submit": ""}, "files": True,
        }])
        t = triage.web_triage(session, hints=["文件上传"])
        self.assertIn("direct_upload", t.stages)
        self.assertNotIn("deser", t.stages)
        self.assertLessEqual(len(t.stages), 4)
        self.assertEqual(t.web_phases[0]["phase"], "direct_upload")

    def test_login_form(self):
        session = FakeSession(forms=[{
            "action": "/login", "method": "POST",
            "fields": {"username": "", "password": "", "csrf": ""}, "files": False,
        }])
        t = triage.web_triage(session, hints=["登录"])
        self.assertIn("login_csrf", t.stages)
        self.assertEqual(t.web_phases[0]["phase"], "login_csrf")

    def test_serialized_deser(self):
        session = FakeSession(
            targets=[{"kind": "get", "url": "http://t/?data=1", "param": "data"}],
            serialized=[{"kind": "php", "where": "param:data", "sample": "O:4:\"User\""}],
            serialized_hints={"classes": ["User"], "props": ["username"]},
        )
        t = triage.web_triage(session, hints=["反序列化"])
        self.assertIn("deser", t.stages)
        self.assertEqual(t.web_phases[0]["phase"], "deser")

    def test_no_evidence_fallback(self):
        t = triage.web_triage(FakeSession(), hints=[])
        self.assertEqual(t.stages, ["sqli", "xss_jwt_idor"])
        self.assertIn("无强证据", t.web_phases[0]["reasons"][0])

    def test_multi_surface_selection(self):
        session = FakeSession(
            forms=[{"action": "/upload", "method": "POST",
                    "fields": {"file": ""}, "files": True},
                   {"action": "/login", "method": "POST",
                    "fields": {"password": ""}, "files": False}],
            links=["http://t/sqli?id=1", "http://t/ping?host=1",
                   "http://t/ssti?name=x", "http://t/lfi?file=a",
                   "http://t/fetch?url=x", "http://t/user?id=1",
                   "http://t/xss?q=1"],
            targets=[{"kind": "get", "url": "http://t/?id=1", "param": "id"},
                     {"kind": "get", "url": "http://t/?url=1", "param": "url"},
                     {"kind": "get", "url": "http://t/?file=1", "param": "file"},
                     {"kind": "get", "url": "http://t/?cmd=1", "param": "cmd"}],
            tech=["PHP"], serialized=[{"kind": "php", "where": "param:x"}],
        )
        t = triage.web_triage(session, hints=["反序列化", "命令执行", "ssrf", "sql 注入"])
        for phase in ("direct_upload", "login_csrf", "sqli", "cmdi",
                      "ssti_lfi", "ssrf_xxe", "xss_jwt_idor", "deser"):
            self.assertIn(phase, t.stages)
        self.assertGreaterEqual(len(t.web_phases), 6)
        self.assertEqual(t.web_phases[0]["phase"], "direct_upload")
        self.assertEqual(t.web_phases[1]["phase"], "login_csrf")


class TestScriptLib(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="mohe_script_")

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def ctx(self, text="", name="input.txt"):
        path = os.path.join(self.tmp, name)
        with open(path, "w", encoding="utf-8") as fp:
            fp.write(text or "x")
        return {"file": path, "workdir": self.tmp, "outdir": self.tmp,
                "text": text, "hints": []}

    def test_select_drops_unknown(self):
        specs = scriptlib.select(["not_exist", "strings_enhanced", "strings_enhanced"])
        self.assertEqual([s.id for s in specs], ["strings_enhanced"])

    def test_strings_args(self):
        spec = scriptlib.get("strings_enhanced")
        args = spec.args(self.ctx())
        self.assertIn("-o", args)
        self.assertTrue(args[-1].endswith("strings.txt"))

    def test_rsa_params_written(self):
        text = "n = 0x12345\ne = 65537\nc = 0xabcdef\n"
        spec = scriptlib.get("rsa_all_in_one")
        args = spec.args(self.ctx(text))
        self.assertEqual(args[0], "--params")
        self.assertTrue(os.path.isfile(args[1]))
        with open(args[1], encoding="utf-8") as fp:
            body = fp.read()
        self.assertIn("n = 0x12345", body)

    def test_rsa_missing_params(self):
        spec = scriptlib.get("rsa_all_in_one")
        self.assertEqual(spec.args(self.ctx("hello")), [])

    def test_registry_mapping(self):
        spec = scriptlib.get("registry_hive_parse")
        self.assertEqual(spec.args(self.ctx("", "NTUSER.DAT"))[0], "--ntuser")
        self.assertIn("--software", spec.args(self.ctx("", "SOFTWARE")))
        self.assertEqual(spec.args(self.ctx("", "SAM")), [])


class TestScriptRunScan(unittest.TestCase):
    def test_strong_and_weak_confidence(self):
        cands = scriptrun._scan_text("flag{abc} ABC{abcd}", "script.test")
        by_value = {c.value: c for c in cands}
        self.assertIn("flag{abc}", by_value)
        self.assertAlmostEqual(by_value["flag{abc}"].confidence, 0.9)
        self.assertIn("ABC{abcd}", by_value)
        self.assertLessEqual(by_value["ABC{abcd}"].confidence, 0.6)

    def test_prepare_zero_width(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "zw.txt")
            with open(path, "w", encoding="utf-8") as fp:
                fp.write("data")
            ctx = {"file": path, "workdir": tmp, "outdir": tmp,
                   "text": "", "hints": []}
            args, why = scriptrun.prepare(scriptlib.get("zero_width_stego"), ctx)
            self.assertEqual(args[:2], ["dec", "-f"], why)


class TestWPAndAutopilotIntegration(TriageBase):
    def setUp(self):
        super().setUp()
        from ctfbox.autopilot import wp as wp_mod
        from ctfbox.autopilot import workspace as ws_mod
        self._old = (wp_mod.WORKSPACE, ws_mod.WORKSPACE)
        wp_mod.WORKSPACE = self.tmp
        ws_mod.WORKSPACE = self.tmp

    def tearDown(self):
        from ctfbox.autopilot import wp as wp_mod
        from ctfbox.autopilot import workspace as ws_mod
        wp_mod.WORKSPACE, ws_mod.WORKSPACE = self._old
        super().tearDown()

    @staticmethod
    def _zw_encode(cover, secret):
        mark = {"0": "\u200b", "1": "\u200c", "s": "\ufeff"}
        bits = "".join(format(ord(ch), "016b") for ch in secret)
        hidden = mark["s"] + "".join(
            mark["1" if bit == "1" else "0"] for bit in bits) + mark["s"]
        mid = len(cover) // 2
        return cover[:mid] + hidden + cover[mid:]

    def test_file_wp_has_triage_section(self):
        from ctfbox.autopilot import wp as wp_mod
        tri = {"kind": "file", "category": "text", "subtype": "zero_width",
               "confidence": 0.8, "evidence": ["出现成串零宽/不可见字符"],
               "stages": ["strings", "codes"],
               "scripts": ["zero_width_stego"], "skipped": []}
        md, data = wp_mod.build_file_wp(
            {"success": True, "target": "zw.txt", "triage": tri},
            meta={"name": "zw"}, workdir=self.tmp)
        self.assertIn("首层判型（主考点路由）", md)
        self.assertIn("zero_width", md)
        self.assertIn("zero_width_stego", md)
        self.assertEqual(data["triage"]["subtype"], "zero_width")

    def test_web_wp_has_triage_section(self):
        from ctfbox.autopilot import wp as wp_mod
        tri = {"kind": "web", "subtype": "web", "confidence": 1.2,
               "evidence": ["表单：/upload（文件上传）"],
               "stages": ["direct_upload", "sqli"],
               "skipped": ["deser(0.0)", "cmdi(0.5)"]}
        md, data = wp_mod.build_web_wp(
            {"success": False, "target": "http://t/",
             "exploit": {"findings": [], "triage": tri}},
            meta={"name": "web"}, workdir=self.tmp)
        self.assertIn("首层判型（主考点路由）", md)
        self.assertIn("direct_upload", md)
        self.assertIn("deser", md)
        self.assertEqual(data["triage"]["stages"][0], "direct_upload")

    def test_autopilot_run_file_records_triage_and_scripts(self):
        from ctfbox.autopilot.orchestrator import AutoPilot
        secret = "flag{zw_auto_script}"
        path = self.write("zw.txt", self._zw_encode(
            "这是一段正常的话，没有任何异常。", secret).encode("utf-8"))
        result = AutoPilot(max_steps=10, timeout=120).run_file(path)
        self.assertTrue(result["success"], result.get("notes"))
        self.assertEqual(result["triage"]["subtype"], "zero_width")
        self.assertIn("zero_width_stego", result["triage"]["scripts"])
        tools = [item.get("tool") for item in result.get("scripts") or []]
        self.assertIn("script.zero_width_stego", tools)
        self.assertTrue(any(c["value"] == secret for c in result["candidates"]))
        self.assertTrue(os.path.isfile(result["wp"]))
        with open(result["wp"], encoding="utf-8") as fp:
            md = fp.read()
        self.assertIn("首层判型（主考点路由）", md)
        self.assertIn("自动脚本：", md)

    def test_prepare_missing_dependency_no_args(self):
        spec = scriptlib.ScriptSpec(
            id="__probe__", path="misc/zero_width_stego.py", direction="misc",
            description="probe", needs=("definitely_missing_module_xyz",))
        ctx = {"file": os.path.join(self.tmp, "x.txt"), "workdir": self.tmp,
               "outdir": self.tmp, "text": "", "hints": []}
        args, why = scriptrun.prepare(spec, ctx)
        self.assertEqual(args, [])
        self.assertIn("缺少依赖", why)


if __name__ == "__main__":
    unittest.main(verbosity=2)
