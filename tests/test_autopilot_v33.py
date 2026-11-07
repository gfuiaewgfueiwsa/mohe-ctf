# -*- coding: utf-8 -*-
"""v3.3.0 集成测试：声明闸门、scope、Web 全量利用链、RAR5 递归、审计。

测试使用 tests/v33_target.py 自建本地靶站（127.0.0.1 随机端口），
不访问公网、不对外发送任何请求。靶站只模拟必要响应，不是真实漏洞环境。
"""
import json
import os
import shutil
import tempfile
import unittest

from ctfbox.autopilot import audit, consent
from ctfbox.autopilot.exploit import payloads
from ctfbox.autopilot.exploit.engine import ExploitSession
from ctfbox.autopilot.scope import ScopeGuard
from ctfbox.autopilot.tools import archive
from ctfbox.autopilot.workspace import TaskWorkspace
from tests.v33_target import LocalTarget


class V33Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="mohe_v33_test_")
        self._old = (consent.CONSENT_DIR, consent.CONSENT_PATH, audit.AUDIT_DIR)
        consent.CONSENT_DIR = os.path.join(self.tmp, "config")
        consent.CONSENT_PATH = os.path.join(consent.CONSENT_DIR, "consent.json")
        audit.AUDIT_DIR = os.path.join(self.tmp, "audit")
        with consent._SESSION_LOCK:
            consent._SESSION.clear()

    def tearDown(self):
        consent.CONSENT_DIR, consent.CONSENT_PATH, audit.AUDIT_DIR = self._old
        with consent._SESSION_LOCK:
            consent._SESSION.clear()
        shutil.rmtree(self.tmp, ignore_errors=True)

    @staticmethod
    def _log(_message):
        pass


class TestConsentAndScope(V33Base):
    def test_legacy_consent_no_longer_blocks(self):
        # v3.7.0：逐工具声明取消，require() 恒放行；历史记录接口仍可用
        self.assertFalse(consent.is_granted())
        self.assertTrue(consent.require())
        consent.grant(source="test")
        self.assertTrue(consent.is_granted())
        self.assertEqual(consent.status()["declaration_version"],
                         consent.DECLARATION_VERSION)

    def test_session_grant_does_not_require_file(self):
        consent.grant_session(target="http://127.0.0.1/")
        self.assertTrue(consent.is_granted())
        self.assertTrue(consent.status()["session_granted"])
        self.assertFalse(os.path.exists(consent.CONSENT_PATH))

    def test_scope_allows_public_host_without_whitelist(self):
        guard = ScopeGuard(authorized=True, allow_hosts=[], allow_private=False)
        self.assertEqual(guard.check("http://example.com/")["host"], "example.com")
        guard2 = ScopeGuard(authorized=True, allow_hosts=["example.com"],
                            allow_private=False)
        self.assertEqual(guard2.check("http://example.com/a")["host"], "example.com")

    def test_payload_generators(self):
        ser = payloads.build_php_pop("MoheProbe", {"cmd": "echo MOHE"})
        self.assertIn('O:9:"MoheProbe"', ser)
        self.assertIn("echo MOHE", ser)
        phar = payloads.build_phar(ser, files={"a.txt": b"x"})
        check = payloads.phar_self_check(phar)
        self.assertTrue(check.get("ok"), check)
        token = payloads.jwt_hs256({"role": "admin"}, b"secret")
        self.assertTrue(payloads.jwt_crack_hs256(token)["ok"])
        variants = payloads.jwt_none_variants({"role": "admin"})
        self.assertGreaterEqual(len(variants), 4)
        self.assertEqual(payloads.jwt_decode(variants[0])["header"]["alg"], "none")
        self.assertEqual(variants[0].split(".")[-1], "")


class TestExploitChain(V33Base):
    def test_full_chain_against_local_target(self):
        consent.grant(source="test")
        with LocalTarget() as target:
            ws = TaskWorkspace("web", "v33_exploit", root=os.path.join(self.tmp, "tasks"))
            guard = ScopeGuard(authorized=True, allow_private=False)
            session = ExploitSession(target.url, guard, ws, audit.AuditLog(ws.dir),
                                     log=self._log, max_requests=240, interval=0.0)
            try:
                disc = session.discover()
                self.assertTrue(disc.ok, disc.summary)
                self.assertGreaterEqual(disc.data["targets"], 5)
                planned = list(session.plan())
                # 判型只选有证据的阶段；该 fixture 根路径也接受序列化参数，
                # 这里显式补跑 deser，用于回归引擎的反序列化能力。
                self.assertNotIn("deser", planned,
                                 "无序列化证据时不应默认遍历反序列化阶段")
                for phase in planned + ["deser"]:
                    session.phase(phase)
                data = session.finish()
            finally:
                ws.close()

            types = {item["type"] for item in data["findings"]}
            expected = {
                "sqli-error", "cmdi", "ssti", "lfi", "upload-exec",
                "weak-login", "xss-reflected", "jwt-hs256", "idor",
                "lfi-wrapper", "xxe", "deser-php",
            }
            missing = expected - types
            self.assertFalse(missing, "缺少发现类型 %s；实际 %s" % (missing, sorted(types)))
            self.assertTrue(any(str(t).startswith("cookie") for t in types))
            self.assertGreater(data["audit"]["entries"], 20)
            self.assertTrue(os.path.isfile(os.path.join(ws.dir, "audit.jsonl")))
            self.assertTrue(os.path.isfile(os.path.join(
                ws.dir, "artifacts", "exploit_result.json")))
            self.assertTrue(data["artifacts"])
            self.assertTrue(any(f.startswith("flag{") for f in data["flags"]),
                            "利用链未取到任何 flag：%s" % data["flags"])
            # 同一 payload 至少记录 hash + preview，不落完整二进制
            with open(os.path.join(ws.dir, "audit.jsonl"), encoding="utf-8") as fp:
                first = json.loads(fp.readline())
            self.assertIn("sha256", first["payload"])
            self.assertIn("preview", first["payload"])

    def test_time_blind_extract_against_local_target(self):
        consent.grant(source="test")
        with LocalTarget() as target:
            ws = TaskWorkspace("web", "v33_time", root=os.path.join(self.tmp, "tasks"))
            guard = ScopeGuard(authorized=True, allow_private=False)
            session = ExploitSession(target.url, guard, ws, audit.AuditLog(ws.dir),
                                     log=self._log, max_requests=200, interval=0.0,
                                     time_extract_chars=4)
            session.time_extract_sleep = 0.35
            notes = []
            try:
                ok = session._sqli_time_extract(
                    {"kind": "get", "url": target.url + "/sqli-time",
                     "param": "id", "value": "1", "form": None},
                    {"mode": "mysql", "quote": False, "sleep": 0.35, "db": "MySQL"},
                    notes)
            finally:
                ws.close()
        self.assertTrue(ok, notes)
        dumps = [f for f in session.findings if f["type"] == "sqli-time-dump"]
        values = [f["evidence"] for f in dumps if "select database()" in f["payload"]]
        self.assertTrue(values and "mohe" in values[0], (values, notes))
        self.assertTrue(any("时间盲注取数完成" in n for n in notes), notes)

    def test_autopilot_exploit_runs_without_per_tool_consent(self):
        # v3.7.0：不再需要 --i-own-this-target / --consent，启动责任说明已统一确认
        from ctfbox.autopilot.orchestrator import AutoPilot
        with LocalTarget() as target:
            pilot = AutoPilot(exploit=True, max_steps=4, timeout=30,
                              log=self._log, exploit_interval=0.0)
            result = pilot.run_url(target.url)
        self.assertTrue(result.get("exploit"), "无逐工具声明时应正常进入利用链")
        self.assertFalse(os.path.exists(consent.CONSENT_PATH))

    def test_autopilot_exploit_chain_wired(self):
        from ctfbox.autopilot.orchestrator import AutoPilot
        consent.grant(source="test")
        with LocalTarget() as target:
            pilot = AutoPilot(exploit=True, max_steps=14, timeout=120,
                              log=self._log, exploit_interval=0.0,
                              exploit_max_requests=240)
            result = pilot.run_url(target.url)
        exploit = result.get("exploit") or {}
        self.assertTrue(exploit, "AutoPilot 未接入利用结果")
        self.assertGreater(exploit.get("requests", 0), 0)
        self.assertTrue(exploit.get("findings"))
        self.assertTrue(os.path.isfile(os.path.join(result["workdir"], "report.md")))
        with open(os.path.join(result["workdir"], "report.md"), encoding="utf-8") as fp:
            report = fp.read()
        self.assertIn("Web 利用结果", report)
        self.assertIn("利用审计", report)


class TestArchive(V33Base):
    def test_real_rar5_fixture_extracts(self):
        fixture = os.path.join(os.path.dirname(__file__), "fixtures", "testfile.rar5.rar")
        self.assertTrue(os.path.isfile(fixture), "缺少 RAR5 测试样本")
        self.assertEqual(archive.archive_kind(fixture), "RAR5")
        result = archive.extract(fixture, os.path.join(self.tmp, "extract"), depth=0,
                                 log=self._log)
        self.assertTrue(result.ok, result.notes)
        self.assertEqual(result.data.get("format"), "RAR5")
        names = [os.path.basename(p) for p in result.data.get("files", [])]
        self.assertIn("testfile.txt", names)
        self.assertTrue(os.path.isfile(result.data["files"][0]))

    def test_nested_zip_chain(self):
        import zipfile
        inner = os.path.join(self.tmp, "inner.zip")
        with zipfile.ZipFile(inner, "w") as zf:
            zf.writestr("flag.txt", "flag{archive_nested_ok}")
        outer = os.path.join(self.tmp, "outer.zip")
        with zipfile.ZipFile(outer, "w") as zf:
            zf.write(inner, "inner.zip")
        result = archive.extract(outer, os.path.join(self.tmp, "extract"), depth=0,
                                 log=self._log)
        self.assertTrue(result.ok, result.notes)
        self.assertEqual(len(result.data.get("nested", [])), 1)
        deep = archive.extract(result.data["nested"][0],
                               os.path.join(self.tmp, "extract"), depth=1,
                               log=self._log)
        self.assertTrue(deep.ok)
        self.assertIn("flag{archive_nested_ok}", deep.data.get("flags", []))


if __name__ == "__main__":
    unittest.main()
