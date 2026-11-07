# -*- coding: utf-8 -*-
"""v3.2.0 编排层/工具层单元测试（不联网、不执行样本）。"""
import base64
import os
import shutil
import tempfile
import unittest

from ctfbox.autopilot import scope, workspace as wsmod
from ctfbox.autopilot.models import Candidate
from ctfbox.autopilot.orchestrator import AutoPilot
from ctfbox.autopilot.tools import codes, crypto, rsa, xor


class TestXor(unittest.TestCase):
    def test_single_byte(self):
        plain = b"flag{xor_single_byte}"
        data = bytes(b ^ 0x42 for b in plain)
        res = xor.single_byte(data)
        self.assertTrue(any(c.value == plain.decode() for c in res.candidates), res.data)

    def test_repeating_key(self):
        # 频率法需要足够长的自然语言样本；短样本由 crib/单字节路径覆盖
        key = b"KEYS"
        head = b"The quick brown fox jumps over the lazy dog. " * 12
        plain = head + b"flag{repeating_xor_key}"
        data = bytes(b ^ key[i % len(key)] for i, b in enumerate(plain))
        res = xor.repeating(data)
        values = [c.value for c in res.candidates]
        self.assertIn("flag{repeating_xor_key}", values, res.data)

    def test_crib_complete_key(self):
        key = b"CTF!"
        plain = b"flag{crib_complete_key}"
        data = bytes(b ^ key[i % len(key)] for i, b in enumerate(plain))
        res = xor.crib_recover(data)
        self.assertTrue(any(c.value == plain.decode() for c in res.candidates), res.data)

    def test_no_false_flag_on_plain_english(self):
        res = xor.crib_recover(b"just some plain english text without a secret")
        self.assertEqual([], [c.value for c in res.candidates])

    def test_noise_flag_body_rejected(self):
        from ctfbox.autopilot.tools.xor import _valid_flags
        self.assertEqual([], _valid_flags(b"flag{??v???????v???}"))
        self.assertEqual([], _valid_flags(b"flag{****}"))
        self.assertEqual(["flag{deadbeef_c0ffee}"],
                         _valid_flags(b"flag{deadbeef_c0ffee}"))


class TestCodes(unittest.TestCase):
    def test_nested_base64(self):
        payload = b"flag{nested_base64}"
        data = base64.b64encode(base64.b64encode(payload))
        res = codes.decode_chain(data)
        self.assertTrue(any(c.value == payload.decode() for c in res.candidates), res.data)


class TestCrypto(unittest.TestCase):
    """对称密码试解：密文 + 密钥候选 → 强 flag 候选。"""

    FLAG = b"flag{crypto_pipeline_ok}"

    def _payload(self, cipher, key, embed=True, block=16):
        from Crypto.Util.Padding import pad
        body = self.FLAG + b" " + b"the quick brown fox. " * 10
        ct = cipher.encrypt(pad(body, block))
        return (b"key=" + key + b"\n" + ct) if embed else ct

    def test_aes_ecb(self):
        from Crypto.Cipher import AES
        key = b"MySecretKey12345"
        data = self._payload(AES.new(key, AES.MODE_ECB), key)
        res = crypto.analyze(data)
        self.assertEqual([self.FLAG.decode()],
                         [c.value for c in res.candidates], res.data)

    def test_aes_cbc(self):
        from Crypto.Cipher import AES
        key = b"0123456789abcdef"
        data = self._payload(AES.new(key, AES.MODE_CBC, b"\x00" * 16), key)
        res = crypto.analyze(data)
        self.assertEqual([self.FLAG.decode()],
                         [c.value for c in res.candidates], res.data)

    def test_des_ecb(self):
        from Crypto.Cipher import DES
        key = b"deskey12"
        data = self._payload(DES.new(key, DES.MODE_ECB), key, block=8)
        res = crypto.analyze(data)
        self.assertEqual([self.FLAG.decode()],
                         [c.value for c in res.candidates], res.data)

    def test_3des_ecb(self):
        from Crypto.Cipher import DES3
        key = b"0123456789abcdef01234567"
        data = self._payload(DES3.new(key, DES3.MODE_ECB), key, block=8)
        res = crypto.analyze(data)
        self.assertEqual([self.FLAG.decode()],
                         [c.value for c in res.candidates], res.data)

    def test_rc4_filename_key(self):
        from Crypto.Cipher import ARC4
        data = ARC4.new(b"secret").encrypt(self.FLAG + b" " + b"abcdefgh " * 40)
        res = crypto.analyze(data, path="rc4_secret.bin")
        self.assertEqual([self.FLAG.decode()],
                         [c.value for c in res.candidates], res.data)


class TestWorkspace(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="mohe_v3_ws_")

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_dedupe_keeps_highest_confidence(self):
        ws = wsmod.TaskWorkspace("test", "sample", root=self.tmp)
        ws.add_candidates([Candidate("flag{a}", 0.5, "tool.a", "low"),
                           Candidate("flag{a}", 0.9, "tool.b", "high")])
        self.assertEqual(1, len(ws.candidates))
        self.assertEqual(0.9, ws.candidates[0].confidence)
        self.assertIn("tool.b", ws.candidates[0].source)
        ws.close()


class TestScope(unittest.TestCase):
    def test_authorization_not_checked_per_target(self):
        # v3.7.0：授权由启动责任说明统一确认，地址层不再拦截
        self.assertEqual("loopback",
                         scope.ScopeGuard(False).check("http://127.0.0.1:8080/")["kind"])

    def test_loopback_allowed(self):
        self.assertEqual("loopback",
                         scope.ScopeGuard(True).check("http://127.0.0.1:8080/")["kind"])

    def test_public_allowed_without_whitelist(self):
        self.assertEqual("domain", scope.ScopeGuard(True).check("http://example.com/")["kind"])
        self.assertEqual("public", scope.ScopeGuard(True).check("http://8.8.8.8/")["kind"])

    def test_private_allowed_without_flag(self):
        self.assertEqual("private",
                         scope.ScopeGuard(True).check("http://192.168.1.10/")["kind"])

    def test_invalid_urls_still_rejected(self):
        guard = scope.ScopeGuard(True)
        with self.assertRaises(scope.ScopeError):
            guard.check("ftp://example.com/")
        with self.assertRaises(scope.ScopeError):
            guard.check("http://user:pass@example.com/")
        self.assertTrue(guard.host_allowed("example.com") is False)
        wildcard = scope.ScopeGuard(True, ["*.example.com"])
        self.assertTrue(wildcard.host_allowed("api.example.com"))
        self.assertFalse(wildcard.host_allowed("evil-example.com"))
        # 白名单只作标注，不再阻止请求
        self.assertEqual("domain", wildcard.check("https://evil-example.com/")["kind"])


class TestScanFlags(unittest.TestCase):
    def test_css_pseudo_not_flag(self):
        from ctfbox.common import scan_flags
        self.assertEqual([], scan_flags(b"a[flag]:before{color:red}", strong_only=True))
        self.assertEqual([], scan_flags(b"i.flag:hover{opacity:.5}", strong_only=True))

    def test_flag_kv_kept(self):
        from ctfbox.common import scan_flags
        self.assertTrue(scan_flags(b"flag{abc_def}", strong_only=True))
        self.assertTrue(scan_flags(b"flag:correct_flag_2026", strong_only=True))

    def test_placeholder_flags_filtered(self):
        from ctfbox.common import is_placeholder_flag, scan_flags
        for value in ("flag{??????????????}", "flag{***}", "flag{xxxx}",
                      "flag{...}", "flag{YOUR_FLAG_HERE}", "flag{REDACTED}"):
            self.assertTrue(is_placeholder_flag(value), value)
            self.assertEqual([], scan_flags(value.encode(), strong_only=True), value)
            self.assertEqual([], scan_flags(value.encode()), value)
        real = "flag{0123456789abcdef0123456789abcdef}"
        self.assertFalse(is_placeholder_flag(real))
        self.assertEqual([real], scan_flags(real.encode(), strong_only=True))


class TestRSA(unittest.TestCase):
    def test_common_modulus(self):
        from Crypto.Util.number import getPrime
        p, q = getPrime(128), getPrime(128)
        n = p * q
        e1, e2 = 17, 65537
        m = int.from_bytes(b"flag{rsa_common_modulus}", "big")
        c1, c2 = pow(m, e1, n), pow(m, e2, n)
        text = ("n = 0x%x\ne1 = %d\ne2 = %d\nc1 = 0x%x\nc2 = 0x%x\n"
                % (n, e1, e2, c1, c2))
        res = rsa.analyze_text(text)
        self.assertTrue(any(c.value.startswith("flag{") for c in res.candidates),
                        res.summary)

    def test_no_params(self):
        res = rsa.analyze_text("hello world")
        self.assertFalse(res.ok)


class TestPipeline(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="mohe_v3_pipe_")
        self.old_ws = wsmod.WORKSPACE
        wsmod.WORKSPACE = os.path.join(self.tmp, "workspace")

    def tearDown(self):
        wsmod.WORKSPACE = self.old_ws
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_plain_flag_pipeline(self):
        path = os.path.join(self.tmp, "plain.txt")
        with open(path, "w", encoding="utf-8") as fp:
            fp.write("flag{pipeline_ok}\n")
        res = AutoPilot().run_file(path)
        self.assertTrue(res["success"])
        self.assertIn("flag{pipeline_ok}", res["flags"])
        self.assertTrue(os.path.exists(os.path.join(res["workdir"], "report.md")),
                        res["workdir"])

    def test_xor_pipeline(self):
        path = os.path.join(self.tmp, "xor.bin")
        key = b"K3Y!"
        plain = b"flag{pipeline_xor}"
        with open(path, "wb") as fp:
            fp.write(bytes(b ^ key[i % len(key)] for i, b in enumerate(plain)))
        res = AutoPilot().run_file(path)
        self.assertTrue(res["success"])
        self.assertIn("flag{pipeline_xor}", res["flags"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
