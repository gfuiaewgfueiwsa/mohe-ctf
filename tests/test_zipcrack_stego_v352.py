# -*- coding: utf-8 -*-
"""v3.5.2：ZipCrypto 口令恢复 + cloacked-pixel 图片隐写回归。"""
import os
import struct
import subprocess
import tempfile
import unittest
import zipfile

from ctfbox import modules_stego, modules_zipcrack
from ctfbox.autopilot.tools import archive


def _has_7z():
    return bool(archive.find_7z())


class TestPasswordCandidates(unittest.TestCase):
    def test_keyboard_mirror(self):
        words = modules_zipcrack.keyboard_words()
        self.assertIn("zaqqaz", words)
        self.assertIn("qazzaq", words)

    def test_known_password_first_and_dedup(self):
        words = modules_zipcrack.password_candidates(
            "caigou.zip", hints=["菜狗"], known=["zaqqaz"])
        self.assertEqual("zaqqaz", words[0])
        self.assertEqual(len(words), len(set(words)))

    def test_filename_and_date_derived(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "202012MISC_PolarDN_CTF_.zip")
            with zipfile.ZipFile(path, "w") as zf:
                zf.writestr("a.txt", "x")
            words = modules_zipcrack.password_candidates(path)
            self.assertIn("202012", words)
            self.assertIn("2020", words)


@unittest.skipUnless(_has_7z(), "需要随包 7-Zip 创建加密 ZIP")
class TestZipCryptoCrack(unittest.TestCase):
    def test_crack_and_extract_zaqqaz(self):
        sevenz = archive.find_7z()
        with tempfile.TemporaryDirectory() as tmp:
            src = os.path.join(tmp, "flag.txt")
            with open(src, "w", encoding="utf-8") as fp:
                fp.write("flag{zipcrack_test}")
            zip_path = os.path.join(tmp, "caigou.zip")
            subprocess.run([sevenz, "a", "-tzip", "-pzaqqaz", zip_path, src],
                           capture_output=True, timeout=60, check=True)
            res = modules_zipcrack.crack_zip(zip_path, hints=["菜狗"])
            self.assertTrue(res.get("ok"), res)
            self.assertEqual("zaqqaz", res.get("password"))

            outdir = os.path.join(tmp, "out")
            tool = archive.extract(zip_path, outdir)
            self.assertTrue(tool.ok, tool.notes)
            self.assertEqual("zaqqaz", (tool.data or {}).get("password"))
            names = [os.path.basename(p) for p in tool.data.get("files", [])]
            self.assertIn("flag.txt", names)


class TestCloackedPixel(unittest.TestCase):
    @staticmethod
    def _embed(path, payload, password):
        import hashlib

        import numpy as np
        from PIL import Image
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

        pad = 32 - len(payload) % 32
        data = payload + bytes([pad]) * pad
        iv = os.urandom(16)
        enc = Cipher(algorithms.AES(hashlib.sha256(password.encode()).digest()),
                     modes.CBC(iv)).encryptor()
        cipher = iv + enc.update(data) + enc.finalize()
        blob = struct.pack("<i", len(cipher)) + cipher

        bits = []
        for byte in blob:
            for shift in range(7, -1, -1):
                bits.append((byte >> shift) & 1)
        rgb = np.zeros((32, 32, 3), dtype=np.uint8)
        flat = rgb.reshape(-1)
        for i, bit in enumerate(bits):
            flat[i] = (flat[i] & 0xFE) | bit
        Image.fromarray(rgb.reshape(32, 32, 3), "RGB").save(path)

    def test_extract_flag(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "caigou.png")
            self._embed(path, b"flag{cloacked_test}", "zaqqaz")
            res = modules_stego.cloacked_extract(
                path, passwords=["wrong", "zaqqaz"], outdir=tmp)
            self.assertTrue(res.get("ok"), res)
            self.assertEqual("zaqqaz", res.get("password"))
            self.assertEqual(b"flag{cloacked_test}", res.get("data"))
            self.assertEqual(["flag{cloacked_test}"], res.get("flags"))

    def test_wrong_password_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "caigou.png")
            self._embed(path, b"flag{cloacked_test}", "zaqqaz")
            res = modules_stego.cloacked_extract(path, passwords=["nope"])
            self.assertFalse(res.get("ok"))


if __name__ == "__main__":
    unittest.main()
