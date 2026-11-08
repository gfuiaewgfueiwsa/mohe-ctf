# -*- coding: utf-8 -*-
"""v3.7.0：兽音变体解码回归（真实 hex 算法 + CJK 符号集 + 引导语杂散符号）。"""
import unittest

from ctfbox import modules_polar


def _roar_encode(plain, syms="喵呜啊~", sign=1):
    """按真实兽音算法编码：码点->4位hex->每位加 n%16->拆2符号，头3尾1。"""
    hexstr = "".join(f"{ord(c):04x}" for c in plain)
    body = []
    for n, h in enumerate(hexstr):
        k = (int(h, 16) + sign * (n % 16)) % 16
        body.append(syms[k // 4])
        body.append(syms[k % 4])
    return syms[3] + syms[1] + syms[0] + "".join(body) + syms[2]


class TestRoarVariant(unittest.TestCase):
    def test_ascii_url_roundtrip(self):
        plain = "http://example.com/r/AbCdEf123456"
        self.assertEqual(modules_polar.roar_variant_decode(_roar_encode(plain)), plain)

    def test_cjk_roundtrip(self):
        plain = "兽音解码测试你好世界"
        cipher = _roar_encode(plain, syms="呜喵啊~")
        self.assertEqual(modules_polar.roar_variant_decode(cipher), plain)

    def test_stray_preamble_symbol(self):
        plain = "flag{0123456789abcdef}"
        text = "小明养了一只喵，它说：\n" + _roar_encode(plain) + "\n请翻译。"
        self.assertEqual(modules_polar.roar_variant_decode(text), plain)

    def test_non_cipher_returns_none(self):
        self.assertIsNone(modules_polar.roar_variant_decode(
            "这是一段普通的中文文本，没有任何兽音密文结构。"))


if __name__ == "__main__":
    unittest.main()