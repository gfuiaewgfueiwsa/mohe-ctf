# -*- coding: utf-8 -*-
"""v3.5.1：异常椭圆曲线 + 多维 HNP（纯 Python LLL/SNF）回归。"""
import hashlib
import itertools
import math
import os
import unittest

from ctfbox import modules_ecc


def _gcdn_minors(rows):
    g = 0
    for cols in itertools.combinations(range(len(rows[0])), len(rows)):
        m = [[row[c] for c in cols] for row in rows]
        if len(m) == 3:
            det = (m[0][0] * (m[1][1] * m[2][2] - m[1][2] * m[2][1])
                   - m[0][1] * (m[1][0] * m[2][2] - m[1][2] * m[2][0])
                   + m[0][2] * (m[1][0] * m[2][1] - m[1][1] * m[2][0]))
        else:
            det = m[0][0] * m[1][1] - m[0][1] * m[1][0]
        g = math.gcd(g, abs(det))
    return g


class TestSaturation(unittest.TestCase):
    def test_even_sublattice_saturates(self):
        basis = [[2, 0, 0, 0, 0, 0], [0, 2, 0, 0, 0, 0], [0, 0, 2, 0, 0, 0]]
        sat = modules_ecc._snf_saturate(basis)
        self.assertEqual(1, _gcdn_minors(sat))

    def test_mixed_lattice_saturates(self):
        basis = [[2, 0, 1, 0, 0, 0], [0, 4, 2, 0, 0, 0],
                 [0, 0, 0, 6, 0, 3]]
        sat = modules_ecc._snf_saturate(basis)
        self.assertEqual(1, _gcdn_minors(sat))


class TestEccAttack(unittest.TestCase):
    def test_detect(self):
        self.assertFalse(modules_ecc.looks_like("n = 12345\ne = 65537"))
        pts = "\n".join("(%d, %d)" % (10 ** 60 + i, 10 ** 61 + i) for i in range(8))
        self.assertTrue(modules_ecc.looks_like(pts))

    def test_1472_points_to_flag(self):
        path = os.path.join(os.path.dirname(__file__), "fixtures", "ecc_points_1472.txt")
        with open(path, encoding="utf-8") as fp:
            text = fp.read()
        res = modules_ecc.attack(text)
        self.assertEqual(73, res["points"])
        self.assertEqual(512, res["p_bits"])
        self.assertTrue(res["flags"])
        digest = hashlib.sha256(res["flags"][0].encode()).hexdigest()
        self.assertEqual("6c5699fac2e452168aa96e7f3aa8b5e04c83f13247f5bde62aaac560fe2db95c",
                         digest)


if __name__ == "__main__":
    unittest.main()
