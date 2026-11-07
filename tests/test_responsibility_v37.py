# -*- coding: utf-8 -*-
"""v3.7.0 唯一《软件责任说明》闸门测试（离线、不启动 GUI）。"""
import json
import os
import tempfile
import unittest

from ctfbox import responsibility


class ResponsibilityGate(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="mohe_resp_")
        self._old = (responsibility.CONFIG_DIR, responsibility.RESPONSIBILITY_PATH)
        responsibility.CONFIG_DIR = self.tmp
        responsibility.RESPONSIBILITY_PATH = os.path.join(self.tmp, "responsibility.json")

    def tearDown(self):
        responsibility.CONFIG_DIR, responsibility.RESPONSIBILITY_PATH = self._old

    def _record(self):
        with open(responsibility.RESPONSIBILITY_PATH, "r", encoding="utf-8") as fp:
            return json.load(fp)

    def test_cli_blocks_until_accepted(self):
        self.assertFalse(responsibility.is_accepted())
        self.assertFalse(responsibility.ensure_cli(["--auto", "sample.bin"]))
        self.assertFalse(os.path.exists(responsibility.RESPONSIBILITY_PATH))
        self.assertTrue(responsibility.ensure_cli(
            ["--auto", "sample.bin", "--accept-responsibility"]))
        self.assertTrue(responsibility.is_accepted())
        self.assertTrue(responsibility.ensure_cli(["--list"]))
        record = self._record()
        self.assertEqual(record["statement_sha256"], responsibility.STATEMENT_SHA256)
        self.assertEqual(record["version"], responsibility.RESPONSIBILITY_VERSION)

    def test_version_mismatch_invalidates(self):
        responsibility.accept("test")
        record = self._record()
        record["version"] = "0"
        with open(responsibility.RESPONSIBILITY_PATH, "w", encoding="utf-8") as fp:
            json.dump(record, fp, ensure_ascii=False)
        self.assertFalse(responsibility.is_accepted())

    def test_statement_covers_responsibility_terms(self):
        for token in ("授权", "法律责任", "数据", "无担保", "不同意"):
            self.assertIn(token, responsibility.RESPONSIBILITY_TEXT)

    def test_revoke(self):
        responsibility.accept("test")
        self.assertTrue(responsibility.revoke())
        self.assertFalse(responsibility.is_accepted())

    def test_consent_dialog_keeps_accept_controls_visible(self):
        """v3.7.0 事故回归：文本区默认高度会把勾选框/按钮挤出窗口。"""
        try:
            from ctfbox.ui_consent import ConsentDialog
            dialog = ConsentDialog()
        except Exception as exc:      # 无图形环境时跳过，不掩盖逻辑失败
            self.skipTest(f"tk unavailable: {exc}")
        try:
            dialog.update_idletasks()
            dialog.update()
            for widget in (dialog.checkbox, dialog.accept_button):
                self.assertTrue(widget.winfo_ismapped())
                bottom = widget.winfo_rooty() + widget.winfo_height()
                self.assertLessEqual(bottom, dialog.winfo_rooty() + dialog.winfo_height())
        finally:
            dialog.destroy()


if __name__ == "__main__":
    unittest.main()
