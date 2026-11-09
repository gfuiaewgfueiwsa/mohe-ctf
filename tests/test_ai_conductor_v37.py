# -*- coding: utf-8 -*-
"""AI conductor 回归：GBNF 约束、动作白名单、参数校验、默认关闭。"""
import os
import unittest

from ctfbox.ai import ai_enabled, ai_config
from ctfbox.ai.conductor import ACTIONS, GRAMMAR, Conductor


class _FakeBackend:
    def __init__(self, output):
        self.output = output
        self.last = None

    def complete(self, prompt, grammar=None, max_tokens=160, temperature=0.2):
        self.last = {"prompt": prompt, "grammar": grammar}
        return self.output


class _Ws:
    def __init__(self, root=""):
        self.artifacts_dir = root
        self.notes = []

    def ranked_candidates(self):
        return []

    def log(self, *a, **k):
        pass

    def record(self, *a, **k):
        pass


class AiConductorTest(unittest.TestCase):
    def test_grammar_enumerates_actions(self):
        self.assertIn("root", GRAMMAR)
        for name in ACTIONS:
            self.assertIn('\\"%s\\"' % name, GRAMMAR)

    def test_decide_accepts_valid_json(self):
        c = Conductor()
        out = c.decide(_FakeBackend(
            '{"action":"deep_misc","target":"T1","depth":2,"reason":"音频深挖"}'),
            {"targets": [{"id": "T0"}, {"id": "T1"}]})
        self.assertEqual(out["action"], "deep_misc")
        self.assertEqual(out["target"], "T1")
        self.assertEqual(out["depth"], 2)

    def test_decide_rejects_unknown_action(self):
        c = Conductor()
        out = c.decide(_FakeBackend(
            '{"action":"rm_rf","target":"T0","depth":1,"reason":"x"}'),
            {"targets": [{"id": "T0"}]})
        self.assertIsNone(out)

    def test_decide_rejects_non_json(self):
        c = Conductor()
        out = c.decide(_FakeBackend("我觉得应该继续"), {"targets": [{"id": "T0"}]})
        self.assertIsNone(out)

    def test_decide_clamps_depth(self):
        c = Conductor()
        out = c.decide(_FakeBackend(
            '{"action":"decode_chain","target":"T0","depth":9,"reason":"x"}'),
            {"targets": [{"id": "T0"}]})
        self.assertEqual(out["depth"], 3)

    def test_decide_stop(self):
        c = Conductor()
        out = c.decide(_FakeBackend(
            '{"action":"stop","target":"T0","depth":1,"reason":"已足够"}'),
            {"targets": [{"id": "T0"}]})
        self.assertEqual(out["action"], "stop")

    def test_prompt_carries_state_and_grammar(self):
        c = Conductor()
        b = _FakeBackend('{"action":"stop","target":"T0","depth":1,"reason":"x"}')
        c.decide(b, {"category": "misc", "targets": [{"id": "T0", "name": "a.bin"}]})
        self.assertIsNotNone(b.last["grammar"])
        self.assertIn("a.bin", b.last["prompt"])
        self.assertIn("deep_misc", b.last["prompt"])

    def test_targets_include_saved_and_artifacts(self):
        import tempfile
        c = Conductor()
        from ctfbox.autopilot.workspace import TaskWorkspace
        ws = TaskWorkspace("file", "ai_targets_test")
        try:
            saved = os.path.join(ws.input_dir, "saved.bin")
            with open(saved, "wb") as fp:
                fp.write(b"x")
            art = os.path.join(ws.artifacts_dir, "member.txt")
            with open(art, "w", encoding="utf-8") as fp:
                fp.write("y")
            targets = c._targets(ws, saved)
            self.assertIn(saved, targets)
            self.assertIn(art, targets)
        finally:
            ws.close()

    def test_allowed_actions_by_file_kind(self):
        import tempfile
        c = Conductor()
        with tempfile.TemporaryDirectory() as tmp:
            paths = {}
            for name in ("a.zip", "a.mp3", "a.png", "a.exe"):
                p = os.path.join(tmp, name)
                with open(p, "wb") as fp:
                    fp.write(b"MZ" if name.endswith(".exe") else b"x")
                paths[name] = p
            self.assertIn("archive_extract", c._allowed_actions(paths["a.zip"]))
            self.assertNotIn("decompile", c._allowed_actions(paths["a.zip"]))
            self.assertIn("deep_misc", c._allowed_actions(paths["a.mp3"]))
            self.assertNotIn("stego_image", c._allowed_actions(paths["a.mp3"]))
            self.assertIn("stego_image", c._allowed_actions(paths["a.png"]))
            self.assertIn("decompile", c._allowed_actions(paths["a.exe"]))

    def test_state_exposes_allowed_actions(self):
        import tempfile
        c = Conductor()
        with tempfile.TemporaryDirectory() as tmp:
            zip_path = os.path.join(tmp, "pkg.zip")
            with open(zip_path, "wb") as fp:
                fp.write(b"PK\x03\x04")
            state = c._state(_Ws(tmp), "misc", [zip_path], set())
            self.assertIn("archive_extract", state["targets"][0]["allowed"])
            tried = {("archive_extract", os.path.realpath(zip_path))}
            state = c._state(_Ws(tmp), "misc", [zip_path], tried)
            self.assertNotIn("archive_extract", state["targets"][0]["allowed"])

    def test_disabled_without_config(self):
        """没有配置文件时必须全部默认关闭。

        旧用例断言「源码目录不存在 ai_config.json」，一旦本机为了融合测试放了配置
        就会误报；这里改成把配置目录指到空临时目录，验证默认值本身。
        """
        import tempfile
        from ctfbox.ai import config as aicfg
        old = aicfg.APP_DIR
        with tempfile.TemporaryDirectory() as tmp:
            aicfg.APP_DIR = tmp
            try:
                cfg = aicfg.ai_config()
                self.assertFalse(cfg["enabled"])
                self.assertFalse(cfg["conductor"])
                self.assertFalse(cfg["rerank"])
                self.assertFalse(ai_enabled())
                self.assertFalse(aicfg.conductor_enabled())
                self.assertFalse(aicfg.rerank_enabled())
            finally:
                aicfg.APP_DIR = old


if __name__ == "__main__":
    unittest.main()
