# -*- coding: utf-8 -*-
"""v4.1.0 自动化架构优化回归测试。

覆盖：
  1. 版本号单一来源（ctfbox.__version__ → autopilot.VERSION → result.json → PE 版本资源）
  2. 统一运行产物目录（稳定路径 + 滚动清理，替代 hash() 随机目录）
  3. 编排阶段顺序：白名单脚本先于深度模块；命中强 flag 后不再跑重模块
  4. RAC 脚本执行器：超时终止进程树（含孙进程）＋ 中文输出不乱码
  5. 平台客户端：非 JSON 响应（登录态失效）抛 PlatformError 而不是崩栈
"""
import os
import shutil
import sys
import tempfile
import time
import unittest

import ctfbox
from ctfbox import common, versioning
from ctfbox.autopilot import VERSION as AP_VERSION
from ctfbox.autopilot import workspace as wsmod
from ctfbox.autopilot.models import ToolResult
from ctfbox.autopilot.orchestrator import AutoPilot
from ctfbox.platforms import ctfd
from ctfbox.rac import runner


class TestVersionSingleSource(unittest.TestCase):
    def test_autopilot_version_follows_package(self):
        self.assertEqual("v" + ctfbox.__version__, AP_VERSION)
        self.assertNotIn("3.7", AP_VERSION)

    def test_result_json_version_matches(self):
        tmp = tempfile.mkdtemp(prefix="mohe_ver_")
        try:
            ws = wsmod.TaskWorkspace("test", "sample", root=tmp)
            res = ws.finalize({})
            self.assertEqual(ctfbox.__version__, res["version"])
            ws.close()
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


class TestNamingConvention(unittest.TestCase):
    """命名规范：产品名固定 `魔盒-CTF`（大写 CTF），完整名 `魔盒-CTF v4.1.0`。"""

    def test_app_name_is_uppercase_ctf(self):
        self.assertEqual("魔盒-CTF", versioning.APP_NAME)
        self.assertNotIn("魔盒-ctf", versioning.APP_NAME)
        self.assertEqual("魔盒-CTF " + versioning.version_tag(), versioning.app_title())

    def test_pe_resource_uses_new_name(self):
        text = versioning.render_version_info()
        self.assertIn("'OriginalFilename', '魔盒-CTF.exe'", text)
        self.assertIn("'ProductName', '魔盒-CTF", text)
        self.assertNotIn("魔盒-ctf", text)

    def test_ui_theme_follows_versioning(self):
        from ctfbox import ui_theme
        self.assertEqual(versioning.APP_NAME, ui_theme.APP_NAME)
        self.assertEqual(versioning.version_tag(), ui_theme.APP_VERSION)

    def test_version_tag_and_tuple(self):
        self.assertEqual("v" + ctfbox.__version__, versioning.version_tag())
        vt = versioning.version_tuple()
        self.assertEqual(4, len(vt))
        self.assertEqual(ctfbox.__version__, ".".join(str(x) for x in vt[:3]))


class TestVersionInfoResource(unittest.TestCase):
    """PE 版本资源必须由源码版本派生，不得手写（历史 bug：长期停在 3.7.0.0）。"""

    def test_pe_resource_matches_package(self):
        text = versioning.render_version_info()
        dot = ".".join(str(x) for x in versioning.version_tuple())
        self.assertIn("filevers=%s" % (versioning.version_tuple(),), text)
        self.assertEqual(2, text.count("'FileVersion', '%s'" % dot),
                         "中英双 StringTable 都要写当前版本")
        self.assertEqual(2, text.count("'ProductVersion', '%s'" % dot))
        self.assertNotIn("3.7.0.0", text)

    def test_write_is_idempotent(self):
        tmp = tempfile.mkdtemp(prefix="mohe_vi_")
        try:
            path = os.path.join(tmp, "version_info.txt")
            versioning.write_version_info(path)
            first = os.path.getmtime(path)
            versioning.write_version_info(path)
            self.assertEqual(first, os.path.getmtime(path),
                             "内容未变时不应重写（避免每次打包都脏工作区）")
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


class TestScriptOrder(unittest.TestCase):
    """脚本库选择顺序：便宜的确定性脚本先跑，命中即止才能省下大把预算。"""

    def test_select_sorts_by_cost(self):
        from ctfbox.autopilot import scriptlib
        ids = [s.id for s in scriptlib.select(
            ["zip_crc_crack", "hash_identify", "pcap_http_extract", "jwt_crack"])]
        self.assertEqual(["hash_identify", "jwt_crack",
                          "zip_crc_crack", "pcap_http_extract"], ids,
                         "最便宜的 hash_identify 必须第一个跑；同为 120s 的两个脚本保持判型顺序")

    def test_equal_cost_keeps_triage_order(self):
        from ctfbox.autopilot import scriptlib
        ids = [s.id for s in scriptlib.select(["file_carver", "rsa_all_in_one"])]
        self.assertEqual(["file_carver", "rsa_all_in_one"], ids, "等代价时须保持判型顺序")


class TestEmbeddedToken(unittest.TestCase):
    """正文里夹一串 base64 —— 真题极常见，旧实现整段 auto_decode 命中 0。"""

    TEXT = ("题目配图说明：flag 藏在下方字符串里。\n"
            "ZmxhZ3twYWNrYWdlZF9zbW9rZV92NDF9\n"
            "备注：本文件仅用于冒烟验证。\n")

    def test_decodes_token_inside_prose(self):
        from ctfbox.autopilot.tools import codes
        res = codes.decode_chain(self.TEXT.encode("utf-8"))
        values = [c.value for c in res.candidates if c.confidence >= 0.9]
        self.assertIn("flag{packaged_smoke_v41}", values, res.summary)

    def test_no_false_flag_from_random_text(self):
        from ctfbox.autopilot.tools import codes
        res = codes.decode_chain(b"hello world, nothing encoded here at all\n")
        self.assertEqual([], [c.value for c in res.candidates if c.confidence >= 0.9])


class TestClassicalNoise(unittest.TestCase):
    """古典分析不能把原文整段当候选刷屏，也不能挤掉 flag 形态的候选。"""

    TEXT = ("题目配图说明：flag 藏在下方字符串里。\n"
            "ZmxhZ3twYWNrYWdlZF9zbW9rZV92NDF9\n"
            "备注：本文件仅用于冒烟验证。\n")

    def test_original_text_is_not_a_candidate(self):
        from ctfbox.autopilot.tools import classical
        res = classical.analyze(self.TEXT.encode("utf-8"))
        body = self.TEXT.strip()
        self.assertNotIn(body, [c.value for c in res.candidates])

    def test_clue_candidates_are_single_line_and_capped(self):
        from ctfbox.autopilot.tools import classical
        res = classical.analyze(self.TEXT.encode("utf-8"))
        clues = [c for c in res.candidates if "\n" not in c.value]
        self.assertEqual(len(res.candidates), len(clues), "线索候选必须压成单行")
        self.assertLessEqual(len(res.candidates), 12)
        self.assertLessEqual(len([c for c in res.candidates
                                  if not c.value.startswith(("flag{", "ctf{"))]), 6)


class TestRunDir(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="mohe_run_")
        self.old_runs, self.old_run = common.RUNS_DIR, common._RUN_DIR
        common.RUNS_DIR = os.path.join(self.tmp, "runs")
        common._RUN_DIR = None

    def tearDown(self):
        common.RUNS_DIR, common._RUN_DIR = self.old_runs, self.old_run
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_stable_within_process(self):
        first = common.new_run_dir("out")
        second = common.new_run_dir("out")
        self.assertEqual(first, second, "同一进程内必须复用同一产物根目录")

    def test_prune_keeps_recent(self):
        os.makedirs(common.RUNS_DIR, exist_ok=True)
        for i in range(20):
            path = os.path.join(common.RUNS_DIR, "old_%02d" % i)
            os.makedirs(path)
            os.utime(path, (1000000 + i, 1000000 + i))
        common.new_run_dir()          # 触发滚动清理
        left = [n for n in os.listdir(common.RUNS_DIR)
                if os.path.isdir(os.path.join(common.RUNS_DIR, n))]
        self.assertLessEqual(len(left), common._RUN_KEEP + 1,
                             "运行目录应只保留最近若干次，实际 %d" % len(left))


class TestStageOrder(unittest.TestCase):
    """用桩替换重模块，验证「便宜的先跑、命中即收敛」。"""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="mohe_order_")
        self.old_ws = wsmod.WORKSPACE
        wsmod.WORKSPACE = os.path.join(self.tmp, "workspace")
        from ctfbox.autopilot import orchestrator as orch
        self.orch = orch
        self.calls = []
        self._saved = (orch.deepmisc.analyze, orch.scriptrun.prepare,
                       orch.scriptrun.run)

    def tearDown(self):
        (self.orch.deepmisc.analyze, self.orch.scriptrun.prepare,
         self.orch.scriptrun.run) = self._saved
        wsmod.WORKSPACE = self.old_ws
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _stub(self):
        calls = self.calls

        def fake_deep(path, category="unknown", **kw):
            calls.append("deep." + str(category))
            return ToolResult(tool="deep." + str(category), ok=False, summary="stub")

        def fake_prepare(spec, ctx):
            return ["stub"], ""

        def fake_run(spec_id, path, workdir, **kw):
            calls.append("script." + str(spec_id))
            return ToolResult(tool="script." + str(spec_id), ok=True, summary="stub")

        self.orch.deepmisc.analyze = fake_deep
        self.orch.scriptrun.prepare = fake_prepare
        self.orch.scriptrun.run = fake_run

    def _write(self, name, text):
        path = os.path.join(self.tmp, name)
        with open(path, "w", encoding="utf-8") as fp:
            fp.write(text)
        return path

    def test_scripts_run_before_deep_modules(self):
        self._stub()
        # 用「读参数 + 反序列化」特征触发 web_source 判型（会排 deep_text + 白名单脚本）；
        # 不写 system($_GET[...]) 这类组合，避免被测环境的样本内容拦截误伤。
        path = self._write("source.php",
                           "<?php\n$id = $_GET['id'];\nunserialize($data);\n?>\n")
        AutoPilot().run_file(path)
        kinds = [c.split(".")[0] for c in self.calls]
        self.assertIn("script", kinds, self.calls)
        self.assertIn("deep", kinds, self.calls)
        self.assertLess(kinds.index("script"), kinds.index("deep"),
                        "白名单脚本必须先于深度模块执行：%s" % self.calls)

    def test_strong_flag_skips_heavy_stages(self):
        self._stub()
        path = self._write("hit.php",
                           "<?php\n// flag{php_inline_hit}\n$id = $_GET['id'];\n?>\n")
        res = AutoPilot().run_file(path)
        self.assertTrue(res["success"], res.get("candidates"))
        self.assertEqual([], [c for c in self.calls if c.split(".")[0] in ("deep", "script")],
                         "已命中强 flag 仍执行了重模块/脚本：%s" % self.calls)


class TestRacRunner(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="mohe_runner_")

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _script(self, name, body):
        path = os.path.join(self.tmp, name)
        with open(path, "w", encoding="utf-8") as fp:
            fp.write(body)
        return path

    def test_utf8_output(self):
        script = self._script("cn.py", "print('中文输出 OK')\n")
        res = runner.run_script_entry(script, [], self.tmp, timeout=30)
        self.assertFalse(res.timed_out, res.error)
        self.assertEqual(0, res.exit_code, res.output)
        self.assertIn("中文输出 OK", res.output)

    def test_timeout_kills_grandchildren(self):
        marker = os.path.join(self.tmp, "grandchild_alive.txt")
        # 生成脚本里必须用正斜杠：反斜杠在非 raw 的双引号字符串里会被当成转义
        # （\U 开头的路径会直接 SyntaxError），Windows 同样接受正斜杠。
        marker_lit = marker.replace("\\", "/")
        spawner = self._script("spawn.py", (
            "import subprocess, sys, time\n"
            "subprocess.Popen([sys.executable, '-c',\n"
            "    \"import time,pathlib;time.sleep(6);\"\n"
            "    \"pathlib.Path(r'%s').write_text('alive')\"])\n"
            "time.sleep(60)\n") % marker_lit)
        res = runner.run_script_entry(spawner, [], self.tmp, timeout=3)
        self.assertTrue(res.timed_out, "超时未被识别")
        self.assertLess(res.elapsed, 30, "超时后未及时返回")
        time.sleep(8)
        self.assertFalse(os.path.exists(marker),
                         "孙进程未被终止（超时后仍在运行并写了标记文件）")


class _HtmlResp:
    status_code = 200
    text = "<html><body>Please login</body></html>"

    def json(self):
        raise ValueError("Expecting value")


class TestPlatformJson(unittest.TestCase):
    def test_non_json_raises_platform_error(self):
        with self.assertRaises(ctfd.PlatformError) as ctx:
            ctfd._json_body(_HtmlResp(), "题目列表获取失败")
        self.assertIn("非 JSON", str(ctx.exception))

    def test_wait_ready_rejects_empty_url(self):
        cli = ctfd.CTFdPlatform(base="https://example.invalid")
        info = cli.wait_ready("", timeout=1)
        self.assertFalse(info["ready"])
        self.assertIn("URL", info["probe"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
