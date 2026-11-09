# -*- coding: utf-8 -*-
"""RAC 流水线编排：Recognize → Assemble → Command 一条龙。

用法（GUI / CLI 共用）：
    p = RacPipeline(log_cb=print)
    result = p.run(description="RSA 题 n=... e=65537 c=...", attachments=["task.zip"])

步骤：
  1. Recognize 识别题目（描述 + 附件类型 + 附件文本参数）
  2. （可选）附件跑一键分析（Dispatcher，深度受限）→ 解码文本再提参数、收集直接 flag
  3. 脚本库评分匹配 top-N
  4. 逐候选装配 + 静默执行，命中 flag 即成功；全部失败输出失败报告与手动指引
  5. 全过程落盘 workspace/rac_runs/<run>/{脚本副本, params.txt, meta.json, report.txt}
"""
import os
import time
from dataclasses import dataclass, field
from typing import Callable, List, Optional

from ..common import save_text
from .recognizer import TaskCard, recognize
from .matcher import ScriptIndex
from .assembler import assemble, write_meta, new_run_dir
from .runner import run_script_entry, DEFAULT_TIMEOUT


@dataclass
class RacResult:
    task: TaskCard = field(default_factory=TaskCard)
    matches: list = field(default_factory=list)          # [(score, ScriptEntry)]
    runs: list = field(default_factory=list)             # [RunResult]
    flags: List[str] = field(default_factory=list)
    success: bool = False
    workdir: str = ""
    meta_path: str = ""
    report_path: str = ""
    started: str = ""
    finished: str = ""


class RacPipeline:
    def __init__(self, log_cb: Callable[[str], None] = print,
                 timeout_per_script: int = DEFAULT_TIMEOUT,
                 top_n: int = 5,
                 analyze_attachments: bool = True,
                 analyze_depth: int = 2,
                 index: Optional[ScriptIndex] = None,
                 cancel_check: Optional[Callable[[], bool]] = None):
        self.log = log_cb
        self.timeout = timeout_per_script
        self.top_n = top_n
        self.analyze_attachments = analyze_attachments
        self.analyze_depth = analyze_depth
        self.index = index or ScriptIndex()
        self.cancel_check = cancel_check or (lambda: False)

    # ------------------------------------------------------------------
    def _analyze_attachment(self, path: str):
        """附件跑受限一键分析，返回 (flags, texts)。失败不影响主流程。"""
        flags, texts = [], []
        try:
            if os.path.getsize(path) > 30 * 1024 * 1024:
                self.log(f"[*] 附件过大(>30MB)，跳过深度分析: {os.path.basename(path)}")
                return flags, texts
            from ..dispatcher import Dispatcher
            d = Dispatcher(log_cb=lambda m: self.log("    " + str(m)),
                           max_depth=self.analyze_depth)
            rep = d.run(path)
            for _p, f in rep.flags():
                if f not in flags:
                    flags.append(f)
            # 收集解码/扫描类 finding 的文本作为补充参数来源
            for fnd in rep.findings:
                if fnd.level in ("ok", "info") and isinstance(fnd.detail, str) \
                        and fnd.detail and fnd.title not in ("文件指纹", "文件头(Hex)"):
                    texts.append(fnd.detail[:200_000])
        except Exception as e:
            self.log(f"[!] 附件深度分析失败（继续主流程）: {e}")
        return flags, texts

    # ------------------------------------------------------------------
    def run(self, description: str = "", attachments: List[str] = None,
            extra_params: dict = None) -> RacResult:
        """extra_params：手动补充参数（在识别后立即并入任务卡，参与脚本匹配）。"""
        result = RacResult(started=time.strftime("%Y-%m-%d %H:%M:%S"))
        self.log("=" * 64)
        self.log("[RAC] 启动自动化流水线：Recognize → Assemble → Command")
        self.log("=" * 64)

        # ---- R1：识别 ----
        self.log("[R] 第一步：识别题目与参数 ...")
        card = recognize(description, attachments or [])
        if extra_params:
            card.params.update(extra_params)
            self.log(f"[R] 手动补充参数: {', '.join(f'{k}={str(v)[:40]}' for k, v in extra_params.items())}")
        extra_texts: List[str] = []
        if attachments:
            for p in card.attachments:
                if self.cancel_check():
                    self.log("[!] 已取消"); return result
                self.log(f"[R] 深度分析附件: {os.path.basename(p)}")
                fl, tx = self._analyze_attachment(p)
                if fl:
                    card.direct_flags = list(dict.fromkeys(card.direct_flags + fl))
                extra_texts.extend(tx)
        if extra_texts:
            # 二次参数提取（把解码结果里的 n/e/c 等收进来）
            from .recognizer import extract_params
            deep = extract_params("\n".join(extra_texts))
            for k, v in deep.items():
                card.params.setdefault(k, v)
            card.category, card.confidence, card.scores = \
                (lambda t: (t.category, t.confidence, t.scores))(
                    recognize(description, card.attachments, extra_texts))
        result.task = card
        self.log(f"[R] 题型判定: {card.category}（置信度 {card.confidence:.0%}）")
        if card.scores:
            tops = sorted(card.scores.items(), key=lambda kv: -kv[1])[:3]
            self.log(f"[R] 各类评分: " + ", ".join(f"{k}={v:.0f}" for k, v in tops if v > 0))
        if card.params:
            self.log("[R] 提取参数:")
            for k, v in card.params.items():
                s = str(v)
                self.log(f"      {k} = {s[:80]}{'...' if len(s) > 80 else ''}")
        if card.attachment_types:
            self.log("[R] 附件类型: " + ", ".join(
                f"{os.path.basename(a)} → {t}" for a, t in
                zip(card.attachments, card.attachment_types)))
        if card.direct_flags:
            self.log("[!!!] 题目/附件中已直接发现 flag: " + "; ".join(card.direct_flags))
            result.flags = list(card.direct_flags)
            result.success = True

        run_dir = new_run_dir(card.category or "rac")
        result.workdir = run_dir

        if result.success:
            # 直接命中也要把候选与报告写好
            self.index.build(self.log)
            result.matches = self.index.match(card, top_n=self.top_n)
            result.meta_path = write_meta(run_dir, card, result.matches, result.runs)
            result.finished = time.strftime("%Y-%m-%d %H:%M:%S")
            result.report_path = self._write_report(result)
            return result

        # ---- A：匹配脚本 ----
        if self.cancel_check():
            self.log("[!] 已取消"); return result
        self.log("[A] 第二步：脚本库评分匹配 ...")
        self.index.build(self.log)
        matches = self.index.match(card, top_n=self.top_n)
        result.matches = matches
        if not matches:
            self.log("[!] 未匹配到可执行脚本，请改用「脚本库」页手动检索，或补充题目参数")
            result.finished = time.strftime("%Y-%m-%d %H:%M:%S")
            result.report_path = self._write_report(result)
            return result
        for i, (score, e) in enumerate(matches, 1):
            dep = "" if e.deps_ok else f"（缺依赖 {','.join(e.missing_deps)}，仍将尝试）"
            self.log(f"    #{i} [{score:.0f}分] {e.name} — {e.title}{dep}")

        # ---- C：依序执行 ----
        self.log(f"[C] 第三步：依序执行 top{len(matches)} 候选（命中即止，单脚本限时 {self.timeout}s）...")
        for i, (score, e) in enumerate(matches, 1):
            if self.cancel_check():
                self.log("[!] 已取消"); break
            self.log("-" * 60)
            self.log(f"[C] 运行候选 #{i}: {e.name} ({e.title})")
            try:
                asm = assemble(e, card, run_dir)
            except Exception as ex:
                self.log(f"[!] 装配失败，跳过: {ex}")
                continue
            for note in asm.notes:
                self.log("    " + note)
            if asm.missing:
                self.log(f"    [!] 参数不全（{', '.join(asm.missing)}），仍按已有参数尝试")
            r = run_script_entry(asm.script_path, asm.arglist, run_dir,
                                 timeout=self.timeout)
            result.runs.append(r)
            state = "✔ 命中" if r.flags else ("✖ 超时" if r.timed_out else
                                              ("✔ 完成" if r.ok else "✖ 失败"))
            self.log(f"    结果: {state}  退出码={r.exit_code}  耗时={r.elapsed:.1f}s")
            if r.error:
                self.log(f"    [!] {r.error}")
            if r.flags:
                self.log(f"    [!!!] 提取到 flag: {'; '.join(r.flags)}")
                result.flags = list(dict.fromkeys(result.flags + r.flags))
                result.success = True
                break
            out = r.output.strip()
            if out:
                for ln in out.splitlines()[:14]:
                    self.log("    | " + ln[:160])
                if len(out.splitlines()) > 14:
                    self.log(f"    | ...(共 {len(out.splitlines())} 行，完整输出见运行目录)")

        # ---- 收尾 ----
        result.flags = list(dict.fromkeys(result.flags + card.direct_flags))
        result.meta_path = write_meta(run_dir, card, result.matches, result.runs)
        result.finished = time.strftime("%Y-%m-%d %H:%M:%S")
        result.report_path = self._write_report(result)
        self.log("=" * 64)
        if result.success:
            self.log(f"[RAC] 完成 ✔  flag: {'; '.join(result.flags)}")
        else:
            self.log("[RAC] 自动流程未能直接拿到 flag（脚本输出与过程已保存，可手动跟进）")
        self.log(f"[RAC] 运行目录: {run_dir}")
        if result.report_path:
            self.log(f"[RAC] 报告文件: {result.report_path}")
        self.log("=" * 64)
        return result

    # ------------------------------------------------------------------
    def _write_report(self, result: RacResult) -> str:
        lines = ["魔盒-CTF RAC 自动化流水线报告",
                 f"开始: {result.started}   结束: {result.finished}",
                 "=" * 60]
        card = result.task
        lines.append(f"题型判定: {card.category}（置信度 {card.confidence:.0%}）")
        lines.append("分类评分: " + ", ".join(
            f"{k}={v:.0f}" for k, v in sorted(card.scores.items(), key=lambda kv: -kv[1]) if v > 0))
        lines.append("")
        lines.append("[题目描述]")
        lines.append((card.description or "(空)")[:3000])
        lines.append("")
        lines.append("[附件]")
        for a, t in zip(card.attachments, card.attachment_types):
            lines.append(f"  {a}  ({t})")
        if not card.attachments:
            lines.append("  (无)")
        lines.append("")
        lines.append("[提取参数]")
        for k, v in card.params.items():
            lines.append(f"  {k} = {str(v)[:200]}")
        lines.append("")
        lines.append("[候选脚本]")
        for i, (score, e) in enumerate(result.matches, 1):
            dep = "" if e.deps_ok else f"  缺依赖:{','.join(e.missing_deps)}"
            lines.append(f"  #{i} [{score:.0f}] {e.name} — {e.title}{dep}")
            lines.append(f"      简介: {e.brief[:150]}")
            lines.append(f"      需要参数: {', '.join(e.needed_params) or '(无)'}")
        lines.append("")
        lines.append("[执行记录]")
        for i, r in enumerate(result.runs, 1):
            lines.append(f"  --- 运行 {i}: {os.path.basename(r.script)} ---")
            lines.append(f"  cmd: {r.cmd}")
            lines.append(f"  退出码: {r.exit_code}   耗时: {r.elapsed:.1f}s   "
                         f"{'超时' if r.timed_out else ('有flag' if r.flags else '正常')}")
            if r.error:
                lines.append(f"  错误: {r.error}")
            out = r.summary()
            if out.strip():
                lines.append("  输出:")
                for ln in out.splitlines()[:200]:
                    lines.append("    " + ln)
        lines.append("")
        lines.append(f"[最终 flag] {'; '.join(result.flags) if result.flags else '(未提取到)'}")
        lines.append("")
        lines.append("[手动跟进建议]")
        if not result.success:
            lines.append("  1. 用「📚 脚本库」页按题型检索脚本，手动填参执行")
            lines.append("  2. 用「一键分析」拖入附件看完整线索")
            lines.append("  3. crypto 题可打开 scripts/library/crypto/rsa_all_in_one.py 手动填 PARAMS")
        path = os.path.join(result.workdir, "report.txt")
        try:
            save_text(path, "\n".join(lines))
            return path
        except Exception:
            return ""
