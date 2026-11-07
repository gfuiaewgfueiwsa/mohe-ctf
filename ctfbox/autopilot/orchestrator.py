# -*- coding: utf-8 -*-
"""编排层（Agent 决策环）：题型分类 → 工具选择 → 执行 → 观察 → 下一轮。

约束：
  - 最大步数与总时限，超限即停并落盘已有结论；
  - 每个工具异常都记录并继续（失败回退），不中断整题；
  - 未知二进制只做静态分析（本机无隔离后端，不执行样本）。
"""
import json
import os
import re
import time

from . import VERSION, scriptlib, triage
from .. import modules_zipcrack
from .models import ToolResult
from .sandbox import detect as sandbox_detect, policy_text
from .scope import ScopeGuard
from .tools import (archive, base, binary, codes, crypto, deepmisc, ecc, ghidra,
                    hash as hashtool, pwnstatic, recon, rsa, scriptrun, stego,
                    webexploit, webprobe, xor)
from .workspace import TaskWorkspace

STRONG_FLAG_CONF = 0.8
IMAGE_EXTS = (".png", ".jpg", ".jpeg", ".bmp", ".gif", ".webp", ".tif", ".tiff")


def _is_image(path: str) -> bool:
    return os.path.basename(path).lower().endswith(IMAGE_EXTS)


def _xor_key_hints(res) -> list:
    """把异或工具反推得到的密钥转成对称密码的候选密钥。"""
    if not res or not isinstance(res.data, dict):
        return []
    out = []
    for group in ("xor.single", "xor.repeating", "xor.crib"):
        for item in (res.data.get(group, {}) or {}).get("top", [])[:8]:
            key = item.get("key")
            if not isinstance(key, str):
                continue
            if key.startswith("0x"):
                try:
                    out.append(bytes([int(key, 16)]))
                except ValueError:
                    continue
            else:
                out.append(key)
    return out


class AutoPilot:
    def __init__(self, allow_private: bool = False, allow_hosts=None,
                 deep: bool = False, render: bool = False,
                 max_steps: int = 20, timeout: int = 300, log=None,
                 user_data: str = "", cdp: str = "", headless: bool = True,
                 exploit: bool = False, exploit_interval: float = 0.55,
                 exploit_max_requests: int = 120, hints=None, meta=None):
        self.hints = [str(h) for h in (hints or []) if h]
        self.meta = dict(meta or {})
        self.allow_private = allow_private
        self.allow_hosts = allow_hosts or []
        self.deep = deep
        self.render = render
        self.user_data = user_data
        self.cdp = cdp
        self.headless = headless
        self.exploit = exploit
        self.exploit_interval = exploit_interval
        self.exploit_max_requests = exploit_max_requests
        self.max_steps = max_steps
        self.timeout = timeout
        self.log = log or (lambda m: None)
        self.step = 0
        self.deadline = 0.0
        self.ws = None

    # ------------------------------------------------------------------
    def _reset_budget(self):
        self.step = 0
        self.deadline = time.time() + self.timeout

    def _can_run(self) -> bool:
        return self.step < self.max_steps and time.time() < self.deadline

    def _run(self, tool_fn, action: str, label: str = ""):
        if not self._can_run():
            self.ws.notes.append("达到步数/时间预算，停止扩展分析")
            return None
        self.step += 1
        tool_name = label or getattr(tool_fn, "__name__", "tool")
        try:
            res = tool_fn()
        except Exception as exc:
            res = ToolResult(tool=tool_name, ok=False, summary=f"工具异常: {exc}")
            self.ws.log(f"[{tool_name}] 异常: {exc}", "warn")
        self.ws.add_candidates(res.candidates)
        self.ws.record(self.step, res.tool or tool_name, action, res)
        self.ws.log(f"[{self.step}] {res.tool or tool_name}: {res.summary}")
        for note in res.notes:
            self.ws.log(f"  - {note}", "note")
        return res

    # ------------------------------------------------------------------
    def run_file(self, path: str) -> dict:
        self._reset_budget()
        if not os.path.isfile(path):
            raise FileNotFoundError(path)
        self.ws = TaskWorkspace("file", os.path.basename(path))
        ws = self.ws
        ws.log(f"{VERSION} AutoPilot 启动 | 输入={path} | 最大步数={self.max_steps}")
        saved = ws.copy_input(path)
        st = base.status()
        sandbox = sandbox_detect()
        ws.notes.append("沙箱：" + policy_text(sandbox))
        for hint in base.missing_hints(st):
            ws.notes.append(hint)
        ws.record(0, "orchestrator", "启动与能力探测",
                  {"tool_status": st, "sandbox": sandbox})

        ident = self._run(lambda: recon.identify(saved), "识别文件类型")
        if ident is None:
            ws.notes.append("识别阶段被预算中断")
            return self._finalize("file", path, {})
        info = ident.data
        raw, size = None, os.path.getsize(saved)
        if size <= 8 * 1024 * 1024:
            try:
                with open(saved, "rb") as fp:
                    raw = fp.read()
            except Exception as exc:
                ws.log(f"读取输入失败: {exc}", "warn")
        tri = triage.file_triage(saved, info, raw, hints=self.hints, meta=self.meta)
        category = tri.category or info.get("category", "unknown")
        ws.log(f"[triage] 首层判型: {tri.summary()}")
        ws.notes.append("首层判型：" + tri.summary())
        ws.record(0, "triage", "首层判型（主考点/阶段/自动脚本）", tri.to_dict())

        self._run(lambda: recon.fingerprint(saved), "文件哈希指纹")
        strings_res = None
        if "strings" in tri.stages and size <= 64 * 1024 * 1024:
            strings_res = self._run(lambda: recon.strings_scan(saved), "strings + flag 扫描")
        else:
            ws.notes.append("strings 阶段按判型跳过（%s）" % tri.subtype)
        if "entropy" in tri.stages:
            self._run(lambda: recon.entropy_blocks(saved), "分块熵检测")

        # v3.3.0：RAR5/7z/ZIP 通过 7-Zip 解包并递归分析（成员只读，不执行）
        archive_results = []
        if "archive" in tri.stages or archive.is_archive(saved):
            archive_results = self._archive_chain(saved)
            if archive_results:
                total_files = sum(len((r.data or {}).get("files") or [])
                                  for r in archive_results if r)
                ws.notes.append("压缩包递归分析：%d 层，解出 %d 个文件；明细见 artifacts/extracted" % (
                    len(archive_results), total_files))
                # 成员里的 ECC 坐标（隐去 p/a/b）：只读文本直接跑异常曲线 HNP
                for ares in archive_results:
                    if not self._can_run():
                        break
                    ecc_done = False
                    for member in ((ares.data or {}).get("files") or [])[:40]:
                        try:
                            if os.path.getsize(member) > 4 * 1024 * 1024:
                                continue
                            with open(member, "r", encoding="utf-8", errors="ignore") as fp:
                                mtext = fp.read()
                        except Exception:
                            continue
                        if ecc.looks_like(mtext):
                            ecc_res = self._run(
                                lambda t=mtext: ecc.analyze_text(t),
                                "压缩包成员 ECC 坐标攻击")
                            if ecc_res and ecc_res.ok:
                                ws.notes.append("ECC：" + ecc_res.summary)
                            ecc_done = True
                            break
                    if ecc_done:
                        break

        # 图片隐写：压缩包成员复用恢复出的口令，独立图片使用题名/文件名派生候选
        image_found = False
        image_jobs, seen_images = [], set()
        if "stego_image" in tri.stages and os.path.isfile(saved):
            image_jobs.append((saved, None))
            seen_images.add(os.path.realpath(saved))
        for ares in archive_results:
            pwd = (ares.data or {}).get("password")
            for member in ((ares.data or {}).get("files") or [])[:40]:
                if not _is_image(member):
                    continue
                real = os.path.realpath(member)
                if real in seen_images:
                    continue
                seen_images.add(real)
                image_jobs.append((member, pwd))
        for image_path, pwd in image_jobs[:6]:
            if not self._can_run():
                ws.notes.append("达到步数/时间预算，剩余图片未做隐写分析")
                break
            pw_list = ([pwd] if pwd else []) + modules_zipcrack.password_candidates(
                image_path, hints=self.hints)
            stego_res = self._run(
                lambda p=image_path, pw=pw_list: stego.analyze(
                    p, ws.artifacts_dir, passwords=pw),
                "图片隐写分析（%s）" % os.path.basename(image_path))
            if stego_res and stego_res.ok:
                ws.notes.append("隐写：" + stego_res.summary)
                if any(c.confidence >= 0.9 for c in stego_res.candidates):
                    image_found = True

        # ---- 深度模块：复用 dispatcher 全量方向能力（崩溃隔离子进程）----
        deep_results = []
        deep_map = {
            "deep_text": "text", "deep_traffic": "capture",
            "deep_forensic": "forensic", "deep_document": "document",
            "deep_audio": "media", "deep_video": "media",
            "deep_database": "database", "deep_reverse": "executable",
            "deep_archive": "archive", "deep_unknown": "unknown",
            "deep_crypto": "crypto",
        }
        deep_done = set()
        for stage_name in tri.stages:
            deep_cat = deep_map.get(stage_name)
            if not deep_cat or deep_cat in deep_done:
                continue
            if not self._can_run():
                ws.notes.append("达到步数/时间预算，剩余深度模块跳过")
                break
            remain = int(self.deadline - time.time())
            if remain < 20:
                ws.notes.append("时间预算不足，%s 深度模块跳过" % deep_cat)
                continue
            deep_done.add(deep_cat)
            budget = max(20, min(180, remain - 10))
            deep_res = self._run(
                lambda c=deep_cat, b=budget: deepmisc.analyze(saved, c, timeout=b),
                "深度模块：%s（取证/流量/文档/音频/逆向/数据库）" % deep_cat,
                label="deep." + deep_cat)
            if deep_res:
                deep_results.append(deep_res)
                if deep_res.candidates:
                    ws.notes.append("深度模块命中：%s" % deep_res.summary)

        is_binary = category in ("executable", "unknown") and not info.get("is_text")
        ghidra_res = None
        strong_now = any(c.confidence >= 0.9 for c in ws.candidates)
        if "binary_struct" in tri.stages or (is_binary and info.get("ftype", "").startswith(("PE", "ELF"))):
            self._run(lambda: binary.analyze(saved, deep=self.deep), "PE/ELF 结构解析")
        if "pwn_static" in tri.stages:
            self._run(lambda: pwnstatic.analyze(saved), "Pwn 静态定位")
        if "decompile" in tri.stages and not strong_now:
            if ghidra.available():
                budget_left = int(self.deadline - time.time()) - 20
                ghidra_res = self._run(
                    lambda: ghidra.decompile(saved, ws.artifacts_dir,
                                             timeout=max(60, min(180, budget_left))),
                    "Ghidra headless 反编译（主证据）")
            else:
                ws.notes.append("未检测到 Ghidra/Java，反编译跳过；" + ghidra.INSTALL_HINT)
            if not ghidra_res or not ghidra_res.ok:
                self._run(lambda: binary.r2_excerpt(saved), "radare2 反汇编摘录（Ghidra 回退）")
        elif "decompile" in tri.stages:
            ws.notes.append("已命中强 flag，反编译阶段跳过")

        skip_codes = "deep_text" in tri.stages
        if (raw is not None and "codes" in tri.stages and not skip_codes
                and (info.get("is_text") or category in ("text", "crypto", "misc"))):
            self._run(lambda: codes.decode_chain(raw), "多编码链自动解码")
        elif skip_codes:
            ws.notes.append("深度文本模块已覆盖解码链，跳过独立 codes 阶段")

        text_raw = ""
        if raw is not None and info.get("is_text"):
            text_raw = raw.decode("utf-8", "ignore")

        rsa_res = None
        if raw is not None and "rsa" in tri.stages and text_raw:
            rsa_res = self._run(lambda: rsa.analyze_text(text_raw),
                                "RSA 参数解析与攻击")
            if rsa_res and rsa_res.ok:
                ws.notes.append("RSA：" + rsa_res.summary)

        # 异常椭圆曲线：大量坐标点、隐去 p/a/b → 行列式求 p + Qp/Hensel + 正交格
        if raw is not None and "ecc" in tri.stages and text_raw:
            if ecc.looks_like(text_raw):
                ecc_res = self._run(lambda: ecc.analyze_text(text_raw),
                                    "异常椭圆曲线 HNP 攻击")
                if ecc_res and ecc_res.ok:
                    ws.notes.append("ECC：" + ecc_res.summary)

        if "hash" in tri.stages and info.get("is_text"):
            preview = "\n".join(
                (strings_res.data.get("strings", []) if strings_res else [])[:500]) or text_raw
            if preview:
                self._run(lambda: hashtool.analyze_text(preview), "哈希识别/弱爆破")

        # 原始数据已直接命中 flag 时跳过异或/对称试解，避免对已明文做无意义搜索
        found_direct = image_found or any(c.confidence >= 0.9 for c in ws.candidates)
        xor_res = None
        if "xor" in tri.stages:
            if found_direct:
                ws.notes.append("已命中强 flag，异或阶段跳过")
            elif raw is not None:
                xor_res = self._run(lambda: xor.analyze(raw), "异或暴力与密钥推断")
            else:
                ws.notes.append("文件过大，跳过全量异或暴力")
        else:
            ws.notes.append("异或阶段按判型跳过（无 XOR 线索）")

        crypto_res = None
        want_crypto = ("symmetric" in tri.stages or xor_res is not None or
                       tri.subtype in ("encrypted_container", "crypto_artifact"))
        if want_crypto and not found_direct and raw is not None:
            key_hints = _xor_key_hints(xor_res)
            crypto_res = self._run(
                lambda: crypto.analyze(raw, saved, hints=key_hints),
                "对称密码密钥候选试解")
            if crypto_res and crypto_res.ok:
                ws.notes.append("对称密码试解：" + crypto_res.summary)
        elif not want_crypto:
            ws.notes.append("对称密码试解按判型跳过（无加密线索）")

        # ---- 脚本库自动调用（白名单 + 参数模板）----
        script_results = self._run_scripts(saved, tri, raw, info)

        extra = {"category": category, "file_type": info.get("ftype"),
                 "identify": info, "sandbox": sandbox, "tool_status": st,
                 "triage": tri.to_dict()}
        if archive_results:
            extra["archive"] = [{
                "summary": r.summary,
                "dir": (r.data or {}).get("dir"),
                "format": (r.data or {}).get("format"),
                "files": (r.data or {}).get("files", [])[:50],
                "flags": (r.data or {}).get("flags", []),
                "nested": (r.data or {}).get("nested", []),
            } for r in archive_results if r]
        if deep_results:
            extra["deep"] = [{"tool": r.tool, "ok": r.ok, "summary": r.summary,
                              "flags": (r.data or {}).get("flags", [])}
                             for r in deep_results]
        if script_results:
            extra["scripts"] = [{"tool": r.tool, "ok": r.ok, "summary": r.summary,
                                 "artifacts": len(r.artifacts)}
                                for r in script_results if r]
        if ghidra_res and ghidra_res.ok:
            extra["ghidra_output"] = ghidra_res.data.get("out_path")
        if crypto_res and crypto_res.ok:
            extra["crypto_attempts"] = crypto_res.data.get("attempts", 0)
        return self._finalize("file", path, extra)

    # ------------------------------------------------------------------
    def run_url(self, url: str) -> dict:
        self._reset_budget()
        guard = ScopeGuard(authorized=True, allow_hosts=self.allow_hosts,
                           allow_private=self.allow_private)
        self.ws = TaskWorkspace("web", url)
        ws = self.ws
        ws.log(f"{VERSION} AutoPilot Web 模式 | 目标={url} | 授权=启动时《软件责任说明》已确认")
        if self.exploit:
            ws.log("Web 利用模块已启用：每个请求经地址校验 + 审计 + 限速")
        try:
            scope = guard.check(url)
        except Exception as exc:
            ws.log("范围校验失败: " + str(exc), "warn")
            ws.notes.append(str(exc))
            return self._finalize("web", url, {"scope_error": str(exc)})
        ws.record(0, "orchestrator", "授权与范围确认", scope)

        res = self._run(lambda: webprobe.probe(url, guard, log=ws.log,
                                               render=self.render,
                                               artifacts_dir=ws.artifacts_dir,
                                               user_data_dir=self.user_data,
                                               cdp_url=self.cdp,
                                               headless=self.headless),
                        "Web 指纹与入口探测")
        extra = {"scope": scope}
        if res:
            extra.update({"fingerprint": res.data.get("fingerprint"),
                          "spa": res.data.get("spa"),
                          "login_required": res.data.get("login_required"),
                          "suspicious": res.data.get("suspicious"),
                          "next_steps": res.data.get("next_steps"),
                          "browser": res.data.get("browser")})
            if res.data.get("login_required"):
                ws.notes.append("结论：目标需要登录，软件不代登录、不试密码；"
                                "登录态需由 --user-data/--cdp 提供")

        # ---- v3.3.0 Web 全量利用（声明闸门 + 双校验 + 审计）----
        exploit_data = None
        if self.exploit:
            try:
                session, _audit = webexploit.start(url, guard, ws, log=ws.log,
                                                   deep=self.deep,
                                                   max_requests=self.exploit_max_requests,
                                                   interval=self.exploit_interval,
                                                   hints=self.hints)
            except Exception as exc:
                ws.log("Web 利用会话初始化失败: %s" % exc, "warn")
                ws.notes.append("Web 利用会话初始化失败：%s" % exc)
            else:
                disc = self._run(session.discover, "Web 利用：入口发现",
                                 label="web.exploit.discover")
                if disc and disc.ok:
                    queue = list(session.plan())
                    done = set()
                    while queue:
                        name = queue.pop(0)
                        if name in done:
                            continue
                        done.add(name)
                        if not self._can_run():
                            ws.notes.append("达到步数/时间预算，剩余利用阶段未执行")
                            break
                        self._run(lambda p=name: session.phase(p),
                                  "Web 利用：" + name,
                                  label="web.exploit." + name)
                        if session.read_flags:
                            ws.notes.append("已通过文件读取取得 flag，剩余利用阶段跳过")
                            break
                        # 登录后识别出后台命令执行入口时，优先于 SQL 等重探测阶段
                        pri = getattr(session, "priority_phase", lambda: "")()
                        if pri and pri not in done and pri != name:
                            if pri in queue:
                                queue.remove(pri)
                            queue.insert(0, pri)
                        # 登录/源码泄露后可能出现新入口：动态追加阶段，反序列化优先
                        for extra_phase in session.plan():
                            if extra_phase in done or extra_phase in queue:
                                continue
                            if extra_phase == "deser":
                                queue.insert(0, extra_phase)
                            else:
                                queue.append(extra_phase)
                else:
                    ws.notes.append("入口发现失败，利用阶段未继续")
                try:
                    exploit_data = session.finish()
                except Exception as exc:
                    ws.log("利用结果落盘失败: %s" % exc, "warn")
                    exploit_data = {"session": True, "error": str(exc)}
                ws.add_candidates(session.candidates)
                if exploit_data:
                    extra["exploit"] = exploit_data
                    ws.notes.append(
                        "Web 利用审计：请求 %s/%s，审计 %s 条，发现 %s 项，"
                        "验证样本 %s 个；明细见任务 audit.jsonl 与 exploit_result.json" % (
                            exploit_data.get("requests", "?"),
                            exploit_data.get("budget", "?"),
                            (exploit_data.get("audit") or {}).get("entries", "?"),
                            len(exploit_data.get("findings") or []),
                            len(exploit_data.get("artifacts") or [])))
                    caps = exploit_data.get("capabilities") or {}
                    if not caps.get("ysoserial_ok"):
                        ws.notes.append("Java 反序列化：未找到 ysoserial，仅生成 URLDNS 探测流；"
                                        + (caps.get("install_hints") or {}).get("ysoserial", ""))
                    if not caps.get("php_ok"):
                        ws.notes.append("PHP 反序列化：未找到 php，phar 只做结构与签名校验；"
                                        + (caps.get("install_hints") or {}).get("php", ""))
        return self._finalize("web", url, extra)

    # ------------------------------------------------------------------
    def _archive_chain(self, path: str, depth: int = 0, seen=None) -> list:
        """解压一层并递归嵌套压缩包；步数由外层 _run 统一计。"""
        seen = seen if seen is not None else set()
        try:
            real = os.path.realpath(path)
        except Exception:
            real = path
        if real in seen or depth > archive.MAX_DEPTH:
            return []
        seen.add(real)
        res = self._run(lambda: archive.extract(path, self.ws.artifacts_dir,
                                                depth=depth, log=self.ws.log,
                                                hints=self.hints, deep=self.deep),
                        "压缩包解包与成员扫描（深度 %d）" % depth)
        if not res:
            return []
        out = [res]
        if not res.ok:
            return out
        nested = (res.data or {}).get("nested") or []
        for child in nested[:6]:
            if not self._can_run():
                self.ws.notes.append("达到步数/时间预算，剩余嵌套压缩包未分析")
                break
            if os.path.realpath(child) in seen:
                continue
            out.extend(self._archive_chain(child, depth + 1, seen))
        return out

    # ------------------------------------------------------------------
    def _run_scripts(self, path: str, tri, raw, info) -> list:
        """按判型清单调用白名单脚本；命中强 flag 即停止后续脚本。"""
        specs = scriptlib.select(tri.scripts)
        results = []
        if not specs:
            return results
        text = ""
        if raw is not None and info.get("is_text"):
            text = raw.decode("utf-8", "ignore")
        executed = 0
        for spec in specs:
            if executed >= 6:
                self.ws.notes.append("脚本数量达到上限，剩余 %d 个未执行" % (len(specs) - executed))
                break
            if not self._can_run():
                self.ws.notes.append("达到步数/时间预算，剩余脚本未执行")
                break
            if any(c.confidence >= 0.9 for c in self.ws.candidates):
                self.ws.notes.append("已命中强 flag，剩余 %d 个脚本跳过" % (len(specs) - executed))
                break
            remain = int(self.deadline - time.time())
            if remain < 15:
                self.ws.notes.append("时间预算不足，剩余脚本未执行")
                break
            workdir = os.path.join(self.ws.artifacts_dir, "scripts", spec.id)
            os.makedirs(workdir, exist_ok=True)
            ctx = {"file": os.path.abspath(path), "workdir": workdir,
                   "outdir": workdir, "text": text, "hints": list(self.hints)}
            args, why = scriptrun.prepare(spec, ctx)
            if not args:
                self.ws.notes.append("脚本 %s 未执行：%s" % (spec.id, why))
                continue
            res = self._run(
                lambda s=spec, w=workdir, r=remain, a=args: scriptrun.run(
                    s.id, path, w, text=text, hints=self.hints,
                    timeout=min(s.timeout, max(10, r - 5)), args=a),
                "脚本库：%s" % spec.description, label="script." + spec.id)
            results.append(res)
            executed += 1
            if res is not None and any(c.confidence >= 0.88 for c in res.candidates):
                self.ws.notes.append("脚本命中候选：%s" % res.summary)
                break
        if not any(c.confidence >= 0.9 for c in self.ws.candidates):
            self._follow_script_artifacts(results)
        return results

    def _follow_script_artifacts(self, results):
        """脚本雕刻/拆分出的图片与压缩包继续深挖，上限 2 图 + 1 包。"""
        files = []
        for res in results:
            for p in (res.artifacts if res else []) or []:
                if os.path.isfile(p) and p not in files:
                    files.append(p)
        for image_path in [p for p in files if _is_image(p)][:2]:
            if not self._can_run():
                return
            pw_list = modules_zipcrack.password_candidates(image_path, hints=self.hints)
            res = self._run(
                lambda p=image_path, pw=pw_list: stego.analyze(
                    p, self.ws.artifacts_dir, passwords=pw),
                "脚本产物图片隐写：%s" % os.path.basename(image_path))
            if res and any(c.confidence >= 0.9 for c in res.candidates):
                return
        for archive_path in [p for p in files if archive.is_archive(p)][:1]:
            if not self._can_run():
                return
            self._archive_chain(archive_path)

    # ------------------------------------------------------------------
    def _finalize(self, kind: str, target: str, extra: dict) -> dict:
        ws = self.ws
        ranked = ws.ranked_candidates()
        flags = [c for c in ranked if c.confidence >= STRONG_FLAG_CONF]
        success = bool(flags)
        if not success and ranked:
            ws.notes.append("存在低置信候选，需人工复核，未自动判定为 flag")

        if kind == "file":
            category = extra.get("category", "unknown")
            next_steps = self._next_steps_file(category, success)
        else:
            next_steps = list(extra.pop("next_steps", None) or [])
            if not next_steps:
                next_steps.append("未发现明显入口：扩大授权字典、检查 JS 接口与 robots")
            next_steps.append("仅限已授权靶场；所有命中需人工确认后再利用")

        ws.notes.extend([n for n in next_steps if n not in ws.notes])
        ws.notes = list(dict.fromkeys(ws.notes))
        try:
            if kind == "web":
                from .wp import write_web_wp
                wp_result = {
                    "success": success,
                    "target": target,
                    "candidates": [c.to_dict() for c in ranked],
                    "exploit": extra.get("exploit") or {},
                }
                task_wp, copy_wp, wp_data = write_web_wp(wp_result, self.meta, ws)
            else:
                from .wp import write_file_wp
                evidence = []
                try:
                    with open(ws.evidence_path, encoding="utf-8") as fp:
                        evidence = [json.loads(line) for line in fp if line.strip()]
                except Exception:
                    evidence = []
                wp_result = {
                    "success": success,
                    "target": target,
                    "workdir": ws.dir,
                    "candidates": [c.to_dict() for c in ranked],
                    "identify": extra.get("identify"),
                    "category": extra.get("category"),
                    "file_type": extra.get("file_type"),
                    "triage": extra.get("triage") or {},
                    "evidence_path": ws.evidence_path,
                    "log_path": ws.log_path,
                }
                task_wp, copy_wp, wp_data = write_file_wp(
                    wp_result, self.meta, ws, evidence=evidence)
            extra["wp"] = task_wp
            if copy_wp:
                extra["wp_copy"] = copy_wp
            extra["wp_format"] = wp_data.get("format")
            ws.notes.append("WP 已生成：%s" % task_wp)
        except Exception as exc:
            ws.log("WP 生成失败: %s" % exc, "warn")
        result = ws.finalize({
            "success": success,
            "target": target,
            "next_steps": next_steps,
            **extra,
        })
        self._write_report(result, ranked, next_steps)
        ws.close()
        self.log(f"[autopilot] 完成，工作区: {ws.dir}")
        return result

    def _next_steps_file(self, category: str, success: bool) -> list:
        steps = []
        if success:
            steps.append("已得强候选 flag：复核字符串上下文，确认不是 honeypot/干扰项")
        if category in ("executable", "reverse"):
            steps.append("继续用 r2/Ghidra 反编译 main/check；缺失 z3 时先补装再做约束求解")
            steps.append("本机无隔离后端：不要直接运行未知样本；如需动态调试先配 Docker/WSL")
        elif category in ("text", "crypto", "misc"):
            steps.append("若无结果：检查非标准编码/自定义码表，或用现有「编码解码」页手工链式尝试")
        elif category in ("image", "media", "archive", "forensic", "document"):
            steps.append("已识别为容器/媒体类：下一步用现有归档/隐写/取证模块深入")
        else:
            steps.append("题型不明确：补充题目描述可提升分类准确率，或人工指定工具")
        steps.append("证据链与中间结果在 workspace 任务目录，可直接复现")
        return list(dict.fromkeys(steps))

    def _write_report(self, result: dict, ranked, next_steps):
        ws = self.ws
        lines = [
            "# 魔盒-ctf %s 自动化报告" % VERSION, "",
            f"- 目标：`{result.get('target')}`",
            f"- 类型：{result.get('kind')} / {result.get('category', 'web')}",
            f"- 工作区：`{ws.dir}`",
            f"- 结论：**{'已得到强候选 flag' if result.get('success') else '未得到高置信 flag'}**",
            "", "## 候选 flag", "",
            "| flag | 置信度 | 来源 | 依据 |", "|---|---|---|---|",
        ]
        if ranked:
            for c in ranked[:10]:
                lines.append(f"| `{c.value}` | {c.confidence:.2f} | {c.source} | {c.reason} |")
        else:
            lines.append("| - | - | - | 未命中 |")
        lines += triage.triage_lines(result.get("triage") or
                                     (result.get("exploit") or {}).get("triage") or {})
        lines += ["", "## 下一步建议", ""]
        lines += [f"- {s}" for s in next_steps]
        if result.get("ghidra_output"):
            lines += ["", "## 反编译伪代码", "",
                      f"- Ghidra 输出：`{result['ghidra_output']}`"]
        lines += ["", "## 工具与边界", ""]
        lines += [f"- {n}" for n in ws.notes] or ["- 无"]
        if result.get("suspicious"):
            lines += ["", "## Web 可疑点", ""]
            for s in result["suspicious"][:20]:
                lines.append(f"- [{s.get('type')}] `{s.get('url')}` — {s.get('evidence')}")
        exploit = result.get("exploit") or {}
        if exploit:
            lines += ["", "## Web 利用结果（%s，声明闸门 + 双校验 + 审计）" % VERSION, ""]
            lines += triage.triage_lines(exploit.get("triage") or {}, level=3)
            lines.append(f"- 请求数：{exploit.get('requests')} / {exploit.get('budget')}")
            caps = exploit.get("capabilities") or {}
            lines.append("- 能力：PHP=%s；Java=%s；ysoserial=%s；phpggc=%s" % (
                "可用" if caps.get("php_ok") else "缺失",
                "可用" if caps.get("java_ok") else "缺失",
                "可用" if caps.get("ysoserial_ok") else "缺失",
                "可用" if caps.get("phpggc_ok") else "缺失"))
            findings = exploit.get("findings") or []
            lines += ["", "### 命中/线索", ""]
            if findings:
                lines += ["| 类型 | 目标 | 载荷摘要 | 证据 | 置信 |", "|---|---|---|---|---|"]
                for f in findings[:40]:
                    lines.append("| %s | `%s` | `%s` | %s | %s |" % (
                        f.get("type"), f.get("url"), str(f.get("payload"))[:80].replace("|", "\\|"),
                        str(f.get("evidence"))[:160].replace("|", "\\|"), f.get("confidence")))
            else:
                lines.append("- 未确认可利用点")
            cookies = exploit.get("cookies") or []
            if cookies:
                lines += ["", "### Cookie 审计", "",
                          "| Cookie | HttpOnly | Secure | SameSite | 风险 |",
                          "|---|---|---|---|---|"]
                for c in cookies[:20]:
                    lines.append("| %s | %s | %s | %s | %s |" % (
                        c.get("name"), c.get("httponly"), c.get("secure"),
                        c.get("samesite") or "-", c.get("risk") or "-"))
            artifacts = exploit.get("artifacts") or []
            if artifacts:
                lines += ["", "### 验证样本（仅任务 artifacts）", ""]
                lines += [f"- `{p}`" for p in artifacts[:40]]
            audit = exploit.get("audit") or {}
            lines += ["", "### 利用审计", "",
                      f"- 审计条数：{audit.get('entries')}",
                      f"- 任务审计：`{audit.get('task_path')}`",
                      f"- 全局审计：`{audit.get('global_pattern')}`"]
            if exploit.get("flags"):
                lines.append("- 利用链直接读到 flag：" + ", ".join(exploit["flags"]))
        lines += ["", "## 证据链", "",
                  f"- 逐步证据：`{ws.evidence_path}`",
                  f"- 运行日志：`{ws.log_path}`",
                  f"- 机器结论：`{ws.result_path}`", ""]
        try:
            with open(ws.report_path, "w", encoding="utf-8") as fp:
                fp.write("\n".join(lines))
        except Exception as exc:
            ws.log(f"报告写入失败: {exc}", "warn")
