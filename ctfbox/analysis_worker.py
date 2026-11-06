# -*- coding: utf-8 -*-
"""Crash-isolated Dispatcher bridge using bounded JSON, never pickle.

main.py must route ``--analysis-worker path depth result_path`` to worker_main
before importing the GUI. run_analysis returns a normal Report; ``report.info``
is the root FileInfo captured in the child (or None), so the GUI need not identify
an untrusted file again. Dispatcher/native analysis libraries load only in child.
"""
from dataclasses import asdict
import json
import os
import sys
import tempfile
from typing import TYPE_CHECKING

from .process_runner import run_command, TaskCancelled, TaskTimeout

if TYPE_CHECKING:
    from .common import Report

MAX_RESULT_BYTES = 16 * 1024 * 1024
MAX_REPORT_DEPTH = 64
MAX_REPORT_NODES = 10000
MAX_FINDINGS = 50000
MAX_ERROR_CHARS = 2048


class AnalysisError(RuntimeError):
    """Child startup, crash, or invalid/incomplete result (not cancellation)."""
    def __init__(self, message, *, returncode=None):
        super().__init__(str(message)[:MAX_ERROR_CHARS])
        self.returncode = returncode


def _worker_command(path, max_depth, result_path):
    command = [sys.executable]
    if not getattr(sys, "frozen", False):
        command.append(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                                    "main.py"))
    return command + ["--analysis-worker", path, str(max_depth), result_path]


def _depth(value):
    if isinstance(value, bool):
        raise ValueError("max_depth must be a nonnegative integer")
    depth = int(value)
    if str(depth) != str(value) or not 0 <= depth <= MAX_REPORT_DEPTH:
        raise ValueError(f"max_depth must be an integer between 0 and {MAX_REPORT_DEPTH}")
    return depth


def _report_from_dict(payload):
    from .common import Finding, Report
    from .identifier import FileInfo

    nodes, findings = 0, 0

    def text(obj, key, default=None):
        value = obj.get(key, default)
        if not isinstance(value, str):
            raise ValueError(f"Invalid report field: {key}")
        return value

    def build(obj, depth):
        nonlocal nodes, findings
        nodes += 1
        if nodes > MAX_REPORT_NODES or depth > MAX_REPORT_DEPTH:
            raise ValueError("Report tree exceeds protocol limits")
        if not isinstance(obj, dict):
            raise ValueError("Report must be an object")
        report = Report(path=text(obj, "path"), category=text(obj, "category", "unknown"),
                        ftype=text(obj, "ftype", "unknown"))
        raw_findings, extracted, children = (obj.get(key, []) for key in
                                            ("findings", "extracted", "children"))
        if not all(isinstance(value, list) for value in (raw_findings, extracted, children)):
            raise ValueError("Report collections must be lists")
        findings += len(raw_findings)
        if findings > MAX_FINDINGS or len(children) > MAX_REPORT_NODES:
            raise ValueError("Report collections exceed protocol limits")
        for item in raw_findings:
            if not isinstance(item, dict):
                raise ValueError("Finding must be an object")
            report.findings.append(Finding(text(item, "level"), text(item, "title"),
                                           text(item, "detail", ""), item.get("data")))
        if not all(isinstance(path, str) for path in extracted):
            raise ValueError("Extracted paths must be strings")
        report.extracted = extracted
        report.children = [build(child, depth + 1) for child in children]
        return report

    report = build(payload, 0)
    report.info = None
    info = payload.get("info")
    if info is not None:
        if not isinstance(info, dict):
            raise ValueError("File info must be an object")
        for key in ("path", "ftype", "category", "head_hex", "ext"):
            text(info, key)
        if (type(info.get("size")) is not int or info["size"] < 0
                or type(info.get("entropy")) not in (int, float)
                or not 0 <= info["entropy"] <= 8
                or type(info.get("is_text")) is not bool
                or not isinstance(info.get("extra"), dict)
                or not (info.get("encoding") is None or isinstance(info["encoding"], str))):
            raise ValueError("Invalid FileInfo metadata")
        report.info = FileInfo(**{key: info[key] for key in FileInfo.__dataclass_fields__})
    return report


def _load_report(result_path):
    try:
        with open(result_path, "rb") as stream:
            if os.fstat(stream.fileno()).st_size > MAX_RESULT_BYTES:
                raise ValueError("Result exceeds size limit")
            raw = stream.read(MAX_RESULT_BYTES + 1)
        if len(raw) > MAX_RESULT_BYTES:
            raise ValueError("Result exceeds size limit")

        def reject_constant(value):
            raise ValueError("Invalid JSON constant")

        payload = json.loads(raw.decode("utf-8"), parse_constant=reject_constant)
        if isinstance(payload, dict) and "error" in payload:
            raise AnalysisError(f"Analysis worker failed: {str(payload['error'])[:MAX_ERROR_CHARS]}")
        return _report_from_dict(payload)
    except AnalysisError:
        raise
    except (OSError, ValueError, TypeError, KeyError, RecursionError) as error:
        raise AnalysisError(f"Invalid or missing analysis result: {error}") from error


def run_analysis(path, max_depth, log=print, cancel_event=None, timeout=300) -> "Report":
    """Run Dispatcher off-process; failures cannot take down the GUI interpreter.

    Raises TaskCancelled, TaskTimeout, or AnalysisError. Report.to_dict() remains
    compatible; optional FileInfo metadata is available as report.info.
    """
    path = os.path.abspath(os.fspath(path))
    depth = _depth(max_depth)
    if cancel_event is not None and cancel_event.is_set():
        raise TaskCancelled()
    # Fixed, portable filenames; never append ':' or a user path to a filename.
    with tempfile.TemporaryDirectory(prefix="ctfbox-analysis-") as directory:
        result_path = os.path.join(directory, "result.json")
        command = _worker_command(path, depth, result_path)
        environment = os.environ.copy()
        environment.update(PYTHONIOENCODING="utf-8:replace", PYTHONUNBUFFERED="1")
        try:
            result = run_command(command, log=log, cancel_event=cancel_event,
                                 timeout=timeout, env=environment)
        except OSError as error:
            if isinstance(error, TaskTimeout):
                raise
            raise AnalysisError(f"Cannot start analysis worker: {error}") from error
        if cancel_event is not None and cancel_event.is_set():
            raise TaskCancelled(cmd=command, stdout=result.stdout, stderr=result.stderr)
        if result.returncode:
            # Do not trust even a complete-looking result after an abnormal exit.
            detail = (result.stderr or result.stdout or "No diagnostic output")[-1500:]
            raise AnalysisError(f"Analysis worker exited with code {result.returncode}: {detail}",
                                returncode=result.returncode)
        report = _load_report(result_path)
        if os.path.normcase(os.path.abspath(report.path)) != os.path.normcase(path):
            raise AnalysisError("Analysis result path does not match the requested file")
        if cancel_event is not None and cancel_event.is_set():
            raise TaskCancelled(cmd=command)
        return report


def _configure_streams():
    # PyInstaller --windowed may set sys.stdout/stderr to None even with inherited
    # pipe handles. Reattach those handles for worker logging, without a console.
    for name, number, win_number in (("stdout", 1, -11), ("stderr", 2, -12)):
        stream = getattr(sys, name)
        if stream is None:
            try:
                stream = os.fdopen(os.dup(number), "w", encoding="utf-8", errors="replace",
                                   buffering=1)
            except OSError:
                if os.name == "nt":
                    try:
                        import ctypes as c
                        from ctypes import wintypes as w
                        import msvcrt
                        api = c.WinDLL("kernel32", use_last_error=True)
                        api.GetStdHandle.argtypes, api.GetStdHandle.restype = [w.DWORD], w.HANDLE
                        handle = api.GetStdHandle(win_number & 0xffffffff)
                        if handle and handle != c.c_void_p(-1).value:
                            descriptor = msvcrt.open_osfhandle(handle, os.O_WRONLY)
                            stream = os.fdopen(descriptor, "w", encoding="utf-8", errors="replace",
                                               buffering=1)
                    except (OSError, ValueError):
                        pass
            if stream is not None:
                setattr(sys, name, stream)
        try:
            stream.reconfigure(encoding="utf-8", errors="replace", line_buffering=True)
        except (AttributeError, OSError, ValueError):
            pass


def _write_result(result_path, payload):
    temporary = result_path + ".tmp"
    try:
        total = 0
        encoder = json.JSONEncoder(ensure_ascii=False, allow_nan=False, default=str)
        with open(temporary, "wb") as stream:
            for chunk in encoder.iterencode(payload):
                raw = chunk.encode("utf-8", "replace")
                total += len(raw)
                if total > MAX_RESULT_BYTES:
                    raise ValueError("Analysis result exceeds size limit")
                stream.write(raw)
        os.replace(temporary, result_path)
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


def worker_main(path, depth, result_path):
    """Private child entry. Return an exit code; main.py should use SystemExit.

    The runner assigns the suspended Windows process to its Job before executing
    any Python; no cooperative gate or vulnerable post-import assignment is needed.
    """
    _configure_streams()
    try:
        depth = _depth(depth)
        path, result_path = os.path.abspath(path), os.path.abspath(result_path)
        if not os.path.isfile(path):
            raise FileNotFoundError(path)
        from . import dispatcher, identifier

        original_identify = identifier.identify
        root_info = None

        def capture_info(filename, *args, **kwargs):
            nonlocal root_info
            info = original_identify(filename, *args, **kwargs)
            if os.path.normcase(os.path.abspath(filename)) == os.path.normcase(path):
                root_info = info
            return info

        def log(message):
            if sys.stdout is not None:
                print(message, flush=True)

        # This patch is confined to the isolated worker. Capture the original
        # identification rather than repeating entropy/I/O work in either process.
        identifier.identify = capture_info
        try:
            report = dispatcher.Dispatcher(log_cb=log, max_depth=depth).run(path)
        finally:
            identifier.identify = original_identify
        payload = report.to_dict()
        payload["info"] = asdict(root_info) if root_info is not None else None
        _write_result(result_path, payload)
        return 0
    except Exception as error:
        message = f"{type(error).__name__}: {error}"[:MAX_ERROR_CHARS]
        try:
            _write_result(result_path, {"error": message})
        except Exception:
            pass
        if sys.stderr is not None:
            print(message, file=sys.stderr, flush=True)
        return 1
