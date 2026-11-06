# -*- coding: utf-8 -*-
"""Bounded, cancellable subprocesses owned by one task (never use a shell).

stdout/stderr are UTF-8 text tails, not unlimited transcripts. Log callbacks
receive at most MAX_LOG_LINES lines of MAX_LINE_CHARS characters and must return
promptly. Nonzero exit codes are returned, not raised. Startup errors propagate.
Windows uses a kill-on-close Job, assigned *before* the suspended child runs;
POSIX uses a new session/process group, plus identity-checked descendant cleanup.
"""
import codecs
from collections import deque
import math
import os
import queue
import signal
import subprocess
import threading
import time

MAX_OUTPUT_BYTES = 256 * 1024  # per stream
MAX_LINE_CHARS = 4096
MAX_LOG_LINES = 1000
_POLL_INTERVAL = 0.025


class TaskCancelled(RuntimeError):
    def __init__(self, message="Task cancelled", *, cmd=None, stdout="", stderr=""):
        super().__init__(message)
        self.cmd, self.stdout, self.stderr = cmd, stdout, stderr
        self.output = stdout


class TaskTimeout(TimeoutError):
    def __init__(self, message="Task timed out", *, cmd=None, timeout=None,
                 stdout="", stderr=""):
        super().__init__(message)
        self.cmd, self.timeout = cmd, timeout
        self.stdout, self.stderr = stdout, stderr
        self.output = stdout


class _WindowsJob:
    """Pointer-sized Win32 declarations are essential on 64-bit Python."""
    def __init__(self):
        import ctypes as c
        from ctypes import wintypes as w

        class BasicLimits(c.Structure):
            _fields_ = [("PerProcessUserTimeLimit", c.c_int64),
                        ("PerJobUserTimeLimit", c.c_int64), ("LimitFlags", w.DWORD),
                        ("MinimumWorkingSetSize", c.c_size_t),
                        ("MaximumWorkingSetSize", c.c_size_t),
                        ("ActiveProcessLimit", w.DWORD), ("Affinity", c.c_size_t),
                        ("PriorityClass", w.DWORD), ("SchedulingClass", w.DWORD)]

        class IOCounters(c.Structure):
            _fields_ = [(name, c.c_uint64) for name in (
                "ReadOperationCount", "WriteOperationCount", "OtherOperationCount",
                "ReadTransferCount", "WriteTransferCount", "OtherTransferCount")]

        class ExtendedLimits(c.Structure):
            _fields_ = [("BasicLimitInformation", BasicLimits),
                        ("IoInfo", IOCounters), ("ProcessMemoryLimit", c.c_size_t),
                        ("JobMemoryLimit", c.c_size_t),
                        ("PeakProcessMemoryUsed", c.c_size_t),
                        ("PeakJobMemoryUsed", c.c_size_t)]

        class ThreadEntry(c.Structure):
            _fields_ = [("dwSize", w.DWORD), ("cntUsage", w.DWORD),
                        ("th32ThreadID", w.DWORD), ("th32OwnerProcessID", w.DWORD),
                        ("tpBasePri", w.LONG), ("tpDeltaPri", w.LONG),
                        ("dwFlags", w.DWORD)]

        self.c, self.ThreadEntry = c, ThreadEntry
        self.api = c.WinDLL("kernel32", use_last_error=True)
        signatures = {
            "CreateJobObjectW": ([c.c_void_p, w.LPCWSTR], w.HANDLE),
            "SetInformationJobObject": ([w.HANDLE, c.c_int, c.c_void_p, w.DWORD], w.BOOL),
            "AssignProcessToJobObject": ([w.HANDLE, w.HANDLE], w.BOOL),
            "TerminateJobObject": ([w.HANDLE, w.UINT], w.BOOL),
            "CloseHandle": ([w.HANDLE], w.BOOL),
            "CreateToolhelp32Snapshot": ([w.DWORD, w.DWORD], w.HANDLE),
            "Thread32First": ([w.HANDLE, c.POINTER(ThreadEntry)], w.BOOL),
            "Thread32Next": ([w.HANDLE, c.POINTER(ThreadEntry)], w.BOOL),
            "OpenThread": ([w.DWORD, w.BOOL, w.DWORD], w.HANDLE),
            "ResumeThread": ([w.HANDLE], w.DWORD),
        }
        for name, (args, result) in signatures.items():
            func = getattr(self.api, name)
            func.argtypes, func.restype = args, result
        self.handle = self.api.CreateJobObjectW(None, None)
        if not self.handle:
            raise c.WinError(c.get_last_error())
        limits = ExtendedLimits()
        limits.BasicLimitInformation.LimitFlags = 0x2000  # JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        if not self.api.SetInformationJobObject(self.handle, 9, c.byref(limits), c.sizeof(limits)):
            error = c.WinError(c.get_last_error())
            self.close()
            raise error

    def assign_and_resume(self, process):
        c, api = self.c, self.api
        # Popen closes the primary thread handle. Use documented Toolhelp/OpenThread
        # APIs to resume it only after containment is in place. Fail closed on error.
        if not api.AssignProcessToJobObject(self.handle, int(process._handle)):
            raise c.WinError(c.get_last_error())
        snapshot = api.CreateToolhelp32Snapshot(0x4, 0)  # TH32CS_SNAPTHREAD
        if snapshot == c.c_void_p(-1).value:
            raise c.WinError(c.get_last_error())
        try:
            entry = self.ThreadEntry()
            entry.dwSize = c.sizeof(entry)
            present = api.Thread32First(snapshot, c.byref(entry))
            while present:
                if entry.th32OwnerProcessID == process.pid:
                    thread = api.OpenThread(0x2, False, entry.th32ThreadID)
                    if not thread:
                        raise c.WinError(c.get_last_error())
                    try:
                        if api.ResumeThread(thread) == 0xffffffff:
                            raise c.WinError(c.get_last_error())
                    finally:
                        api.CloseHandle(thread)
                    return
                present = api.Thread32Next(snapshot, c.byref(entry))
            raise OSError("Cannot find suspended child thread")
        finally:
            api.CloseHandle(snapshot)

    def close(self):
        if self.handle:
            # Also terminate surviving grandchildren on successful/abnormal root exit.
            self.api.TerminateJobObject(self.handle, 1)
            self.api.CloseHandle(self.handle)
            self.handle = None


class _PosixSession:
    def __init__(self, process):
        self.pid = process.pid
        self.children = {}
        try:
            import psutil
            self.psutil = psutil
            self.root = psutil.Process(process.pid)
        except (ImportError, ProcessLookupError):
            self.root = None
        except Exception:
            self.root = None

    def track(self):
        if self.root is None:
            return
        try:
            for child in self.root.children(recursive=True):
                self.children[(child.pid, child.create_time())] = child
        except self.psutil.Error:
            pass

    def close(self):
        self.track()
        # No executable-name matching, taskkill /IM, or scans of unrelated processes.
        try:
            os.killpg(self.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        for child in self.children.values():
            try:
                # psutil.kill checks PID reuse; also covers observed setsid descendants.
                child.kill()
            except self.psutil.Error:
                pass
        if self.children:
            self.psutil.wait_procs(list(self.children.values()), timeout=1)


class _Capture:
    def __init__(self, stream, messages, logging_done):
        self.stream, self.messages, self.logging_done = stream, messages, logging_done
        self.chunks, self.size = deque(), 0
        self.truncated = False
        self.dropped_logs = False
        self.lock = threading.Lock()
        self.thread = threading.Thread(target=self.read, name="ctfbox-output", daemon=True)

    def tail(self):
        with self.lock:
            return b"".join(self.chunks).decode("utf-8", "replace")

    def emit(self, line):
        if self.logging_done.is_set():
            self.dropped_logs = True
            return
        try:
            self.messages.put_nowait(line)
        except queue.Full:
            self.dropped_logs = True

    def read(self):
        decoder = codecs.getincrementaldecoder("utf-8")("replace")
        pending, clipped = "", False

        def lines(text, final=False):
            nonlocal pending, clipped
            if self.logging_done.is_set():
                self.dropped_logs = True
                pending = ""
                return
            # A read chunk is bounded, including a pathological stream without newlines.
            for part_index, part in enumerate(text.split("\n")):
                if part_index:
                    self.emit(pending.rstrip("\r"))
                    pending, clipped = "", False
                if not clipped:
                    room = MAX_LINE_CHARS - len(pending)
                    pending += part[:room]
                    clipped = len(part) > room
            if final and pending:
                self.emit(pending.rstrip("\r"))

        try:
            while True:
                chunk = self.stream.read(8192)
                if not chunk:
                    break
                with self.lock:
                    self.chunks.append(chunk)
                    self.size += len(chunk)
                    while self.size > MAX_OUTPUT_BYTES:
                        excess = self.size - MAX_OUTPUT_BYTES
                        first = self.chunks.popleft()
                        if len(first) > excess:
                            self.chunks.appendleft(first[excess:])
                            self.size -= excess
                        else:
                            self.size -= len(first)
                        self.truncated = True
                lines(decoder.decode(chunk))
            lines(decoder.decode(b"", final=True), final=True)
        except (OSError, ValueError):
            pass  # teardown may close a pipe
        finally:
            self.stream.close()


def run_command(args, log=print, cancel_event=None, timeout=180, cwd=None, env=None):
    """Run an argv sequence; return CompletedProcess with bounded *text* tails.

    Cancellation/timeouts raise TaskCancelled/TaskTimeout with cmd/stdout/stderr.
    All exits clean up the owned process tree. String commands and Windows batch
    files are rejected: invoking those would implicitly use a command shell.
    A None timeout disables the deadline. Log callbacks run on the calling thread.
    """
    if isinstance(args, (str, bytes, os.PathLike)):
        raise TypeError("args must be an argv sequence, not a shell command")
    args = [os.fspath(arg) for arg in args]
    if not args:
        raise ValueError("args must not be empty")
    if os.name == "nt" and os.fsdecode(args[0]).lower().endswith((".bat", ".cmd")):
        raise ValueError("Windows batch files require a shell and are not supported")
    if timeout is not None and (not math.isfinite(timeout) or timeout < 0):
        raise ValueError("timeout must be finite and nonnegative, or None")
    if cancel_event is not None and cancel_event.is_set():
        raise TaskCancelled(cmd=args)
    if timeout == 0:
        raise TaskTimeout(cmd=args, timeout=timeout)
    deadline = None if timeout is None else time.monotonic() + timeout
    messages, logging_done = queue.Queue(maxsize=128), threading.Event()
    captures, process, owner = [], None, None
    log_count = 0
    outcome = None

    def drain():
        nonlocal log_count
        for _ in range(64):  # output floods cannot starve cancellation/deadline checks
            try:
                line = messages.get_nowait()
            except queue.Empty:
                break
            if log_count < MAX_LOG_LINES and log is not None:
                log(line)
                log_count += 1
            if log is None or log_count >= MAX_LOG_LINES:
                logging_done.set()

    try:
        options = dict(stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                       stderr=subprocess.PIPE, shell=False, bufsize=0,
                       close_fds=True, cwd=cwd, env=env)
        if os.name == "nt":
            owner = _WindowsJob()
            options["creationflags"] = 0x4 | 0x08000000  # CREATE_SUSPENDED | CREATE_NO_WINDOW
        else:
            options["start_new_session"] = True
        process = subprocess.Popen(args, **options)
        if os.name == "nt":
            owner.assign_and_resume(process)
        else:
            owner = _PosixSession(process)
        for stream in (process.stdout, process.stderr):
            capture = _Capture(stream, messages, logging_done)
            captures.append(capture)
            capture.thread.start()
        while True:
            if cancel_event is not None and cancel_event.is_set():
                outcome = "cancel"
                break
            if deadline is not None and time.monotonic() >= deadline:
                outcome = "timeout"
                break
            if isinstance(owner, _PosixSession):
                owner.track()
            if process.poll() is not None:
                break
            drain()
            delay = _POLL_INTERVAL
            if deadline is not None:
                delay = max(0, min(delay, deadline - time.monotonic()))
            if cancel_event is not None:
                cancel_event.wait(delay)
            else:
                time.sleep(delay)
    finally:
        # This also covers Popen/assignment/reader startup failures and log exceptions.
        try:
            if owner is not None:
                owner.close()
        finally:
            if process is not None:
                if process.poll() is None:
                    process.kill()
                process.wait(timeout=5)
                for capture in captures:
                    if capture.thread.ident is not None:
                        capture.thread.join(timeout=2)
                for stream in (process.stdout, process.stderr):
                    if not any(c.stream is stream and c.thread.is_alive() for c in captures):
                        stream.close()
                if os.name == "nt":
                    process._handle.Close()
    stdout, stderr = (capture.tail() for capture in captures)
    if outcome == "cancel":
        raise TaskCancelled(cmd=args, stdout=stdout, stderr=stderr)
    if outcome == "timeout":
        raise TaskTimeout(f"Task timed out after {timeout}s", cmd=args, timeout=timeout,
                          stdout=stdout, stderr=stderr)
    while not messages.empty():
        drain()
    result = subprocess.CompletedProcess(args, process.returncode, stdout, stderr)
    result.output_truncated = any(c.truncated for c in captures)
    result.logs_truncated = any(c.dropped_logs for c in captures)
    return result
