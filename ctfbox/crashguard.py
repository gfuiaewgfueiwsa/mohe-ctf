# -*- coding: utf-8 -*-
"""全局崩溃保护：faulthandler 抓 C 级段错误栈，excepthook 抓未处理异常，
全部写入 workspace/crash.log，避免 windowed 打包后静默闪退、无迹可查。"""
import sys
import os
import time
import faulthandler
import threading
import traceback

_log_fp = None
LOG_PATH = None
_HEADER_MARK = 0


def _write(banner, msg):
    global _log_fp
    if _log_fp is None:
        return
    try:
        _log_fp.write(f"\n[{time.strftime('%Y-%m-%d %H:%M:%S')}] {banner}\n{msg}\n")
        _log_fp.flush()
    except Exception:
        pass


def _strip_header_only(path):
    """文件里只有会话分隔行、没有任何堆栈时删掉，避免正常启动也留下一个空 crash.log。"""
    try:
        if not os.path.isfile(path):
            return
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                s = line.strip()
                if s and not s.startswith("================ session "):
                    return
        os.remove(path)
    except Exception:
        pass


def install():
    global _log_fp, LOG_PATH, _HEADER_MARK
    try:
        from .common import WORKSPACE
        os.makedirs(WORKSPACE, exist_ok=True)
        LOG_PATH = os.path.join(WORKSPACE, "crash.log")
        _strip_header_only(LOG_PATH)     # 上一次被强杀时留下的空日志，先清掉
        _log_fp = open(LOG_PATH, "a", encoding="utf-8")
        _log_fp.write(f"\n\n================ session {time.strftime('%Y-%m-%d %H:%M:%S')} "
                      f"python {sys.version.split()[0]} frozen={getattr(sys, 'frozen', False)} ================\n")
        _log_fp.flush()
        _HEADER_MARK = _log_fp.tell()    # 正常退出时若没有写出这条分隔之外的任何内容，就把文件删掉
        faulthandler.enable(file=_log_fp, all_threads=True)
        import atexit

        def _drop_empty_log():
            """正常结束时清掉只写了会话分隔、没有堆栈的 crash.log；真崩过（atexit 不执行）则保留。"""
            try:
                if _log_fp is None:
                    return
                _log_fp.flush()
                if _log_fp.tell() <= _HEADER_MARK:
                    _log_fp.close()
                    os.remove(LOG_PATH)
            except Exception:
                pass

        atexit.register(_drop_empty_log)
    except Exception:
        LOG_PATH = None

    def excepthook(etype, value, tb):
        msg = "".join(traceback.format_exception(etype, value, tb))
        _write("UNCAUGHT MAIN THREAD", msg)
        try:
            import tkinter as tk
            from tkinter import messagebox
            try:
                root = tk.Tk(); root.withdraw(); root.after(0, root.destroy)
            except Exception:
                pass
            messagebox.showerror(
                "CTFToolbox 出错",
                f"发生未捕获异常，详情已记录到：\n{LOG_PATH or 'workspace/crash.log'}\n\n"
                f"{etype.__name__}: {str(value)[:600]}")
        except Exception:
            pass

    def thread_hook(args):
        msg = "".join(traceback.format_exception(args.exc_type, args.exc_value, args.exc_traceback))
        _write(f"UNCAUGHT THREAD {args.thread.name}", msg)

    sys.excepthook = excepthook
    threading.excepthook = thread_hook
    return LOG_PATH
