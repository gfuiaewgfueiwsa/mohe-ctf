"""Win32 Unicode drops; native callbacks must only enqueue data, never call Tk."""

import ctypes
from ctypes import wintypes
import logging
import sys


WM_DROPFILES = 0x0233
WM_NCDESTROY = 0x0082
GWLP_WNDPROC = -4
GWL_EXSTYLE = -20
WS_EX_ACCEPTFILES = 0x00000010
GA_ROOT = 2

# Windows stores a raw function pointer, not a Python reference. Keep each
# installed thunk alive even if the caller forgets to retain the DropTarget.
_LIVE_HOOKS = set()
_LOG = logging.getLogger(__name__)

if sys.platform == "win32":
    _LONG_PTR = ctypes.c_ssize_t
    _WPARAM = ctypes.c_size_t
    _LPARAM = ctypes.c_ssize_t
    _WNDPROC = ctypes.WINFUNCTYPE(
        _LONG_PTR, wintypes.HWND, wintypes.UINT, _WPARAM, _LPARAM
    )
    _user32 = ctypes.WinDLL("user32", use_last_error=True)
    _shell32 = ctypes.WinDLL("shell32", use_last_error=True)
    _kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

    # *LongPtrW is a C macro for *LongW on 32-bit Windows (no DLL export).
    _get_window_long = getattr(
        _user32, "GetWindowLongPtrW" if ctypes.sizeof(ctypes.c_void_p) == 8
        else "GetWindowLongW"
    )
    _get_window_long.argtypes = [wintypes.HWND, ctypes.c_int]
    _get_window_long.restype = _LONG_PTR
    _set_window_long = getattr(
        _user32, "SetWindowLongPtrW" if ctypes.sizeof(ctypes.c_void_p) == 8
        else "SetWindowLongW"
    )
    _set_window_long.argtypes = [wintypes.HWND, ctypes.c_int, _LONG_PTR]
    _set_window_long.restype = _LONG_PTR
    _call_window_proc = _user32.CallWindowProcW
    _call_window_proc.argtypes = [
        ctypes.c_void_p, wintypes.HWND, wintypes.UINT, _WPARAM, _LPARAM
    ]
    _call_window_proc.restype = _LONG_PTR
    _get_ancestor = _user32.GetAncestor
    _get_ancestor.argtypes = [wintypes.HWND, wintypes.UINT]
    _get_ancestor.restype = wintypes.HWND
    _is_window = _user32.IsWindow
    _is_window.argtypes = [wintypes.HWND]
    _is_window.restype = wintypes.BOOL
    _window_thread = _user32.GetWindowThreadProcessId
    _window_thread.argtypes = [wintypes.HWND, ctypes.POINTER(wintypes.DWORD)]
    _window_thread.restype = wintypes.DWORD
    _current_thread = _kernel32.GetCurrentThreadId
    _current_thread.argtypes = []
    _current_thread.restype = wintypes.DWORD
    _drag_accept_files = _shell32.DragAcceptFiles
    _drag_accept_files.argtypes = [wintypes.HWND, wintypes.BOOL]
    _drag_accept_files.restype = None
    _drag_query_file = _shell32.DragQueryFileW
    _drag_query_file.argtypes = [
        wintypes.HANDLE, wintypes.UINT, wintypes.LPWSTR, wintypes.UINT
    ]
    _drag_query_file.restype = wintypes.UINT
    _drag_finish = _shell32.DragFinish
    _drag_finish.argtypes = [wintypes.HANDLE]
    _drag_finish.restype = None


def _window_long(function, *args):
    # Zero can be a valid style/previous value: consult GetLastError as well.
    ctypes.set_last_error(0)
    value = function(*args)
    error = ctypes.get_last_error()
    if not value and error:
        raise ctypes.WinError(error)
    return value


def _pointer(value):
    return ctypes.c_void_p(value).value or 0


class _WindowHook:
    def __init__(self, target, hwnd):
        self.target = target
        self.hwnd = hwnd
        self.installed = False
        self.old_proc = _window_long(_get_window_long, hwnd, GWLP_WNDPROC)
        if not self.old_proc:
            raise OSError("Window has no WNDPROC")
        self.accepted_files = bool(
            _window_long(_get_window_long, hwnd, GWL_EXSTYLE) & WS_EX_ACCEPTFILES
        )
        self.procedure = _WNDPROC(self._dispatch)
        self.address = ctypes.cast(self.procedure, ctypes.c_void_p).value

    def install(self):
        _LIVE_HOOKS.add(self)
        try:
            self.old_proc = _window_long(
                _set_window_long, self.hwnd, GWLP_WNDPROC, self.address
            )
        except BaseException:
            _LIVE_HOOKS.discard(self)
            raise
        self.installed = True
        _drag_accept_files(self.hwnd, True)

    def restore(self):
        if not self.installed:
            return
        if not _is_window(self.hwnd):
            self._release()
            return
        current = _window_long(_get_window_long, self.hwnd, GWLP_WNDPROC)
        if _pointer(current) != self.address:
            # A later subclass may still call us. Do not overwrite its WNDPROC
            # or free our thunk. Retry on close(), or release at WM_NCDESTROY.
            return
        _window_long(_set_window_long, self.hwnd, GWLP_WNDPROC, self.old_proc)
        _drag_accept_files(self.hwnd, self.accepted_files)
        self._release()

    def _release(self):
        self.installed = False
        _LIVE_HOOKS.discard(self)

    def _dispatch(self, hwnd, message, wparam, lparam):
        if message == WM_DROPFILES:
            paths = None
            try:
                try:
                    if not self.target.closed:
                        count = _drag_query_file(wparam, 0xFFFFFFFF, None, 0)
                        copied = []
                        for index in range(count):
                            length = _drag_query_file(wparam, index, None, 0)
                            if not length:
                                raise OSError("DragQueryFileW could not read a path")
                            # Size is in UTF-16 code units, including the NUL,
                            # not bytes and not a fixed MAX_PATH-sized buffer.
                            buffer = ctypes.create_unicode_buffer(length + 1)
                            copied_length = _drag_query_file(
                                wparam, index, buffer, length + 1
                            )
                            if copied_length != length:
                                raise OSError("DragQueryFileW returned an incomplete path")
                            copied.append(buffer.value)
                        paths = tuple(copied)
                finally:
                    _drag_finish(wparam)
                if paths is not None and not self.target.closed:
                    self.target._callback(paths)
            except BaseException as error:
                # No Python exception may cross the native callback boundary.
                self.target._report(error)
            # The HDROP has been freed. NEVER forward it to the previous proc.
            return 0
        try:
            return _call_window_proc(self.old_proc, hwnd, message, wparam, lparam)
        except BaseException as error:
            self.target._report(error)
            return 0
        finally:
            if message == WM_NCDESTROY:
                # Forward destruction first: an earlier subclass may need it.
                self._release()
                if not any(hook.installed for hook in self.target._hooks):
                    self.target.closed = True
                    self.target._callback = None
                    self.target._on_error = None


class DropTarget:
    """Create and close on the Tk thread; later subclasses retain inactive hooks."""

    def __init__(self, widget, callback, on_error=None):
        if sys.platform != "win32":
            raise OSError("Windows file drops are only supported on Windows")
        if not callable(callback):
            raise TypeError("callback must be callable")
        if on_error is not None and not callable(on_error):
            raise TypeError("on_error must be callable or None")
        self.closed = False
        self._callback = callback
        self._on_error = on_error
        self._hooks = []
        self._thread_id = _current_thread()

        # Tk's winfo_id() is the inner client HWND, not the top-level wrapper
        # Explorer targets. Realize the wrapper before discovering its HWND.
        widget.update_idletasks()
        inner = int(widget.winfo_id())
        handles = [inner]
        if widget == widget.winfo_toplevel():
            outer = _get_ancestor(inner, GA_ROOT)
            if outer and outer != inner:
                handles.append(outer)
        for hwnd in handles:
            if not _is_window(hwnd):
                raise OSError("Drop target is not a live Windows window")
            if _window_thread(hwnd, None) != self._thread_id:
                raise RuntimeError("DropTarget must be created on the window's UI thread")
            if any(hook.hwnd == hwnd for hook in _LIVE_HOOKS):
                raise ValueError("This window already has a DropTarget")
        try:
            for hwnd in handles:
                hook = _WindowHook(self, hwnd)
                self._hooks.append(hook)
                hook.install()
        except BaseException:
            self.close()
            raise

    def _report(self, error):
        try:
            if self._on_error is not None:
                self._on_error(error)
            else:
                _LOG.error("Windows file drop failed: %s", error)
        except BaseException:
            # Even a failing error sink must not escape into user32.
            pass

    def close(self):
        """Stop drops and restore native state; call from the window's UI thread."""
        if any(hook.installed for hook in self._hooks):
            if _current_thread() != self._thread_id:
                raise RuntimeError("DropTarget.close() must run on the window's UI thread")
        self.closed = True
        self._callback = None
        for hook in reversed(self._hooks):
            try:
                hook.restore()
            except Exception as error:
                # Keep failed/unrestorable hooks alive; a future close can retry.
                self._report(error)
        if not any(hook.installed for hook in self._hooks):
            self._on_error = None
