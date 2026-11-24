"""Shared IPC transport for policyd and the core daemon.

Both servers speak the same JSON-lines protocol: one JSON object per
line (``json.dumps(payload) + "\\n"``, UTF-8), one JSON reply per line,
with the request carrying an ``auth`` token field. The framing helpers
here (:func:`encode_message`, :func:`decode_message`,
:func:`send_message`) are the single definition of that protocol —
client and servers must all go through them so the bytes on the wire
are identical whichever transport carries them.

Transports, selected by platform (:func:`transport_kind`):

* POSIX — Unix-domain socket (``AF_UNIX``), the Phase 1 behaviour,
  unchanged. The socket file is owner-only (0600).
* Windows — named pipe (``\\\\.\\pipe\\opencobot-policyd`` /
  ``\\\\.\\pipe\\opencobot-daemon``). The *client* side is implemented
  here with stdlib :func:`open` (see :class:`NamedPipeTransport`).
  The *server* side (:class:`NamedPipeListener`) is implemented with
  ``ctypes`` ``CreateNamedPipeW`` and a DACL that grants access only
  to the current user and the local Administrators group and
  explicitly denies remote (NETWORK) logons (see
  :class:`_CtypesWindowsPipeApi`). If the ACL cannot be built, or
  the Win32 API is unavailable, the server refuses to start — an
  ACL-less pipe is never served (SECURITY.md adversary 5).

  HONEST LIMIT: this was written and mock-verified on Linux only.
  The ``ctypes`` calls are real Win32 calls, but no Windows host
  was available to the builder, so the listener has never run
  against a real pipe. Laptop verification is tracked in
  docs/WINDOWS_TESTING.md §6; until that passes, treat the
  listener as implemented-but-unverified, not proven.

This module is stdlib-only and imports nothing from ``core`` or
``policy``, so the separate policyd process can import it without
dragging in the Gateway/Runtime.
"""

from __future__ import annotations

import ctypes
import json
import platform
import socket
import sys
import threading
from pathlib import Path

# Fixed-width Win32 types. ``ctypes.wintypes`` is NOT used: on LP64
# Linux ``wintypes.DWORD`` is ``c_ulong`` (8 bytes), while on Windows
# a DWORD is 4 bytes — struct layouts built from ``wintypes`` would
# silently be the wrong size on the Linux build host. These aliases
# are the Windows widths on every platform, so the layouts below can
# be checked on Linux too.
_DWORD = ctypes.c_uint32
_BOOL = ctypes.c_int32
# HANDLE is ULONG_PTR: an *unsigned* pointer-sized int. It must NOT
# be ``c_void_p``: ``GetCurrentProcess()`` returns the pseudo-handle
# 0xffffffffffffffff (-1), and passing that Python int through a
# ``c_void_p`` argtype raises OverflowError on 64-bit Windows.
# ``c_size_t`` holds the full unsigned range, so -1 / INVALID_HANDLE
# round-trips. (BUG-A/B/C fix: wrong-DLL prototypes + HANDLE overflow.)
_HANDLE = ctypes.c_size_t
_LPCWSTR = ctypes.c_wchar_p

__all__ = [
    "POLICYD_PIPE_PATH",
    "DAEMON_PIPE_PATH",
    "PIPE_PATH_PREFIX",
    "TransportNotAvailableError",
    "is_windows",
    "transport_kind",
    "encode_message",
    "decode_message",
    "send_message",
    "UnixSocketTransport",
    "NamedPipeTransport",
    "NamedPipeListener",
]

#: Named-pipe addresses used on Windows (client and server must agree).
POLICYD_PIPE_PATH = r"\\.\pipe\opencobot-policyd"
DAEMON_PIPE_PATH = r"\\.\pipe\opencobot-daemon"
PIPE_PATH_PREFIX = "\\\\.\\pipe\\"  # literal: \\.\pipe\


class TransportNotAvailableError(OSError):
    """The selected transport cannot be used on this platform/host.

    Subclasses :class:`OSError` so callers that already map connect
    failures to "unavailable" keep working; the message always says
    *why* (missing socket, Windows-only pipe on a POSIX host, ...).
    """


def is_windows() -> bool:
    """True on a Windows host (``platform.system() == "Windows"``)."""
    return platform.system() == "Windows"


def transport_kind() -> str:
    """``"pipe"`` on Windows, ``"unix"`` everywhere else."""
    return "pipe" if is_windows() else "unix"


# ---------------------------------------------------------------------------
# JSON-lines framing (the protocol — identical on both transports)
# ---------------------------------------------------------------------------

def encode_message(payload: dict) -> bytes:
    """Encode one request/reply as a single newline-terminated JSON line."""
    return (json.dumps(payload) + "\n").encode("utf-8")


def decode_message(raw: bytes) -> dict:
    """Decode one JSON line; raises ValueError on bad JSON / non-object."""
    try:
        obj = json.loads(raw.decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise ValueError(f"invalid JSON: {exc}") from exc
    if not isinstance(obj, dict):
        raise ValueError("message must be a JSON object")
    return obj


def send_message(stream, payload: dict) -> None:
    """Write one framed message to a binary stream and flush."""
    stream.write(encode_message(payload))
    stream.flush()


# ---------------------------------------------------------------------------
# Client transports (one-shot request/response; ``connect()`` returns a
# binary file-like object usable as a context manager)
# ---------------------------------------------------------------------------

class _SocketConnection:
    """Binary file-like wrapper around a connected AF_UNIX socket.

    Closing closes the buffered file first (flush) and then the
    socket; double-close is safe.
    """

    def __init__(self, sock: socket.socket):
        self._sock = sock
        self._file = sock.makefile("rwb")

    def write(self, data: bytes) -> int:
        return self._file.write(data)

    def flush(self) -> None:
        self._file.flush()

    def readline(self) -> bytes:
        return self._file.readline()

    def close(self) -> None:
        try:
            self._file.close()
        finally:
            self._sock.close()

    def __enter__(self) -> "_SocketConnection":
        return self

    def __exit__(self, *exc) -> bool:
        self.close()
        return False


class UnixSocketTransport:
    """AF_UNIX client transport — the Phase 1 behaviour, unchanged."""

    def __init__(self, sock_path: Path | str, timeout: float = 10.0):
        self.sock_path = Path(sock_path)
        self.timeout = timeout

    def connect(self) -> _SocketConnection:
        """Connect; raises TransportNotAvailableError if unreachable."""
        if not self.sock_path.exists():
            raise TransportNotAvailableError(
                f"policyd socket missing: {self.sock_path}"
            )
        try:
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect(str(self.sock_path))
        except OSError as exc:
            raise TransportNotAvailableError(
                f"cannot connect to policyd socket: {self.sock_path}"
            ) from exc
        return _SocketConnection(sock)


class NamedPipeTransport:
    """Windows named-pipe client transport.

    On a Windows host the pipe is opened with stdlib :func:`open` in
    ``"r+b"`` mode (no ``shell``, no new dependency). ``open()`` blocks
    until a server instance is listening, and has no timeout — a
    ``ctypes`` ``CreateFile`` client with a timeout is the hardening
    step for later; this round the 10 s read behaviour of the caller
    still bounds a single request once connected.

    On a non-Windows host :meth:`connect` raises
    :class:`TransportNotAvailableError` ("not available on this
    platform"). Tests may inject ``pipe_file`` (any binary file-like
    object with ``write``/``flush``/``readline``/``close``) to drive
    the client without a real pipe.
    """

    def __init__(
        self,
        pipe_path: str = POLICYD_PIPE_PATH,
        pipe_file=None,
        opener=None,
    ):
        self.pipe_path = pipe_path
        self._pipe_file = pipe_file
        self._opener = opener

    def connect(self):
        """Open the pipe (or return the injected fake for tests)."""
        if self._pipe_file is not None:
            return self._pipe_file
        if not is_windows():
            raise TransportNotAvailableError(
                "named-pipe transport is not available on this platform "
                "(Windows only); use the Unix-socket transport"
            )
        opener = self._opener or open
        try:
            return opener(self.pipe_path, "r+b", buffering=0)
        except OSError as exc:
            raise TransportNotAvailableError(
                f"cannot connect to named pipe: {self.pipe_path}"
            ) from exc


# ---------------------------------------------------------------------------
# Server listener — Windows named pipe with a restrictive DACL (ctypes)
# ---------------------------------------------------------------------------
#
# The stdlib cannot create a named pipe with an ACL, so the server
# side is implemented here against the Win32 API via ``ctypes``
# (ADR-010). The design keeps the Win32 calls behind a small
# interface so the listener logic (accept loop, JSON-lines dispatch,
# fail-closed behaviour) is testable on Linux with a fake API, while
# the real API class below is the only place that touches Win32.
#
# HONEST LIMIT: the real API class has never run on Windows — it was
# written and mock-verified on Linux only. The Win32 call sequence
# (OpenProcessToken / GetTokenInformation / CreateWellKnownSid /
# SetEntriesInAclW / InitializeSecurityDescriptor /
# SetSecurityDescriptorDacl / CreateNamedPipeW / ConnectNamedPipe /
# ReadFile / WriteFile / DisconnectNamedPipe) follows the documented
# API contracts, but a typo in a struct layout or a missed error
# code can only be caught by running it on a real Windows host
# (docs/WINDOWS_TESTING.md §6). Until that laptop run passes, the
# listener is implemented-but-unverified.

#: Access mask granted on the pipe: read + write, nothing else.
#: (GENERIC_READ = 0x80000000, GENERIC_WRITE = 0x40000000.)
_PIPE_ACCESS_MASK = 0x80000000 | 0x40000000

#: Well-known SID types (WinNT.h): S-1-5-2 and S-1-5-32-544.
_WIN_NETWORK_SID = 12
_WIN_BUILTIN_ADMINISTRATORS_SID = 26

# ACCESS_MODE values for EXPLICIT_ACCESS (AccCtrl.h).
_ACCESS_MODE_GRANT = 1
_ACCESS_MODE_DENY = 3

# TRUSTEE_FORM / TRUSTEE_TYPE values (AccCtrl.h).
_TRUSTEE_IS_SID = 0
_TRUSTEE_IS_USER = 1
_TRUSTEE_IS_WELL_KNOWN_GROUP = 5


class _DaclEntry:
    """One DACL entry for the pipe: (mode, SID bytes, access mask).

    A tiny value object so the *policy* of the DACL — who is allowed,
    who is denied — can be built and unit-tested on Linux without
    any Win32 call (see :func:`_pipe_dacl_entries`); only
    :class:`_CtypesWindowsPipeApi` turns entries into
    ``EXPLICIT_ACCESS`` structs.
    """

    __slots__ = ("mode", "sid", "access", "trustee_type")

    def __init__(self, mode: int, sid: bytes, access: int,
                 trustee_type: int):
        self.mode = mode
        self.sid = sid
        self.access = access
        self.trustee_type = trustee_type

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        mode = "GRANT" if self.mode == _ACCESS_MODE_GRANT else "DENY"
        return f"_DaclEntry({mode}, sid={self.sid.hex()}, access={self.access:#x})"


def _pipe_dacl_entries(user_sid: bytes, admin_sid: bytes,
                       network_sid: bytes) -> list[_DaclEntry]:
    """The DACL policy for every OpenCobot named pipe.

    Order matters: the explicit DENY for remote logons comes first
    (``SetEntriesInAclW`` also orders deny ACEs before grant ACEs,
    but listing it first makes the intent unmistakable), then the
    two grants. A DACL grants only what its ACEs list, so every
    other local account — including other logged-on users and
    services running as someone else — gets no access at all.

    * DENY ``NT AUTHORITY\\NETWORK`` (S-1-5-2): a remote client
      connecting to ``\\\\<host>\\pipe\\...`` arrives as a network
      logon; the deny ACE makes remote access fail even if some
      other ACE would have allowed it. The pipe name itself is
      local-only (``\\\\.\\pipe\\...``), so this is defence in depth.
    * GRANT the current user (the account ``policyd`` / the daemon
      runs as): read + write, the named-pipe equivalent of the
      0600 Unix socket.
    * GRANT ``BUILTIN\\Administrators`` (S-1-5-32-544): an
      administrator already owns the machine (process memory,
      token theft), so denying them buys no security and would
      break admin diagnostics and a policyd run elevated under a
      different admin account.
    """
    return [
        _DaclEntry(_ACCESS_MODE_DENY, network_sid, _PIPE_ACCESS_MASK,
                   _TRUSTEE_IS_WELL_KNOWN_GROUP),
        _DaclEntry(_ACCESS_MODE_GRANT, user_sid, _PIPE_ACCESS_MASK,
                   _TRUSTEE_IS_USER),
        _DaclEntry(_ACCESS_MODE_GRANT, admin_sid, _PIPE_ACCESS_MASK,
                   _TRUSTEE_IS_WELL_KNOWN_GROUP),
    ]


def _load_windows_api():
    """Return the real Win32 pipe API, or fail closed if unavailable.

    On a non-Windows host ``ctypes.windll`` does not exist, so this
    raises the same :class:`NotImplementedError` the shape-only
    listener raised (ADR-008): a pipe server cannot be built without
    the Win32 API, and refusing is the correct behaviour. On a real
    Windows host ``windll`` always exists.
    """
    windll = getattr(ctypes, "windll", None)
    if windll is None:
        raise NotImplementedError(
            "named-pipe listener is not implemented yet: it requires "
            "ctypes CreateNamedPipeW with a current-user-only ACL (see "
            "core/transport.py NamedPipeListener) and must be verified "
            "on a Windows host; refusing to serve without the ACL"
        )
    return _CtypesWindowsPipeApi(windll)


class _CtypesWindowsPipeApi:
    """The real Win32 named-pipe API, behind the listener's interface.

    Methods (the interface :class:`NamedPipeListener` uses; a fake
    implementing the same methods drives the listener in tests):

    * ``build_security_attributes()`` -> SECURITY_ATTRIBUTES struct
      holding a DACL per :func:`_pipe_dacl_entries`. Any failure
      raises :class:`TransportNotAvailableError` — the caller must
      refuse to serve, never fall back to a NULL DACL (which would
      mean "everyone may connect").
    * ``create_pipe(path, sa)`` -> pipe HANDLE.
    * ``wait_for_client(handle, stop)`` -> True when a client
      connected, False when ``stop`` was set while waiting.
    * ``read_available(handle, size)`` -> bytes read, ``b""`` when
      the client disconnected.
    * ``write_all(handle, data)`` -> None (writes the whole buffer).
    * ``disconnect(handle)`` / ``close(handle)``.

    All Win32 errors raise :class:`TransportNotAvailableError` with
    the failing call named, so the listener can fail closed with a
    useful message instead of serving a half-built pipe.
    """

    # Win32 constants (WinBase.h / WinNT.h / WinError.h).
    _PIPE_ACCESS_DUPLEX = 0x00000003
    _PIPE_TYPE_MESSAGE = 0x00000004
    _PIPE_READMODE_MESSAGE = 0x00000002
    _PIPE_WAIT = 0x00000000
    _PIPE_UNLIMITED_INSTANCES = 255
    _TOKEN_QUERY = 0x0008
    _TOKEN_USER = 1
    _SECURITY_DESCRIPTOR_REVISION = 1
    _ERROR_PIPE_CONNECTED = 535
    _ERROR_IO_PENDING = 997
    _ERROR_BROKEN_PIPE = 109
    _ERROR_NO_DATA = 232
    _WAIT_OBJECT_0 = 0
    _WAIT_TIMEOUT = 0x00000102
    _INFINITE = 0xFFFFFFFF

    def __init__(self, windll):
        self._kernel32 = windll.kernel32
        self._advapi32 = windll.advapi32
        self._setup_prototypes()
        # Buffers the SECURITY_DESCRIPTOR / ACL live in. They must
        # stay alive as long as the pipe exists: CreateNamedPipeW
        # copies the descriptor, but freeing the ACL while the pipe
        # is live would be a use-after-free if any later call re-read
        # it, so keep them until close().
        self._sa_keepalive: tuple | None = None

    # -- prototypes ---------------------------------------------------

    def _setup_prototypes(self) -> None:
        # DLL OWNERSHIP RULE (do not regress — a prototype set on the
        # wrong DLL object silently does nothing there, and the call
        # on the owning DLL then runs with no argtypes, which
        # overflows on 64-bit handles / fails with AttributeError):
        # advapi32 owns the token/SID/ACL functions — OpenProcessToken,
        # GetTokenInformation, CreateWellKnownSid, SetEntriesInAclW,
        # InitializeSecurityDescriptor, SetSecurityDescriptorDacl,
        # GetLengthSid; kernel32 owns the process/pipe/file functions
        # — GetCurrentProcess, CreateNamedPipeW, CreateEventW,
        # ConnectNamedPipe, WaitForSingleObject, GetOverlappedResult,
        # CancelIoEx, ReadFile, WriteFile, DisconnectNamedPipe,
        # CloseHandle, LocalFree.
        k = self._kernel32
        a = self._advapi32
        H = _HANDLE
        DWORD = _DWORD
        BOOL = _BOOL
        LPVOID = ctypes.c_void_p
        LPDWORD = ctypes.POINTER(DWORD)
        k.GetCurrentProcess.restype = H
        k.GetCurrentProcess.argtypes = []
        a.OpenProcessToken.restype = BOOL
        a.OpenProcessToken.argtypes = [H, DWORD, ctypes.POINTER(H)]
        a.GetLengthSid.restype = DWORD
        a.GetLengthSid.argtypes = [LPVOID]
        a.GetTokenInformation.restype = BOOL
        a.GetTokenInformation.argtypes = [H, DWORD, LPVOID, DWORD, LPDWORD]
        a.CreateWellKnownSid.restype = BOOL
        a.CreateWellKnownSid.argtypes = [DWORD, LPVOID, LPVOID, LPDWORD]
        a.SetEntriesInAclW.restype = DWORD
        a.SetEntriesInAclW.argtypes = [
            DWORD, ctypes.POINTER(_ExplicitAccess), LPVOID,
            ctypes.POINTER(LPVOID)]
        a.InitializeSecurityDescriptor.restype = BOOL
        a.InitializeSecurityDescriptor.argtypes = [LPVOID, DWORD]
        a.SetSecurityDescriptorDacl.restype = BOOL
        a.SetSecurityDescriptorDacl.argtypes = [LPVOID, BOOL, LPVOID, BOOL]
        k.CreateNamedPipeW.restype = H
        k.CreateNamedPipeW.argtypes = [
            _LPCWSTR, DWORD, DWORD, DWORD, DWORD, DWORD, DWORD,
            ctypes.POINTER(_SecurityAttributes)]
        k.CreateEventW.restype = H
        k.CreateEventW.argtypes = [LPVOID, BOOL, BOOL, _LPCWSTR]
        k.ConnectNamedPipe.restype = BOOL
        k.ConnectNamedPipe.argtypes = [H, ctypes.POINTER(_Overlapped)]
        k.WaitForSingleObject.restype = DWORD
        k.WaitForSingleObject.argtypes = [H, DWORD]
        k.GetOverlappedResult.restype = BOOL
        k.GetOverlappedResult.argtypes = [
            H, ctypes.POINTER(_Overlapped), LPDWORD, BOOL]
        k.CancelIoEx.restype = BOOL
        k.CancelIoEx.argtypes = [H, ctypes.POINTER(_Overlapped)]
        k.ReadFile.restype = BOOL
        k.ReadFile.argtypes = [H, LPVOID, DWORD, LPDWORD, LPVOID]
        k.WriteFile.restype = BOOL
        k.WriteFile.argtypes = [H, LPVOID, DWORD, LPDWORD, LPVOID]
        k.DisconnectNamedPipe.restype = BOOL
        k.DisconnectNamedPipe.argtypes = [H]
        k.CloseHandle.restype = BOOL
        k.CloseHandle.argtypes = [H]
        k.LocalFree.restype = LPVOID
        k.LocalFree.argtypes = [LPVOID]

    # -- errors ---------------------------------------------------------

    def _fail(self, call: str) -> TransportNotAvailableError:
        err = ctypes.get_last_error()
        return TransportNotAvailableError(
            f"named-pipe server: {call} failed (Win32 error {err}); "
            "refusing to serve without a protected pipe"
        )

    # -- SIDs -----------------------------------------------------------

    def _current_user_sid(self) -> bytes:
        """SID of the account this process runs as (TokenUser)."""
        token = _HANDLE()
        if not self._advapi32.OpenProcessToken(
                self._kernel32.GetCurrentProcess(), self._TOKEN_QUERY,
                ctypes.byref(token)):
            raise self._fail("OpenProcessToken")
        try:
            size = _DWORD(0)
            # First call reports the needed size (expected failure).
            self._advapi32.GetTokenInformation(
                token, self._TOKEN_USER, None, 0, ctypes.byref(size))
            buf = ctypes.create_string_buffer(size.value)
            if not self._advapi32.GetTokenInformation(
                    token, self._TOKEN_USER, buf, size, ctypes.byref(size)):
                raise self._fail("GetTokenInformation")
            user = _TokenUser.from_buffer(buf)
            sid_len = self._advapi32.GetLengthSid(user.User.Sid)
            return ctypes.string_at(user.User.Sid, sid_len)
        finally:
            self._kernel32.CloseHandle(token)

    def _well_known_sid(self, sid_type: int) -> bytes:
        size = _DWORD(0)
        # First call reports the needed size (expected failure).
        self._advapi32.CreateWellKnownSid(sid_type, None, None,
                                          ctypes.byref(size))
        buf = ctypes.create_string_buffer(size.value)
        if not self._advapi32.CreateWellKnownSid(
                sid_type, None, buf, ctypes.byref(size)):
            raise self._fail("CreateWellKnownSid")
        return buf.raw[:size.value]

    # -- security attributes --------------------------------------------

    def build_security_attributes(self):
        """Build the pipe's SECURITY_ATTRIBUTES (DACL per policy).

        FAIL CLOSED: any step failing raises
        :class:`TransportNotAvailableError` before a pipe exists.
        A NULL DACL (everyone allowed) is never produced.
        """
        user_sid = self._current_user_sid()
        admin_sid = self._well_known_sid(
            _WIN_BUILTIN_ADMINISTRATORS_SID)
        network_sid = self._well_known_sid(_WIN_NETWORK_SID)
        entries = _pipe_dacl_entries(user_sid, admin_sid, network_sid)

        explicit = (_ExplicitAccess * len(entries))()
        sid_buffers = []
        for i, entry in enumerate(entries):
            sid_buf = ctypes.create_string_buffer(entry.sid, len(entry.sid))
            sid_buffers.append(sid_buf)
            explicit[i].grfAccessPermissions = entry.access
            explicit[i].grfAccessMode = entry.mode
            explicit[i].grfInheritance = 0  # NO_INHERITANCE
            explicit[i].Trustee.pMultipleTrustee = None
            explicit[i].Trustee.MultipleTrusteeOperation = 0
            explicit[i].Trustee.TrusteeForm = _TRUSTEE_IS_SID
            explicit[i].Trustee.TrusteeType = entry.trustee_type
            explicit[i].Trustee._u.pSid = ctypes.cast(
                sid_buf, ctypes.c_void_p)

        new_acl = ctypes.c_void_p()
        err = self._advapi32.SetEntriesInAclW(
            len(entries), explicit, None, ctypes.byref(new_acl))
        if err != 0:
            raise TransportNotAvailableError(
                f"named-pipe server: SetEntriesInAclW failed (Win32 "
                f"error {err}); refusing to serve without a protected pipe"
            )
        # SECURITY_DESCRIPTOR_MIN_LENGTH is 20 bytes; 64 leaves room.
        sd_buf = ctypes.create_string_buffer(64)
        try:
            if not self._advapi32.InitializeSecurityDescriptor(
                    sd_buf, self._SECURITY_DESCRIPTOR_REVISION):
                raise self._fail("InitializeSecurityDescriptor")
            if not self._advapi32.SetSecurityDescriptorDacl(
                    sd_buf, True, new_acl, False):
                raise self._fail("SetSecurityDescriptorDacl")
        except TransportNotAvailableError:
            self._kernel32.LocalFree(new_acl)
            raise
        sa = _SecurityAttributes()
        sa.nLength = ctypes.sizeof(_SecurityAttributes)
        sa.lpSecurityDescriptor = ctypes.cast(sd_buf, ctypes.c_void_p)
        sa.bInheritHandle = False
        # Keep the descriptor, the ACL and the SID buffers alive for
        # the pipe's lifetime (see __init__ note).
        self._sa_keepalive = (sd_buf, new_acl, sid_buffers, sa)
        return sa

    # -- pipe lifetime ----------------------------------------------------

    def create_pipe(self, pipe_path: str, sa) -> int:
        handle = self._kernel32.CreateNamedPipeW(
            pipe_path,
            self._PIPE_ACCESS_DUPLEX,
            self._PIPE_TYPE_MESSAGE | self._PIPE_READMODE_MESSAGE
            | self._PIPE_WAIT,
            self._PIPE_UNLIMITED_INSTANCES,
            65536,  # out buffer
            65536,  # in buffer
            0,      # default timeout (client WaitNamedPipe default)
            ctypes.byref(sa),
        )
        if handle == _INVALID_HANDLE_VALUE:
            raise self._fail("CreateNamedPipeW")
        return handle

    def wait_for_client(self, handle: int, stop) -> bool:
        """Block until a client connects (overlapped, stop-aware).

        ``ConnectNamedPipe`` on a message-mode pipe blocks until a
        client connects, so it is issued overlapped against an event
        and polled every 500 ms: that is what lets ``stop`` end the
        wait without a client ever connecting. Returns False only
        when ``stop`` was set; a client that connects between
        ``CreateNamedPipeW`` and ``ConnectNamedPipe`` reports
        ERROR_PIPE_CONNECTED and counts as connected.
        """
        event = self._kernel32.CreateEventW(None, True, False, None)
        if not event:
            raise self._fail("CreateEventW")
        overlapped = _Overlapped()
        overlapped.hEvent = event
        try:
            if self._kernel32.ConnectNamedPipe(
                    handle, ctypes.byref(overlapped)):
                return True
            err = ctypes.get_last_error()
            if err == self._ERROR_PIPE_CONNECTED:
                return True
            if err != self._ERROR_IO_PENDING:
                raise TransportNotAvailableError(
                    f"named-pipe server: ConnectNamedPipe failed "
                    f"(Win32 error {err}); refusing to serve"
                )
            while True:
                if stop is not None and stop.is_set():
                    # Drain the pending connect before returning so
                    # the OVERLAPPED struct is not freed mid-flight.
                    self._kernel32.CancelIoEx(handle, ctypes.byref(overlapped))
                    self._kernel32.WaitForSingleObject(event, self._INFINITE)
                    return False
                waited = self._kernel32.WaitForSingleObject(event, 500)
                if waited == self._WAIT_OBJECT_0:
                    nread = _DWORD(0)
                    if not self._kernel32.GetOverlappedResult(
                            handle, ctypes.byref(overlapped),
                            ctypes.byref(nread), True):
                        raise self._fail("GetOverlappedResult")
                    return True
                if waited == self._WAIT_TIMEOUT:
                    continue
                raise self._fail("WaitForSingleObject")
        finally:
            self._kernel32.CloseHandle(event)

    def read_available(self, handle: int, size: int) -> bytes:
        buf = ctypes.create_string_buffer(size)
        nread = _DWORD(0)
        if self._kernel32.ReadFile(handle, buf, size,
                                   ctypes.byref(nread), None):
            return buf.raw[:nread.value]
        err = ctypes.get_last_error()
        if err in (self._ERROR_BROKEN_PIPE, self._ERROR_NO_DATA):
            return b""  # client disconnected
        raise TransportNotAvailableError(
            f"named-pipe server: ReadFile failed (Win32 error {err})"
        )

    def write_all(self, handle: int, data: bytes) -> None:
        offset = 0
        while offset < len(data):
            nwritten = _DWORD(0)
            chunk = ctypes.create_string_buffer(
                data[offset:], len(data) - offset)
            if not self._kernel32.WriteFile(
                    handle, chunk, len(data) - offset,
                    ctypes.byref(nwritten), None):
                raise self._fail("WriteFile")
            if nwritten.value == 0:
                raise TransportNotAvailableError(
                    "named-pipe server: WriteFile wrote 0 bytes"
                )
            offset += nwritten.value

    def disconnect(self, handle: int) -> None:
        self._kernel32.DisconnectNamedPipe(handle)

    def close(self, handle: int) -> None:
        try:
            self._kernel32.CloseHandle(handle)
        finally:
            if self._sa_keepalive is not None:
                _, new_acl, _, _ = self._sa_keepalive
                self._kernel32.LocalFree(new_acl)
                self._sa_keepalive = None


_INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value


class _SidAndAttributes(ctypes.Structure):
    _fields_ = [
        ("Sid", ctypes.c_void_p),
        ("Attributes", _DWORD),
    ]


class _TokenUser(ctypes.Structure):
    _fields_ = [("User", _SidAndAttributes)]


class _Trustee(ctypes.Structure):
    class _SidUnion(ctypes.Union):
        _fields_ = [
            ("ptstrName", ctypes.c_wchar_p),
            ("pSid", ctypes.c_void_p),
        ]

    _fields_ = [
        ("pMultipleTrustee", ctypes.c_void_p),
        ("MultipleTrusteeOperation", _DWORD),
        ("TrusteeForm", _DWORD),
        ("TrusteeType", _DWORD),
        ("_u", _SidUnion),
    ]


class _ExplicitAccess(ctypes.Structure):
    _fields_ = [
        ("grfAccessPermissions", _DWORD),
        ("grfAccessMode", _DWORD),
        ("grfInheritance", _DWORD),
        ("Trustee", _Trustee),
    ]


class _SecurityAttributes(ctypes.Structure):
    _fields_ = [
        ("nLength", _DWORD),
        ("lpSecurityDescriptor", ctypes.c_void_p),
        ("bInheritHandle", _BOOL),
    ]


class _Overlapped(ctypes.Structure):
    _fields_ = [
        ("Internal", ctypes.c_ulonglong),
        ("InternalHigh", ctypes.c_ulonglong),
        ("Offset", _DWORD),
        ("OffsetHigh", _DWORD),
        ("hEvent", _HANDLE),
    ]


class NamedPipeListener:
    """Server side of a Windows named pipe, with a restrictive DACL.

    The pipe is created with ``CreateNamedPipeW`` and a
    ``SECURITY_ATTRIBUTES`` whose DACL grants read+write only to the
    current user and to local Administrators, and explicitly denies
    remote (NETWORK) logons — the named-pipe equivalent of the 0600
    Unix socket (R-017, ADR-010). The JSON-lines protocol is the
    same as the Unix-socket servers (:func:`encode_message` /
    :func:`decode_message`); every request is dispatched to
    ``handler`` (a ``request dict -> reply dict`` callable, e.g.
    ``policy.policyd.handle_request`` bound to its engine, or
    ``Daemon.handle_request``), which is responsible for the auth
    check, exactly as the Unix-socket servers are.

    FAIL CLOSED, at every step: if the Win32 API is unavailable, if
    the ACL cannot be built, or if the pipe cannot be created, the
    server refuses to start — an ACL-less pipe is never served.
    A failure mid-connection only ends that connection (the client
    disconnects; the server keeps listening), never the ACL.

    ``api`` is an injectable stand-in for the Win32 API (same
    methods as :class:`_CtypesWindowsPipeApi`); tests inject a fake
    so the accept loop and the fail-closed paths are verified on
    Linux. On a real Windows host ``api`` is always the real one.

    HONEST LIMIT: the real ``ctypes`` API class has never run on a
    Windows host (written and mock-verified on Linux only). The
    laptop run in docs/WINDOWS_TESTING.md §6 is what proves it.
    """

    def __init__(self, pipe_path: str, api=None):
        self.pipe_path = pipe_path
        self._api = api

    def listen(self, handler=None, stop=None) -> None:
        """Serve ``handler`` on the pipe until ``stop`` is set.

        ``stop`` is a :class:`threading.Event` (or None to serve
        forever). Returns when ``stop`` is set; raises
        :class:`TransportNotAvailableError` if the server cannot be
        started safely, and :class:`NotImplementedError` if the
        Win32 API is unavailable at all (e.g. this code running on
        a non-Windows host).
        """
        if not is_windows():
            raise TransportNotAvailableError(
                "named-pipe listener is not available on this platform "
                "(Windows only)"
            )
        api = self._api if self._api is not None else _load_windows_api()
        if handler is None:
            raise ValueError(
                "named-pipe listener needs a request handler "
                "(request dict -> reply dict); refusing to serve "
                "without one"
            )
        if stop is not None and stop.is_set():
            return
        try:
            sa = api.build_security_attributes()
        except TransportNotAvailableError:
            raise
        except Exception as exc:
            raise TransportNotAvailableError(
                "named-pipe server: cannot build the pipe ACL "
                f"({exc}); refusing to serve without a protected pipe"
            ) from exc
        try:
            handle = api.create_pipe(self.pipe_path, sa)
        except TransportNotAvailableError:
            raise
        except Exception as exc:
            raise TransportNotAvailableError(
                "named-pipe server: cannot create the pipe "
                f"({exc}); refusing to serve"
            ) from exc
        print(f"listening on named pipe {self.pipe_path}",
              file=sys.stderr, flush=True)
        try:
            while stop is None or not stop.is_set():
                try:
                    connected = api.wait_for_client(handle, stop)
                except TransportNotAvailableError:
                    raise
                except Exception as exc:
                    raise TransportNotAvailableError(
                        "named-pipe server: waiting for a client failed "
                        f"({exc})"
                    ) from exc
                if not connected:
                    break
                self._serve_one_connection(api, handle, handler, stop)
        finally:
            api.close(handle)

    def _serve_one_connection(self, api, handle, handler, stop) -> None:
        """Serve one connected client: lines in, replies out.

        Mirrors the Unix-socket servers: blank lines are skipped, a
        bad-JSON line gets an error reply (the connection stays up),
        a handler exception gets an error reply, and a client
        disconnect ends the connection. A read/write failure ends
        the connection, never the server.
        """
        buffer = bytearray()
        try:
            while stop is None or not stop.is_set():
                try:
                    chunk = api.read_available(handle, 65536)
                except TransportNotAvailableError:
                    break
                if not chunk:
                    break  # client disconnected
                buffer += chunk
                while b"\n" in buffer:
                    line, _, rest = buffer.partition(b"\n")
                    buffer = bytearray(rest)
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        request = decode_message(line)
                    except ValueError:
                        response = {"ok": False, "error": "invalid request"}
                    else:
                        try:
                            response = handler(request)
                        except Exception as exc:
                            response = {"ok": False,
                                        "error": f"handler error: {exc}"}
                    try:
                        api.write_all(handle, encode_message(response))
                    except TransportNotAvailableError:
                        return
        finally:
            api.disconnect(handle)
