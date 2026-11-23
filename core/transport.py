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
  The *server* side is shape-only this round (see
  :class:`NamedPipeListener`): the stdlib cannot create a named pipe
  with a restrictive ACL, so serving on Windows refuses to start
  until a ``ctypes`` implementation with a current-user-only ACL
  lands and is verified on a Windows host. Failing closed here is
  deliberate — an ACL-less pipe would let any local process talk to
  policyd/the daemon (SECURITY.md adversary 5).

This module is stdlib-only and imports nothing from ``core`` or
``policy``, so the separate policyd process can import it without
dragging in the Gateway/Runtime.
"""

from __future__ import annotations

import json
import platform
import socket
from pathlib import Path

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
# Server listener — named-pipe side is SHAPE ONLY this round
# ---------------------------------------------------------------------------

class NamedPipeListener:
    """Server side of a Windows named pipe — shape only, do not serve.

    SECURITY — REQUIRED before any real Windows deployment, and the
    reason this class refuses to listen: a named pipe is local IPC, so
    it does not open an inbound *network* port (SECURITY.md inv. 5),
    but without an ACL any local process could connect to policyd or
    the daemon and issue policy decisions (SECURITY.md adversary 5:
    a local low-privilege process hijacking the daemon). The pipe
    MUST be created with an ACL granting access only to the current
    user — the named-pipe equivalent of the 0600 Unix socket.

    The stdlib cannot set that ACL. The real implementation must use
    ``ctypes`` ``CreateNamedPipeW`` with a ``SECURITY_ATTRIBUTES``
    holding a security descriptor whose DACL allows only the current
    user's SID (build with ``GetTokenInformation`` /
    ``SetSecurityDescriptorDacl``), then per connection
    ``ConnectNamedPipe`` / ``ReadFile`` / ``WriteFile`` /
    ``DisconnectNamedPipe``, speaking the same JSON-lines protocol
    (:func:`encode_message` / :func:`decode_message`). That
    implementation must be verified on a real Windows host (laptop)
    before policyd/the daemon serve on Windows; until then
    :meth:`listen` fails closed.
    """

    def __init__(self, pipe_path: str):
        self.pipe_path = pipe_path

    def listen(self) -> None:
        """Fail closed: the pipe server is not implemented yet."""
        if not is_windows():
            raise TransportNotAvailableError(
                "named-pipe listener is not available on this platform "
                "(Windows only)"
            )
        raise NotImplementedError(
            "named-pipe listener is not implemented yet: it requires "
            "ctypes CreateNamedPipeW with a current-user-only ACL (see "
            "core/transport.py NamedPipeListener) and must be verified "
            "on a Windows host; refusing to serve without the ACL"
        )
