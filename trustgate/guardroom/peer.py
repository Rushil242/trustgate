"""Which OS user is on the other end of a Unix socket, according to the kernel.

This is the one fact about the caller the agent cannot shape: it is not read
from the request, it is read from the connection. macOS and the BSDs provide
`getpeereid`; Linux provides `SO_PEERCRED`.
"""

from __future__ import annotations

import ctypes
import ctypes.util
import socket
import struct
import sys


def peer_uid(conn: socket.socket) -> int | None:
    """The peer's effective uid, or None if this platform cannot tell us."""
    if sys.platform.startswith("linux"):
        try:
            creds = conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
            _pid, uid, _gid = struct.unpack("3i", creds)
            return uid
        except OSError:
            return None
    try:
        libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)
        uid, gid = ctypes.c_uint32(), ctypes.c_uint32()
        if libc.getpeereid(conn.fileno(), ctypes.byref(uid), ctypes.byref(gid)) != 0:
            return None
        return uid.value
    except (OSError, AttributeError):
        return None
