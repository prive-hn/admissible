"""Launch a command behind a seccomp network boundary, or refuse to launch it.

This is the Linux half of :func:`separation_guards.network_denied_command`. It
installs an unprivileged seccomp-bpf filter that fails ``socket(AF_INET, …)``
and ``socket(AF_INET6, …)`` with ``EPERM`` -- the kernel refusing the call, not
the network declining to answer -- and then ``execve``s the wrapped command.
The filter is inherited across ``fork`` and ``execve``, so it binds the command
and every process underneath it, which is the depth a mutated build backend
that spawns its own client reaches.

Two properties matter and are not negotiable:

* ``AF_UNIX`` and every non-internet family stay open, so local IPC a build
  legitimately needs is untouched; only routes off the machine are cut.
* if the filter cannot be installed, the command is **not** run. A mutant that
  ran outside the boundary because the boundary was unavailable would be a
  silent hole, so an install failure exits non-zero without ``exec``ing.

seccomp needs no privilege once ``PR_SET_NO_NEW_PRIVS`` is set, so this works
for the unprivileged CI user and inside a default Docker/OrbStack container
alike. It is x86-64 and aarch64 aware; on any other architecture it declines
(returns no boundary) rather than install a filter it cannot reason about.
"""

from __future__ import annotations

import ctypes
import os
import struct
import sys

_PR_SET_NO_NEW_PRIVS = 38
_PR_SET_SECCOMP = 22
_SECCOMP_MODE_FILTER = 2

_AUDIT_ARCH_X86_64 = 0xC000003E
_AUDIT_ARCH_AARCH64 = 0xC00000B7
#: ``__NR_socket`` per architecture (the numbers differ, so the filter checks
#: ``arch`` before it trusts ``nr``; a mismatch means "not us, allow").
_NR_SOCKET = {_AUDIT_ARCH_X86_64: 41, _AUDIT_ARCH_AARCH64: 198}

_AF_INET = 2
_AF_INET6 = 10

# Classic-BPF opcodes and seccomp return values.
_LD_W_ABS = 0x20        # BPF_LD | BPF_W | BPF_ABS
_JMP_JEQ_K = 0x15       # BPF_JMP | BPF_JEQ | BPF_K
_RET_K = 0x06           # BPF_RET | BPF_K
_RET_ALLOW = 0x7FFF0000        # SECCOMP_RET_ALLOW
_RET_ERRNO = 0x00050000        # SECCOMP_RET_ERRNO
_EPERM = 1

# Byte offsets into ``struct seccomp_data``: nr (u32), arch (u32), then the
# instruction pointer (u64) before the six u64 args, so args[0] low word is 16.
_OFF_NR = 0
_OFF_ARCH = 4
_OFF_ARG0 = 16


def _machine_arch() -> int | None:
    machine = os.uname().machine
    if machine in ("x86_64", "amd64"):
        return _AUDIT_ARCH_X86_64
    if machine in ("aarch64", "arm64"):
        return _AUDIT_ARCH_AARCH64
    return None


def _program(arch: int) -> bytes:
    """The BPF program that fails an internet ``socket`` and allows the rest.

    Nine instructions: check the architecture is the one whose syscall numbers
    we know, then that the call is ``socket``, then that its domain is
    ``AF_INET``/``AF_INET6``; only that last conjunction returns ``EPERM``.
    Anything else -- a different arch, a different syscall, a ``AF_UNIX``
    socket -- falls through to ``ALLOW``.
    """

    instructions = [
        (_LD_W_ABS, 0, 0, _OFF_ARCH),
        (_JMP_JEQ_K, 0, 5, arch),               # not our arch -> ALLOW (idx 7)
        (_LD_W_ABS, 0, 0, _OFF_NR),
        (_JMP_JEQ_K, 0, 3, _NR_SOCKET[arch]),   # not socket() -> ALLOW (idx 7)
        (_LD_W_ABS, 0, 0, _OFF_ARG0),
        (_JMP_JEQ_K, 2, 0, _AF_INET),           # AF_INET  -> DENY (idx 8)
        (_JMP_JEQ_K, 1, 0, _AF_INET6),          # AF_INET6 -> DENY (idx 8)
        (_RET_K, 0, 0, _RET_ALLOW),             # idx 7
        (_RET_K, 0, 0, _RET_ERRNO | _EPERM),    # idx 8
    ]
    return b"".join(struct.pack("HBBI", *each) for each in instructions)


class _SockFprog(ctypes.Structure):
    _fields_ = [("len", ctypes.c_ushort), ("filter", ctypes.c_void_p)]


def install_network_seccomp() -> None:
    """Install the filter, or raise ``OSError`` if the platform will not take it."""

    arch = _machine_arch()
    if arch is None:
        raise OSError("seccomp network boundary: unsupported architecture "
                      f"{os.uname().machine!r}")
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(_PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0:
        raise OSError(ctypes.get_errno(), "PR_SET_NO_NEW_PRIVS failed")
    program = _program(arch)
    buffer = ctypes.create_string_buffer(program, len(program))
    fprog = _SockFprog(len(program) // 8, ctypes.cast(buffer, ctypes.c_void_p))
    if libc.prctl(_PR_SET_SECCOMP, _SECCOMP_MODE_FILTER, ctypes.byref(fprog),
                  0, 0) != 0:
        raise OSError(ctypes.get_errno(), "PR_SET_SECCOMP failed")


def main(argv: list[str]) -> int:
    if not argv:
        sys.stderr.write("network_boundary_launch: no command to run\n")
        return 2
    try:
        install_network_seccomp()
    except OSError as error:
        # Never exec the command without the boundary: a mutant that reached the
        # network because the guard was missing is exactly what this prevents.
        sys.stderr.write(f"network_boundary_launch: no boundary: {error}\n")
        return 3
    try:
        os.execvp(argv[0], argv)
    except OSError as error:
        sys.stderr.write(f"network_boundary_launch: exec failed: {error}\n")
        return 4


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
