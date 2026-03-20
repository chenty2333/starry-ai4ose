#!/usr/bin/env python3

import argparse
import collections
import datetime as dt
import errno
import fcntl
import hashlib
import os
import pathlib
import queue
import re
import select
import shutil
import socket
import subprocess
import sys
import threading
import time
from dataclasses import dataclass
from functools import lru_cache


PROMPT = "starry:~#"
SERIAL_PORT = 4444
ANSI_RE = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]")
BASELINE_ARCH = "riscv64"
BASELINE_APP_FEATURES = "qemu,lab"
BASELINE_ACCEL = "n"
BASELINE_NET = "n"
BASELINE_ICOUNT = "y"
BASELINE_SMP = "1"
BASELINE_RANDOM_SEED = "0123456789abcdef0123456789abcdef"
RUNNER_HOST = "10.0.2.2"
UDP_PORT = 34567
TCP_PORT = 34568
HTTP_PORT = 34569
SSH_POLL_PORT = 34570
SSH_SELECT_PORT = 34571
SSHD_PORT = 5555
REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
WORKING_DISK_IMG = REPO_ROOT / "make" / "disk.img"
LAB_BIN_DIR = REPO_ROOT / ".lab-bin"
PTY_HELPER_SOURCE = REPO_ROOT / "scripts" / "lab-helpers" / "pty_relay.c"
WAITCTL_HELPER_SOURCE = REPO_ROOT / "scripts" / "lab-helpers" / "waitctl.c"
PTY_HELPER_GUEST = "/usr/bin/lab_pty_relay"
WAITCTL_HELPER_GUEST = "/usr/bin/lab_waitctl"
DROPBEAR_ATTR = "nixpkgs#pkgsCross.riscv64-musl.dropbear"
DROPBEAR_STAGE_DIR = LAB_BIN_DIR / "dropbear"
SSH_KEY_STAGE_DIR = LAB_BIN_DIR / "ssh"
DROPBEAR_GUEST = "/usr/bin/lab_dropbear"
DROPBEARKEY_GUEST = "/usr/bin/lab_dropbearkey"
DROPBEAR_LIB_GUEST_DIR = "/usr/lib/ssh-lab"
DROPBEAR_LIBCRYPT_GUEST = f"{DROPBEAR_LIB_GUEST_DIR}/libcrypt.so.2"
DROPBEAR_LOG_GUEST = "/tmp/lab_dropbear.log"
DROPBEARKEY_LOG_GUEST = "/tmp/lab_dropbearkey.log"
DROPBEAR_HOSTKEY_GUEST = "/root/dropbear_ed25519_host_key"
AUTHORIZED_KEYS_GUEST = "/root/.ssh/authorized_keys"
SSHD_PHASE1_TOKEN = "__LAB_SSH_PHASE1_CONNECTED__"
SSHD_PHASE2_TOKEN = "__LAB_SSH_PHASE2_PTY__"
SSHD_PHASE3_TOKEN = "sshd-lab"
SSHD_PHASE2_LINES: tuple[str, ...] = (
    "PS1=",
    "export PS1",
    f"printf '{SSHD_PHASE2_TOKEN}\\n'",
    "exit",
)
SSHD_PHASE3_LINES: tuple[str, ...] = (
    "PS1=",
    "export PS1",
    f"sh -c 'sleep 1 & wait $!; printf \"{SSHD_PHASE3_TOKEN}\\\\n\"'",
    "exit",
)

TTY_CTL_NAMES: dict[int, str] = {
    1: "TIOCSCTTY",
    2: "TIOCSPGRP",
    3: "TIOCNOTTY",
}

UDP_SCRIPT_LINES: tuple[str, ...] = (
    "#!/bin/sh",
    "rm -f /tmp/udp.out",
    f"timeout 5 sh -c \"printf 'udp-lab' | nc -u -w 1 {RUNNER_HOST} {UDP_PORT} >/tmp/udp.out 2>/dev/null || true\" || true",
    "cat /tmp/udp.out",
)

TCP_SCRIPT_LINES: tuple[str, ...] = (
    "#!/bin/sh",
    "rm -f /tmp/tcp.out",
    f"timeout 5 sh -c \"{{ printf 'tcp-lab\\n'; sleep 1; }} | nc -w 2 {RUNNER_HOST} {TCP_PORT} >/tmp/tcp.out 2>/dev/null || true\" || true",
    "head -n 1 /tmp/tcp.out",
)

HTTP_SCRIPT_LINES: tuple[str, ...] = (
    "#!/bin/sh",
    f"wget -q -O - http://{RUNNER_HOST}:{HTTP_PORT}",
)

PTY_SCRIPT_LINES: tuple[str, ...] = (
    "#!/bin/sh",
    f"{PTY_HELPER_GUEST} -n /bin/sh -c 'echo pty-lab'",
)

JOBCTL_SCRIPT_LINES: tuple[str, ...] = (
    "#!/bin/sh",
    f"{PTY_HELPER_GUEST} -j /bin/sh -i",
)

SSH_POLL_SCRIPT_LINES: tuple[str, ...] = (
    "#!/bin/sh",
    f"{PTY_HELPER_GUEST} -t {RUNNER_HOST}:{SSH_POLL_PORT} /bin/sh",
)

SSH_SELECT_SCRIPT_LINES: tuple[str, ...] = (
    "#!/bin/sh",
    f"{PTY_HELPER_GUEST} -s -t {RUNNER_HOST}:{SSH_SELECT_PORT} /bin/sh",
)

WAITCTL_SCRIPT_LINES: tuple[str, ...] = (
    "#!/bin/sh",
    f"{WAITCTL_HELPER_GUEST}",
)


@dataclass(frozen=True)
class Demo:
    name: str
    goal: str
    commands: tuple[str, ...]
    expected_events: tuple[str, ...]
    focus_events: tuple[str, ...]
    focus_syscalls: tuple[str, ...] = ()
    setup_commands: tuple[str, ...] = ()
    focus_page_fault_arg0: str | None = None
    focus_signal_arg0: str | None = None
    net: str = "n"


@dataclass(frozen=True)
class TraceEvent:
    seq: int
    time_ns: int
    tid: int
    kind: str
    arg0: str
    arg1: str


@dataclass(frozen=True)
class EventView:
    event: TraceEvent
    label: str
    detail: str


@dataclass(frozen=True)
class RunResult:
    out_dir: pathlib.Path
    events: list[TraceEvent]
    event_views: list[EventView]
    stats_text: str
    last_fault_text: str
    key_events: list[TraceEvent]
    key_views: list[EventView]
    input_stream: tuple[str, ...]
    net: str
    peer_notes: tuple[str, ...]
    phase_results: tuple["PhaseResult", ...] = ()


@dataclass(frozen=True)
class PhaseResult:
    name: str
    title: str
    out_dir: pathlib.Path
    events: list[TraceEvent]
    event_views: list[EventView]
    key_events: list[TraceEvent]
    key_views: list[EventView]
    stats_text: str
    last_fault_text: str
    input_stream: tuple[str, ...]
    walkthrough: tuple[str, ...]


@dataclass(frozen=True)
class PeerResult:
    notes: tuple[str, ...]
    transcript: str = ""
    returncode: int = 0


@dataclass(frozen=True)
class PeerController:
    thread: threading.Thread
    results: "queue.Queue[PeerResult]"

    def finish(self, timeout: float) -> PeerResult:
        try:
            result = self.results.get(timeout=timeout)
        except queue.Empty:
            result = PeerResult(notes=("runner peer timed out waiting for guest traffic.",))
        self.thread.join(timeout=0.1)
        return result


def shell_quote(raw: str) -> str:
    return "'" + raw.replace("'", "'\"'\"'") + "'"


def build_script_setup(path: str, lines: tuple[str, ...]) -> tuple[str, ...]:
    commands = [f"rm -f {path}"]
    for index, line in enumerate(lines):
        redirect = ">" if index == 0 else ">>"
        commands.append(f"printf '%s\\n' {shell_quote(line)} {redirect}{path}")
    commands.append(f"chmod +x {path}")
    return tuple(commands)


UDP_SETUP_COMMANDS = build_script_setup("/tmp/lab_udp_demo.sh", UDP_SCRIPT_LINES)
TCP_SETUP_COMMANDS = build_script_setup("/tmp/lab_tcp_echo.sh", TCP_SCRIPT_LINES)
HTTP_SETUP_COMMANDS = build_script_setup("/tmp/lab_http_once.sh", HTTP_SCRIPT_LINES)
PTY_SETUP_COMMANDS = build_script_setup("/tmp/lab_pty_demo.sh", PTY_SCRIPT_LINES)
JOBCTL_SETUP_COMMANDS = build_script_setup("/tmp/lab_jobctl_demo.sh", JOBCTL_SCRIPT_LINES)
SSH_POLL_SETUP_COMMANDS = build_script_setup("/tmp/lab_ssh_poll_demo.sh", SSH_POLL_SCRIPT_LINES)
SSH_SELECT_SETUP_COMMANDS = build_script_setup(
    "/tmp/lab_ssh_select_demo.sh", SSH_SELECT_SCRIPT_LINES
)
WAITCTL_SETUP_COMMANDS = build_script_setup("/tmp/lab_waitctl_demo.sh", WAITCTL_SCRIPT_LINES)


DEMOS: dict[str, Demo] = {
    "pipe": Demo(
        name="pipe",
        goal="Show how a tiny shell pipeline drives fork/exec, pipe usage, and wakeups.",
        commands=("echo hi | cat",),
        expected_events=("SysEnter", "SysExit", "FdOpen", "FdClose", "PollSleep", "PollWake"),
        focus_events=("FdOpen", "FdClose", "PollSleep", "PollWake", "TaskExit"),
        focus_syscalls=(),
        setup_commands=(),
        focus_page_fault_arg0=None,
        focus_signal_arg0=None,
        net="n",
    ),
    "wait": Demo(
        name="wait",
        goal="Show child execution, blocking, and wait-based completion.",
        commands=("sleep 1 & wait",),
        expected_events=("SysEnter", "SysExit", "TaskExit", "ProcessGroupSet", "PollSleep", "PollWake"),
        focus_events=("PollSleep", "PollWake", "TaskExit", "ProcessGroupSet", "WaitReap", "SignalSend", "SignalHandle"),
        focus_syscalls=(),
        setup_commands=(),
        focus_page_fault_arg0=None,
        focus_signal_arg0=None,
        net="n",
    ),
    "fd": Demo(
        name="fd",
        goal="Show the current process fd view and the Starry Lab fd snapshot side by side.",
        commands=("ls -l /proc/self/fd", "cat /proc/starry/fd"),
        expected_events=("SysEnter", "SysExit", "FdOpen", "FdClose"),
        focus_events=("FdOpen", "FdClose"),
        focus_syscalls=(),
        setup_commands=(),
        focus_page_fault_arg0=None,
        focus_signal_arg0=None,
        net="n",
    ),
    "fault": Demo(
        name="fault",
        goal="Show a deliberate fault path through page-fault recording, SIGSEGV delivery, and task exit.",
        commands=("sh -c 'echo 1 > /proc/starry/fault_demo' || true",),
        expected_events=("PageFault", "SignalSend", "SignalHandle", "TaskExit"),
        focus_events=("PageFault", "SignalSend", "SignalHandle", "TaskExit"),
        focus_syscalls=(),
        setup_commands=(),
        focus_page_fault_arg0="0xdeadbeef",
        focus_signal_arg0="0xb",
        net="n",
    ),
    "udp": Demo(
        name="udp",
        goal="Show one datagram crossing the guest stack and bouncing off the runner-side UDP peer.",
        commands=("timeout 5 sh /tmp/lab_udp_demo.sh 2>/dev/null || true",),
        expected_events=("SysEnter", "SysExit", "FdOpen", "FdClose", "PollSleep", "PollWake"),
        focus_events=("FdOpen", "FdClose", "PollSleep", "PollWake", "TaskExit"),
        focus_syscalls=("socket", "sendto", "recvfrom", "close"),
        setup_commands=UDP_SETUP_COMMANDS,
        focus_page_fault_arg0=None,
        focus_signal_arg0=None,
        net="y",
    ),
    "tcp": Demo(
        name="tcp",
        goal="Show one guest TCP connection against a runner-side echo peer.",
        commands=("sh /tmp/lab_tcp_echo.sh 2>/dev/null || true",),
        expected_events=("SysEnter", "SysExit", "FdOpen", "FdClose", "PollSleep", "PollWake"),
        focus_events=("FdOpen", "FdClose", "PollSleep", "PollWake", "TaskExit"),
        focus_syscalls=("socket", "connect", "read", "write", "close"),
        setup_commands=TCP_SETUP_COMMANDS,
        focus_page_fault_arg0=None,
        focus_signal_arg0=None,
        net="y",
    ),
    "http": Demo(
        name="http",
        goal="Show a one-shot HTTP request/response against a runner-side HTTP peer.",
        commands=("timeout 5 sh /tmp/lab_http_once.sh 2>/dev/null || true",),
        expected_events=("SysEnter", "SysExit", "FdOpen", "FdClose", "PollSleep", "PollWake"),
        focus_events=("FdOpen", "FdClose", "PollSleep", "PollWake", "TaskExit"),
        focus_syscalls=("socket", "connect", "read", "write", "close"),
        setup_commands=HTTP_SETUP_COMMANDS,
        focus_page_fault_arg0=None,
        focus_signal_arg0=None,
        net="y",
    ),
    "pty": Demo(
        name="pty",
        goal="Show a shell process launched over a freshly created pty pair.",
        commands=("sh /tmp/lab_pty_demo.sh 2>/dev/null || true",),
        expected_events=("PtyOpen", "SessionCreate", "TtyCtl", "TaskExit"),
        focus_events=("PtyOpen", "SessionCreate", "TtyCtl", "ProcessGroupSet", "PollSleep", "PollWake", "TaskExit"),
        focus_syscalls=(),
        setup_commands=PTY_SETUP_COMMANDS,
        focus_page_fault_arg0=None,
        focus_signal_arg0=None,
        net="n",
    ),
    "jobctl": Demo(
        name="jobctl",
        goal="Drive an interactive shell over a pty and exercise Ctrl-Z/fg/Ctrl-C job-control paths.",
        commands=("sh /tmp/lab_jobctl_demo.sh 2>/dev/null || true",),
        expected_events=(
            "PtyOpen",
            "SessionCreate",
            "TtyCtl",
            "ProcessGroupSet",
            "SignalSend",
            "SignalHandle",
            "WaitStop",
            "WaitReap",
            "TaskExit",
        ),
        focus_events=(
            "PtyOpen",
            "SessionCreate",
            "TtyCtl",
            "ProcessGroupSet",
            "SignalSend",
            "SignalHandle",
            "WaitStop",
            "WaitReap",
            "PollSleep",
            "PollWake",
            "TaskExit",
        ),
        focus_syscalls=("wait4", "read", "write", "ioctl", "close"),
        setup_commands=JOBCTL_SETUP_COMMANDS,
        focus_page_fault_arg0=None,
        focus_signal_arg0=None,
        net="n",
    ),
    "waitctl": Demo(
        name="waitctl",
        goal="Exercise explicit wait4 stopped/continued/reap semantics with a tiny helper process tree.",
        commands=("sh /tmp/lab_waitctl_demo.sh 2>/dev/null || true",),
        expected_events=("SignalSend", "SignalHandle", "WaitContinue", "WaitReap", "TaskExit"),
        focus_events=("SignalSend", "SignalHandle", "WaitContinue", "WaitReap", "TaskExit"),
        focus_syscalls=("wait4", "kill", "close"),
        setup_commands=WAITCTL_SETUP_COMMANDS,
        focus_page_fault_arg0=None,
        focus_signal_arg0=None,
        net="n",
    ),
    "ssh-poll": Demo(
        name="ssh-poll",
        goal="Show a socket-backed pty relay using poll/ppoll between the runner peer and an interactive shell.",
        commands=("sh /tmp/lab_ssh_poll_demo.sh 2>/dev/null || true",),
        expected_events=(
            "PtyOpen",
            "SessionCreate",
            "TtyCtl",
            "ProcessGroupSet",
            "WaitReap",
            "PollSleep",
            "PollWake",
            "TaskExit",
        ),
        focus_events=(
            "PtyOpen",
            "SessionCreate",
            "TtyCtl",
            "ProcessGroupSet",
            "WaitReap",
            "SignalSend",
            "SignalHandle",
            "PollSleep",
            "PollWake",
            "TaskExit",
        ),
        focus_syscalls=("socket", "connect", "read", "write", "wait4", "close"),
        setup_commands=SSH_POLL_SETUP_COMMANDS,
        focus_page_fault_arg0=None,
        focus_signal_arg0=None,
        net="y",
    ),
    "ssh-select": Demo(
        name="ssh-select",
        goal="Show a socket-backed pty relay using select/pselect6 between the runner peer and an interactive shell.",
        commands=("sh /tmp/lab_ssh_select_demo.sh 2>/dev/null || true",),
        expected_events=(
            "PtyOpen",
            "SessionCreate",
            "TtyCtl",
            "ProcessGroupSet",
            "WaitReap",
            "PollSleep",
            "PollWake",
            "TaskExit",
        ),
        focus_events=(
            "PtyOpen",
            "SessionCreate",
            "TtyCtl",
            "ProcessGroupSet",
            "WaitReap",
            "SignalSend",
            "SignalHandle",
            "PollSleep",
            "PollWake",
            "TaskExit",
        ),
        focus_syscalls=("socket", "connect", "read", "write", "wait4", "close"),
        setup_commands=SSH_SELECT_SETUP_COMMANDS,
        focus_page_fault_arg0=None,
        focus_signal_arg0=None,
        net="y",
    ),
    "sshd": Demo(
        name="sshd",
        goal="Bring up a real Dropbear SSH server in the guest and log in from the host with an interactive pty-backed shell.",
        commands=(),
        expected_events=(
            "PtyOpen",
            "SessionCreate",
            "TtyCtl",
            "ProcessGroupSet",
            "WaitReap",
            "PollSleep",
            "PollWake",
            "TaskExit",
        ),
        focus_events=(
            "PtyOpen",
            "SessionCreate",
            "TtyCtl",
            "ProcessGroupSet",
            "WaitReap",
            "SignalSend",
            "SignalHandle",
            "PollSleep",
            "PollWake",
            "TaskExit",
        ),
        focus_syscalls=("socket", "bind", "listen", "accept", "accept4", "read", "write", "wait4", "close"),
        setup_commands=(),
        focus_page_fault_arg0=None,
        focus_signal_arg0=None,
        net="y",
    ),
}

ARTIFACT_COMMANDS: tuple[tuple[str, str], ...] = (
    ("starry_stats.txt", "cat /proc/starry/stats"),
    ("starry_trace.txt", "cat /proc/starry/trace"),
    ("starry_last_fault.txt", "cat /proc/starry/last_fault"),
    ("starry_fd.txt", "cat /proc/starry/fd"),
)

SYSCALL_FIRST_ARG_LABELS: dict[str, str] = {
    "close": "fd",
    "dup": "oldfd",
    "dup3": "oldfd",
    "epoll_create1": "flags",
    "epoll_ctl": "epfd",
    "epoll_pwait": "epfd",
    "eventfd2": "initval",
    "execve": "path",
    "fcntl": "fd",
    "futex": "uaddr",
    "ioctl": "fd",
    "kill": "pid",
    "lseek": "fd",
    "nanosleep": "req",
    "newfstatat": "dirfd",
    "openat": "dirfd",
    "pipe2": "pipefd",
    "ppoll": "nfds",
    "pselect6": "nfds",
    "read": "fd",
    "readlinkat": "dirfd",
    "rt_sigaction": "signum",
    "rt_sigprocmask": "how",
    "rt_sigreturn": "frame",
    "set_tid_address": "tidptr",
    "wait4": "pid",
    "waitid": "which",
    "write": "fd",
}

SIGNAL_ACTIONS: dict[int, str] = {
    1: "terminate",
    2: "core dump",
    3: "stop",
    4: "continue",
    5: "user handler",
}

PAGE_FAULT_FLAGS: tuple[tuple[int, str], ...] = (
    (1 << 0, "READ"),
    (1 << 1, "WRITE"),
    (1 << 2, "EXECUTE"),
    (1 << 3, "USER"),
    (1 << 4, "DEVICE"),
    (1 << 5, "UNCACHED"),
)


class Session:
    def __init__(self, sock: socket.socket):
        self.sock = sock
        self.log = ""

    def recv_until(self, marker: str, timeout: float, start: int = 0) -> str:
        self.sock.settimeout(timeout)
        end = dt.datetime.now() + dt.timedelta(seconds=timeout)
        while marker not in self.log[start:]:
            if dt.datetime.now() >= end:
                raise TimeoutError(f"Timed out waiting for marker: {marker!r}")
            chunk = self.sock.recv(4096).decode("utf-8", errors="ignore")
            if not chunk:
                raise ConnectionError("Serial connection closed")
            self.log += chunk.replace("\r", "")
        return self.log

    def wait_for_prompt(self, timeout: float, start: int = 0) -> str:
        return self.recv_until(PROMPT, timeout, start)

    def run_command(self, command: str, timeout: float) -> str:
        marker = f"__LAB_DONE__{time.time_ns()}__"
        wrapped = f"{command}\nprintf${{IFS}}'\\n{marker}:%s\\n'${{IFS}}$?\n"
        start = len(self.log)
        self.sock.sendall(wrapped.encode("utf-8"))
        self.recv_until(marker, timeout, start)
        marker_index = self.log.index(marker, start)
        self.wait_for_prompt(timeout, marker_index)
        return self.log[start:marker_index]


def wait_for_qemu_start(proc: subprocess.Popen[str], timeout: float) -> None:
    ready = threading.Event()

    def worker() -> None:
        assert proc.stderr is not None
        for line in proc.stderr:
            print(line, file=sys.stderr, end="")
            if "QEMU waiting for connection" in line:
                ready.set()
        ready.set()

    thread = threading.Thread(target=worker, daemon=True)
    thread.start()

    if not ready.wait(timeout=timeout):
        raise TimeoutError("QEMU did not start in time")
    if proc.poll() is not None:
        raise RuntimeError("QEMU exited before the serial server was ready")


def ensure_working_disk(arch: str) -> pathlib.Path:
    if WORKING_DISK_IMG.exists():
        return WORKING_DISK_IMG

    source = REPO_ROOT / f"rootfs-{arch}.img"
    if not source.exists():
        raise FileNotFoundError(f"missing rootfs image: {source}")
    WORKING_DISK_IMG.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source, WORKING_DISK_IMG)
    return WORKING_DISK_IMG


def compile_helper(source: pathlib.Path, output_name: str, arch: str) -> pathlib.Path:
    LAB_BIN_DIR.mkdir(parents=True, exist_ok=True)
    output = LAB_BIN_DIR / f"{output_name}-{arch}"
    compiler = f"{arch}-linux-musl-gcc"
    subprocess.run(
        [
            compiler,
            "-O2",
            "-Wall",
            "-Wextra",
            "-static",
            "-s",
            "-o",
            str(output),
            str(source),
        ],
        check=True,
    )
    output.chmod(0o755)
    return output


def nix_build_output(attr: str) -> pathlib.Path:
    completed = subprocess.run(
        ["nix", "build", "--no-link", "--print-out-paths", attr],
        check=True,
        capture_output=True,
        text=True,
    )
    lines = [line.strip() for line in completed.stdout.splitlines() if line.strip()]
    if not lines:
        raise RuntimeError(f"nix build did not return an output path for {attr}")
    return pathlib.Path(lines[-1])


def read_rpath(binary: pathlib.Path) -> tuple[str, ...]:
    completed = subprocess.run(
        ["patchelf", "--print-rpath", str(binary)],
        check=True,
        capture_output=True,
        text=True,
    )
    rendered = completed.stdout.strip()
    if not rendered:
        return ()
    return tuple(part for part in rendered.split(":") if part)


def prepare_dropbear_assets(arch: str) -> tuple[pathlib.Path, pathlib.Path, pathlib.Path]:
    if arch != BASELINE_ARCH:
        raise RuntimeError(f"unsupported arch for dropbear assets: {arch}")

    package = nix_build_output(DROPBEAR_ATTR)
    dropbear_src = package / "bin" / "dropbear"
    dropbearkey_src = package / "bin" / "dropbearkey"
    rpath = read_rpath(dropbear_src)
    libcrypt_dir = next((pathlib.Path(part) for part in rpath if "libxcrypt" in part), None)
    if libcrypt_dir is None:
        raise RuntimeError("failed to locate libxcrypt directory in dropbear RUNPATH")
    libcrypt_src = libcrypt_dir / "libcrypt.so.2"

    stage_dir = DROPBEAR_STAGE_DIR / arch
    stage_dir.mkdir(parents=True, exist_ok=True)
    dropbear_dst = stage_dir / "lab_dropbear"
    dropbearkey_dst = stage_dir / "lab_dropbearkey"
    libcrypt_dst = stage_dir / "libcrypt.so.2"

    for path in (dropbear_dst, dropbearkey_dst, libcrypt_dst):
        if path.exists():
            path.chmod(0o755)
            path.unlink()

    shutil.copy2(dropbear_src, dropbear_dst)
    shutil.copy2(dropbearkey_src, dropbearkey_dst)
    shutil.copy2(libcrypt_src, libcrypt_dst)

    for binary in (dropbear_dst, dropbearkey_dst):
        binary.chmod(0o755)
        subprocess.run(
            [
                "patchelf",
                "--set-interpreter",
                "/lib/ld-musl-riscv64.so.1",
                "--set-rpath",
                f"{DROPBEAR_LIB_GUEST_DIR}:/usr/lib:/lib",
                str(binary),
            ],
            check=True,
        )
    libcrypt_dst.chmod(0o644)
    return dropbear_dst, dropbearkey_dst, libcrypt_dst


def ensure_ssh_client_key() -> tuple[pathlib.Path, str]:
    SSH_KEY_STAGE_DIR.mkdir(parents=True, exist_ok=True)
    private_key = SSH_KEY_STAGE_DIR / "client_ed25519"
    public_key = SSH_KEY_STAGE_DIR / "client_ed25519.pub"
    if not private_key.exists() or not public_key.exists():
        subprocess.run(
            [
                "ssh-keygen",
                "-q",
                "-t",
                "ed25519",
                "-N",
                "",
                "-C",
                "starry-lab",
                "-f",
                str(private_key),
            ],
            check=True,
        )
    return private_key, public_key.read_text(encoding="utf-8").strip()


def debugfs_run(img: pathlib.Path, command: str, *, check: bool = False) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["debugfs", "-w", "-R", command, str(img)],
        check=check,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        text=True,
    )


def debugfs_mkdir(img: pathlib.Path, guest_dir: str) -> None:
    parts = [part for part in guest_dir.split("/") if part]
    current = ""
    for part in parts:
        current += "/" + part
        debugfs_run(img, f"mkdir {current}")


def debugfs_write(img: pathlib.Path, local: pathlib.Path, guest: str) -> None:
    debugfs_run(img, f"rm {guest}")
    debugfs_run(img, f"write {local} {guest}", check=True)


def ensure_guest_helpers(demo: Demo, arch: str) -> None:
    if demo.name not in {"pty", "jobctl", "waitctl", "ssh-poll", "ssh-select", "sshd"}:
        return
    img = ensure_working_disk(arch)
    if demo.name in {"pty", "jobctl", "ssh-poll", "ssh-select"}:
        helper = compile_helper(PTY_HELPER_SOURCE, "pty-relay", arch)
        debugfs_write(img, helper, PTY_HELPER_GUEST)
    if demo.name == "waitctl":
        helper = compile_helper(WAITCTL_HELPER_SOURCE, "waitctl", arch)
        debugfs_write(img, helper, WAITCTL_HELPER_GUEST)
    if demo.name == "sshd":
        dropbear, dropbearkey, libcrypt = prepare_dropbear_assets(arch)
        debugfs_mkdir(img, DROPBEAR_LIB_GUEST_DIR)
        debugfs_write(img, dropbear, DROPBEAR_GUEST)
        debugfs_write(img, dropbearkey, DROPBEARKEY_GUEST)
        debugfs_write(img, libcrypt, DROPBEAR_LIBCRYPT_GUEST)


def run_build(arch: str) -> None:
    subprocess.run(
        ["make", f"ARCH={arch}", f"APP_FEATURES={BASELINE_APP_FEATURES}", "NET=y", "build"],
        check=True,
    )


def spawn_qemu(arch: str, net: str) -> subprocess.Popen[str]:
    return subprocess.Popen(
        [
            "make",
            f"ARCH={arch}",
            f"APP_FEATURES={BASELINE_APP_FEATURES}",
            f"NET={net}",
            f"ACCEL={BASELINE_ACCEL}",
            f"ICOUNT={BASELINE_ICOUNT}",
            f"SMP={BASELINE_SMP}",
            "justrun",
            f"QEMU_ARGS=-snapshot -monitor none -serial tcp::{SERIAL_PORT},server=on",
        ],
        stderr=subprocess.PIPE,
        text=True,
    )


def write_text(path: pathlib.Path, content: str) -> None:
    path.write_text(content, encoding="utf-8")


def clean_capture(text: str, command: str | None = None) -> str:
    text = ANSI_RE.sub("", text).replace("\r", "")
    lines = text.splitlines()
    cleaned: list[str] = []
    for line in lines:
        stripped = line.strip()
        if not stripped:
            cleaned.append(line)
            continue
        if command is not None and stripped == command:
            continue
        if "__LAB_DONE__" in stripped:
            continue
        if PROMPT in line:
            prefix = line.split(PROMPT, 1)[0].rstrip()
            if prefix.strip():
                cleaned.append(prefix)
            continue
        if stripped == "$?":
            continue
        cleaned.append(line)

    while cleaned and not cleaned[0].strip():
        cleaned.pop(0)
    while cleaned and not cleaned[-1].strip():
        cleaned.pop()
    return "\n".join(cleaned) + ("\n" if cleaned else "")


def normalize_demo_output(demo: Demo, text: str) -> str:
    if demo.name not in {"pty", "jobctl", "ssh-poll", "ssh-select", "sshd"}:
        return text
    drop = {
        "echo pty-lab",
        "sleep 30",
        "jobs",
        "fg",
        "echo jobctl-lab",
        "echo ssh-lab",
        "PS1=",
        "export PS1",
        f"printf '{SSHD_PHASE2_TOKEN}\\n'",
        r"printf${IFS}sshd-lab\\n",
        r"printf${IFS}ssh-lab\\n",
        f"sh -c 'sleep 1 & wait $!; printf \"{SSHD_PHASE3_TOKEN}\\\\n\"'",
        "sleep 1 & wait",
        r"sleep${IFS}1&wait",
        "sleep 1 &",
        r"sleep${IFS}1&",
        "wait $!",
        r"wait${IFS}$!",
        "exit",
        "Connection to 127.0.0.1 closed.",
        "Welcome to Alpine!",
        "The Alpine Wiki contains a large amount of how-to guides a general",
        "information about administrating Alpine systems.",
        "See <https://wiki.alnelinux.org/>.",
        "You can setup the system with the command: setup-alpine",
        "You change this message by editing /etc/motd.",
    }
    kept = []
    for line in text.splitlines():
        candidate = line.strip()
        if candidate.startswith(PROMPT):
            candidate = candidate.split(PROMPT, 1)[1].strip()
        if not candidate:
            continue
        if candidate in drop:
            continue
        kept.append(candidate)
    while kept and not kept[0].strip():
        kept.pop(0)
    while kept and not kept[-1].strip():
        kept.pop()
    if demo.name == "jobctl":
        normalized: list[str] = []
        saw_stopped = False
        for line in kept:
            candidate = line
            if "Stopped" in candidate:
                if saw_stopped:
                    continue
                saw_stopped = True
                candidate = "[1]+  Stopped                    sleep 30"
            normalized.append(candidate)
        kept = normalized
    return "\n".join(kept) + ("\n" if kept else "")


def clean_remote_shell_transcript(text: str) -> str:
    text = ANSI_RE.sub("", text).replace("\r", "")
    kept = [line.rstrip() for line in text.splitlines() if line.strip()]
    while kept and not kept[0].strip():
        kept.pop(0)
    while kept and not kept[-1].strip():
        kept.pop()
    return "\n".join(kept) + ("\n" if kept else "")


def parse_trace(text: str) -> list[TraceEvent]:
    events: list[TraceEvent] = []
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    if not lines:
        return events
    for line in lines:
        parts = line.split("\t")
        if len(parts) != 6:
            continue
        if parts[0] == "seq":
            continue
        try:
            events.append(
                TraceEvent(
                    seq=int(parts[0]),
                    time_ns=int(parts[1]),
                    tid=int(parts[2]),
                    kind=parts[3],
                    arg0=parts[4],
                    arg1=parts[5],
                )
            )
        except ValueError:
            continue
    return events


def parse_usize(raw: str) -> int:
    return int(raw, 0)


def parse_i64(raw: str) -> int:
    value = parse_usize(raw)
    if value >= 1 << 63:
        value -= 1 << 64
    return value


def format_signed(raw: str) -> str:
    value = parse_i64(raw)
    return str(value)


def format_small_int(raw: str) -> str:
    value = parse_usize(raw)
    if value < 4096:
        return str(value)
    return raw


def format_fd(raw: str) -> str:
    return str(parse_usize(raw))


def format_errno_or_value(raw: str) -> str:
    value = parse_i64(raw)
    if value < 0:
        err_name = errno.errorcode.get(-value)
        if err_name is not None:
            return f"{value} ({err_name})"
        return str(value)
    if value < 4096:
        return str(value)
    return raw


def format_at_dirfd(raw: str) -> str:
    value = parse_i64(raw)
    if value == -100:
        return "AT_FDCWD"
    return str(value)


def format_signal(raw: str) -> str:
    value = parse_usize(raw)
    name = load_signal_names().get(value)
    if name is None:
        return str(value)
    return f"{name} ({value})"


def format_signal_action(raw: str) -> str:
    value = parse_usize(raw)
    action = SIGNAL_ACTIONS.get(value)
    if action is None:
        return str(value)
    return f"{action} ({value})"


def format_page_fault_flags(raw: str) -> str:
    value = parse_usize(raw)
    labels = [label for bit, label in PAGE_FAULT_FLAGS if value & bit]
    if not labels:
        return raw
    return "|".join(labels)


def format_exit_status(raw: str) -> str:
    value = parse_i64(raw)
    if value < 0:
        return str(value)
    if value >= 128:
        signo = value - 128
        signame = load_signal_names().get(signo)
        if signame is not None:
            return f"{value} ({signame})"
    return str(value)


def format_boolish(raw: str) -> str:
    return "yes" if parse_usize(raw) != 0 else "no"


def first_arg_label(syscall_name: str) -> str:
    return SYSCALL_FIRST_ARG_LABELS.get(syscall_name, "arg0")


@lru_cache(maxsize=1)
def load_syscall_names() -> dict[int, str]:
    mapping: dict[int, str] = {}
    base = pathlib.Path.home() / ".cargo" / "registry" / "src"
    pattern = re.compile(r"^\s*([A-Za-z0-9_]+)\s*=\s*(\d+),\s*$")
    candidates = sorted(base.glob("*/syscalls-*/src/arch/riscv64.rs"))
    if not candidates:
        return mapping
    for line in candidates[-1].read_text(encoding="utf-8").splitlines():
        match = pattern.match(line)
        if match is not None:
            mapping[int(match.group(2))] = match.group(1)
    return mapping


@lru_cache(maxsize=1)
def load_signal_names() -> dict[int, str]:
    mapping: dict[int, str] = {}
    base = pathlib.Path.home() / ".cargo" / "registry" / "src"
    pattern = re.compile(r"^\s*([A-Za-z0-9_]+)\s*=\s*(\d+),\s*$")
    candidates = sorted(base.glob("*/starry-signal-*/src/types.rs"))
    if not candidates:
        return mapping
    for line in candidates[-1].read_text(encoding="utf-8").splitlines():
        match = pattern.match(line)
        if match is not None:
            mapping[int(match.group(2))] = match.group(1)
    return mapping


def syscall_name(raw: str) -> str:
    value = parse_usize(raw)
    return load_syscall_names().get(value, raw)


def describe_syscall_enter(event: TraceEvent) -> str:
    name = syscall_name(event.arg0)
    label = first_arg_label(name)
    first_arg = event.arg1
    if name == "openat":
        rendered = format_at_dirfd(first_arg)
    elif name in {"close", "dup", "dup3", "read", "write", "fcntl", "ioctl", "epoll_pwait"}:
        rendered = format_fd(first_arg)
    elif name in {"ppoll", "pselect6"}:
        rendered = format_small_int(first_arg)
    elif name in {"rt_sigaction", "kill"}:
        rendered = format_signal(first_arg) if name == "rt_sigaction" else format_signed(first_arg)
    elif name in {"wait4", "waitid"}:
        rendered = format_signed(first_arg)
    else:
        rendered = first_arg
    return f"{name}({label}={rendered})"


def describe_syscall_exit(event: TraceEvent) -> str:
    return f"{syscall_name(event.arg0)} -> {format_errno_or_value(event.arg1)}"


def describe_poll_event(event: TraceEvent, active_syscall: str | None) -> str:
    syscall = active_syscall or "poll-like wait"
    amount = format_small_int(event.arg0)
    if event.kind == "PollSleep":
        if active_syscall == "epoll_pwait":
            return f"{syscall} blocked on epfd={amount}"
        unit = "fd slot(s)" if active_syscall == "pselect6" else "fd(s)"
        return f"{syscall} blocked on {amount} {unit}"
    return f"{syscall} woke with {amount} ready source(s)"


def describe_page_fault(event: TraceEvent) -> str:
    return f"addr={event.arg0} flags={format_page_fault_flags(event.arg1)}"


def describe_signal_send(event: TraceEvent) -> str:
    return f"send {format_signal(event.arg0)} to target={format_small_int(event.arg1)}"


def describe_signal_handle(event: TraceEvent) -> str:
    return f"handle {format_signal(event.arg0)} via {format_signal_action(event.arg1)}"


def describe_fd_open(event: TraceEvent) -> str:
    return f"fd={format_fd(event.arg0)} cloexec={format_boolish(event.arg1)}"


def describe_fd_close(event: TraceEvent) -> str:
    return f"fd={format_fd(event.arg0)}"


def describe_task_exit(event: TraceEvent) -> str:
    return f"status={format_exit_status(event.arg0)} group_exit={format_boolish(event.arg1)}"


def describe_session_create(event: TraceEvent) -> str:
    return f"setsid -> sid={format_small_int(event.arg0)} pgid={format_small_int(event.arg1)}"


def describe_process_group_set(event: TraceEvent) -> str:
    return f"setpgid(pid={format_small_int(event.arg0)}, pgid={format_small_int(event.arg1)})"


def describe_wait_reap(event: TraceEvent) -> str:
    return f"wait4 reaped pid={format_small_int(event.arg0)} status={format_exit_status(event.arg1)}"


def describe_wait_stop(event: TraceEvent) -> str:
    return f"wait4 observed stop pid={format_small_int(event.arg0)} status={format_exit_status(event.arg1)}"


def describe_wait_continue(event: TraceEvent) -> str:
    return f"wait4 observed continue pid={format_small_int(event.arg0)} status={format_exit_status(event.arg1)}"


def describe_pty_open(event: TraceEvent) -> str:
    return f"open /dev/ptmx -> fd={format_fd(event.arg0)} pty={format_small_int(event.arg1)}"


def describe_tty_ctl(event: TraceEvent) -> str:
    op = TTY_CTL_NAMES.get(parse_usize(event.arg0), event.arg0)
    return f"{op} value={format_small_int(event.arg1)}"


def build_event_views(events: list[TraceEvent]) -> list[EventView]:
    views: list[EventView] = []
    active_syscalls: dict[int, str] = {}
    for event in events:
        if event.kind == "SysEnter":
            detail = describe_syscall_enter(event)
            active_syscalls[event.tid] = syscall_name(event.arg0)
        elif event.kind == "SysExit":
            detail = describe_syscall_exit(event)
            active_syscalls.pop(event.tid, None)
        elif event.kind in {"PollSleep", "PollWake"}:
            detail = describe_poll_event(event, active_syscalls.get(event.tid))
        elif event.kind == "PageFault":
            detail = describe_page_fault(event)
        elif event.kind == "SignalSend":
            detail = describe_signal_send(event)
        elif event.kind == "SignalHandle":
            detail = describe_signal_handle(event)
        elif event.kind == "FdOpen":
            detail = describe_fd_open(event)
        elif event.kind == "FdClose":
            detail = describe_fd_close(event)
        elif event.kind == "TaskExit":
            detail = describe_task_exit(event)
        elif event.kind == "SessionCreate":
            detail = describe_session_create(event)
        elif event.kind == "ProcessGroupSet":
            detail = describe_process_group_set(event)
        elif event.kind == "WaitReap":
            detail = describe_wait_reap(event)
        elif event.kind == "WaitStop":
            detail = describe_wait_stop(event)
        elif event.kind == "WaitContinue":
            detail = describe_wait_continue(event)
        elif event.kind == "PtyOpen":
            detail = describe_pty_open(event)
        elif event.kind == "TtyCtl":
            detail = describe_tty_ctl(event)
        else:
            detail = f"arg0={event.arg0} arg1={event.arg1}"
        views.append(EventView(event=event, label=event.kind, detail=detail))
    return views


def select_key_events(demo: Demo, events: list[TraceEvent]) -> list[TraceEvent]:
    selected = [event for event in events if event.kind in demo.focus_events]
    if demo.focus_page_fault_arg0 is not None:
        keep = {
            event.seq
            for event in selected
            if event.kind != "PageFault" or event.arg0 == demo.focus_page_fault_arg0
        }
        selected = [event for event in selected if event.seq in keep]
    else:
        page_faults = [event for event in selected if event.kind == "PageFault"]
        if len(page_faults) > 8:
            keep = {event.seq for event in page_faults[-8:]}
            selected = [
                event for event in selected if event.kind != "PageFault" or event.seq in keep
            ]
    if demo.focus_signal_arg0 is not None:
        keep = {
            event.seq
            for event in selected
            if event.kind not in {"SignalSend", "SignalHandle"} or event.arg0 == demo.focus_signal_arg0
        }
        selected = [event for event in selected if event.seq in keep]
    return selected


def render_aligned_table(
    headers: tuple[str, ...],
    rows: list[tuple[str, ...]],
    aligns: tuple[str, ...] | None = None,
) -> str:
    widths = [len(header) for header in headers]
    for row in rows:
        for index, cell in enumerate(row):
            widths[index] = max(widths[index], len(cell))

    if aligns is None:
        aligns = tuple(">" if index < 2 else "<" for index in range(len(headers)))

    def format_row(row: tuple[str, ...]) -> str:
        parts: list[str] = []
        for index, cell in enumerate(row):
            align = aligns[index] if index < len(aligns) else "<"
            parts.append(f"{cell:{align}{widths[index]}}")
        return "  ".join(parts)

    divider = "  ".join("-" * width for width in widths)
    lines = [format_row(headers), divider]
    lines.extend(format_row(row) for row in rows)
    return "\n".join(lines) + "\n"


def select_key_views(demo: Demo, views: list[EventView]) -> list[EventView]:
    selected = select_key_events(demo, [view.event for view in views])
    network_tids: set[int] = set()
    if demo.name in {"udp", "tcp", "http"}:
        seed_syscalls = {"socket", "connect", "sendto", "recvfrom"}
        for view in views:
            if view.label != "SysEnter":
                continue
            name = syscall_name(view.event.arg0)
            if name not in seed_syscalls:
                continue
            network_tids.add(view.event.tid)

    keep = {
        event.seq
        for event in selected
        if not network_tids or event.tid in network_tids
    }
    pending_syscalls: dict[int, str] = {}
    if demo.focus_syscalls:
        for view in views:
            if view.label == "SysEnter":
                name = syscall_name(view.event.arg0)
                if name not in demo.focus_syscalls:
                    continue
                if network_tids and view.event.tid not in network_tids:
                    continue
                if name in {"read", "write", "close"} and parse_i64(view.event.arg1) in {0, 1, 2}:
                    continue
                keep.add(view.event.seq)
                pending_syscalls[view.event.tid] = name
                continue
            if view.label != "SysExit":
                continue
            if network_tids and view.event.tid not in network_tids:
                continue
            name = syscall_name(view.event.arg0)
            if pending_syscalls.get(view.event.tid) == name:
                keep.add(view.event.seq)
                pending_syscalls.pop(view.event.tid, None)
    selected_views = [view for view in views if view.event.seq in keep]
    if demo.name == "tcp":
        eof_tids: set[int] = set()
        trimmed: list[EventView] = []
        for view in selected_views:
            tid = view.event.tid
            syscall = syscall_name(view.event.arg0) if view.label in {"SysEnter", "SysExit"} else None
            if tid in eof_tids:
                if view.label == "FdClose" or (view.label in {"SysEnter", "SysExit"} and syscall == "close"):
                    trimmed.append(view)
                continue
            trimmed.append(view)
            if view.label == "SysExit" and syscall == "read" and parse_i64(view.event.arg1) == 0:
                eof_tids.add(tid)
        selected_views = trimmed
    if demo.name in {"ssh-poll", "ssh-select", "sshd"}:
        trimmed = []
        pending_io: dict[tuple[int, str], EventView] = {}
        for view in selected_views:
            if view.label == "SysEnter":
                name = syscall_name(view.event.arg0)
                if name in {"read", "write"}:
                    pending_io[(view.event.tid, name)] = view
                    continue
                trimmed.append(view)
                continue
            if view.label == "SysExit":
                name = syscall_name(view.event.arg0)
                key = (view.event.tid, name)
                if name in {"read", "write"}:
                    enter = pending_io.pop(key, None)
                    if abs(parse_i64(view.event.arg1)) == 1:
                        continue
                    if enter is not None:
                        trimmed.append(enter)
                    trimmed.append(view)
                    continue
            trimmed.append(view)
        selected_views = trimmed
        collapsed: list[EventView] = []
        burst_signatures: set[tuple[int, str, str]] = set()
        for view in selected_views:
            if view.label in {"PollSleep", "PollWake"}:
                signature = (view.event.tid, view.label, view.detail)
                if signature in burst_signatures:
                    continue
                burst_signatures.add(signature)
                collapsed.append(view)
                continue
            burst_signatures.clear()
            collapsed.append(view)
        selected_views = collapsed
    return selected_views


def render_key_trace(path: pathlib.Path, demo: Demo, views: list[EventView]) -> list[EventView]:
    selected = select_key_views(demo, views)
    rows = [
        (str(view.event.seq), str(view.event.tid), view.label, view.detail)
        for view in selected
    ]
    write_text(
        path,
        render_aligned_table(
            ("seq", "tid", "event", "detail"),
            rows,
            aligns=(">", ">", "<", "<"),
        ),
    )
    return selected


def select_sshd_phase_views(phase_name: str, views: list[EventView]) -> list[EventView]:
    if phase_name == "phase-1-connect":
        focus_syscalls = {"accept", "accept4", "close", "read", "write"}
        network_tids: set[int] = set()
        for view in views:
            if view.label != "SysEnter":
                continue
            name = syscall_name(view.event.arg0)
            if name in {"accept", "accept4"}:
                network_tids.add(view.event.tid)
        keep: set[int] = set()
        pending_syscalls: dict[int, str] = {}
        for view in views:
            if network_tids and view.event.tid not in network_tids and view.label in {"SysEnter", "SysExit", "PollSleep", "PollWake", "TaskExit"}:
                continue
            if view.label == "SysEnter":
                name = syscall_name(view.event.arg0)
                if name in focus_syscalls:
                    if name == "close" and parse_usize(view.event.arg0) >= (1 << 63):
                        continue
                    if name in {"read", "write"} and parse_i64(view.event.arg1) in {0, 1, 2}:
                        continue
                    keep.add(view.event.seq)
                    pending_syscalls[view.event.tid] = name
                continue
            if view.label == "SysExit":
                name = syscall_name(view.event.arg0)
                if pending_syscalls.get(view.event.tid) == name:
                    if name == "close" and parse_i64(view.event.arg1) == -9:
                        pending_syscalls.pop(view.event.tid, None)
                        continue
                    if name in {"read", "write"} and abs(parse_i64(view.event.arg1)) == 1:
                        pending_syscalls.pop(view.event.tid, None)
                        continue
                    keep.add(view.event.seq)
                    pending_syscalls.pop(view.event.tid, None)
                continue
            if view.label in {"PollSleep", "PollWake", "TaskExit"}:
                keep.add(view.event.seq)
        return [
            view
            for view in views
            if view.event.seq in keep and "18446744073709551615" not in view.detail
        ]

    if phase_name == "phase-2-pty":
        keep_labels = {"PtyOpen", "SessionCreate", "TtyCtl", "ProcessGroupSet", "TaskExit"}
        return [view for view in views if view.label in keep_labels]

    if phase_name == "phase-3-shell":
        keep_labels = {
            "ProcessGroupSet",
            "WaitStop",
            "WaitContinue",
            "WaitReap",
            "SignalSend",
            "SignalHandle",
            "PollSleep",
            "PollWake",
            "TaskExit",
        }
        focus_syscalls = {"read", "write", "wait4", "close"}
        keep: set[int] = {view.event.seq for view in views if view.label in keep_labels}
        pending_syscalls: dict[int, str] = {}
        for view in views:
            if view.label == "SysEnter":
                name = syscall_name(view.event.arg0)
                if name in focus_syscalls:
                    if name in {"read", "write"} and parse_i64(view.event.arg1) in {0, 1, 2}:
                        continue
                    keep.add(view.event.seq)
                    pending_syscalls[view.event.tid] = name
                continue
            if view.label == "SysExit":
                name = syscall_name(view.event.arg0)
                if pending_syscalls.get(view.event.tid) == name:
                    if name in {"read", "write"} and abs(parse_i64(view.event.arg1)) == 1:
                        pending_syscalls.pop(view.event.tid, None)
                        continue
                    keep.add(view.event.seq)
                    pending_syscalls.pop(view.event.tid, None)
        selected = [view for view in views if view.event.seq in keep]
        collapsed: list[EventView] = []
        burst_signatures: set[tuple[int, str, str]] = set()
        for view in selected:
            if view.label in {"PollSleep", "PollWake"}:
                signature = (view.event.tid, view.label, view.detail)
                if signature in burst_signatures:
                    continue
                burst_signatures.add(signature)
                collapsed.append(view)
                continue
            burst_signatures.clear()
            collapsed.append(view)
        return collapsed

    return views


def render_event_table(views: list[EventView]) -> str:
    rows = [
        (str(view.event.seq), str(view.event.tid), view.label, view.detail)
        for view in views
    ]
    return render_aligned_table(
        ("seq", "tid", "event", "detail"),
        rows,
        aligns=(">", ">", "<", "<"),
    )


def build_sshd_phase_walkthrough(
    phase_name: str,
    key_views: list[EventView],
    transcript: str,
) -> tuple[str, ...]:
    counts = collections.Counter(view.label for view in key_views)
    if phase_name == "phase-1-connect":
        accept_exit = next(
            (
                view
                for view in key_views
                if view.label == "SysExit" and syscall_name(view.event.arg0) in {"accept", "accept4"}
            ),
            None,
        )
        lines = [
            "this phase isolates the network half of SSH bring-up: server socket setup, accept, and the first authenticated session handoff.",
        ]
        if accept_exit is not None:
            lines.append(f"the server-side accept path completed as {accept_exit.detail}.")
        if transcript.strip():
            lines.append("the host-side remote command returned a success marker, which confirms the SSH transport and authentication path succeeded.")
        return tuple(lines)

    if phase_name == "phase-2-pty":
        pty_open = next((view for view in key_views if view.label == "PtyOpen"), None)
        session_create = next((view for view in key_views if view.label == "SessionCreate"), None)
        tty_ctls = [view for view in key_views if view.label == "TtyCtl"]
        pg_set = next((view for view in key_views if view.label == "ProcessGroupSet"), None)
        lines = [
            "this phase isolates the interactive shell bootstrap: pty allocation, new session creation, and controlling-terminal setup.",
        ]
        if pty_open is not None:
            lines.append(f"dropbear allocated the terminal side via {pty_open.detail}.")
        if session_create is not None:
            lines.append(f"the login shell created a new session with {session_create.detail}.")
        if tty_ctls:
            rendered = ", ".join(view.detail for view in tty_ctls[:3])
            lines.append(f"tty job-control setup flowed through {rendered}.")
        if pg_set is not None:
            lines.append(f"the foreground/background group path was visible as {pg_set.detail}.")
        return tuple(lines)

    if phase_name == "phase-3-shell":
        wait_stop = next((view for view in key_views if view.label == "WaitStop"), None)
        wait_continue = next((view for view in key_views if view.label == "WaitContinue"), None)
        wait_reap = next((view for view in key_views if view.label == "WaitReap"), None)
        task_exit = next((view for view in key_views if view.label == "TaskExit"), None)
        lines = [
            "this phase isolates the interactive shell workload: a background `sleep`, SIGCHLD delivery, `wait4` reaping, and session teardown.",
        ]
        if counts["SignalSend"] or counts["SignalHandle"]:
            lines.append(
                f"signal flow stayed visible with send={counts['SignalSend']} and handle={counts['SignalHandle']} event(s)."
            )
        if wait_stop is not None:
            lines.append(f"job-control stop handling surfaced through {wait_stop.detail}.")
        if wait_continue is not None:
            lines.append(f"job-control resume handling surfaced through {wait_continue.detail}.")
        if wait_reap is not None:
            lines.append(f"the shell-side wait path completed through {wait_reap.detail}.")
        if transcript.strip():
            lines.append("the remote transcript printed `sshd-lab`, so the interactive command stream crossed ssh socket -> pty -> shell -> pty -> ssh socket end to end.")
        if task_exit is not None:
            lines.append(f"the phase closed with {task_exit.detail}.")
        return tuple(lines)

    return ()


def create_phase_summary(
    path: pathlib.Path,
    title: str,
    input_stream: tuple[str, ...],
    events: list[TraceEvent],
    key_views: list[EventView],
    stats_text: str,
    walkthrough: tuple[str, ...],
) -> None:
    counts = collections.Counter(event.kind for event in events)
    stats = parse_tab_values(stats_text)
    lines = [
        f"title: {title}",
        f"trace_events: {len(events)}",
        "",
        "input stream:",
    ]
    lines.extend(f"- {cmd}" for cmd in input_stream)
    lines.append("")
    lines.append("walkthrough:")
    lines.extend(f"- {line}" for line in walkthrough or ("none",))
    lines.append("")
    lines.append("trace buffer:")
    for key in ("enabled", "emitted", "overwritten", "buffered"):
        if key in stats:
            lines.append(f"- {key}: {stats[key]}")
    lines.append("")
    lines.append("key trace preview:")
    if key_views:
        for view in key_views[:8]:
            lines.append(f"- seq={view.event.seq} tid={view.event.tid} {view.label}: {view.detail}")
    else:
        lines.append("- none")
    lines.append("")
    lines.append("event counts:")
    for kind, count in sorted(counts.items()):
        lines.append(f"- {kind}: {count}")
    write_text(path, "\n".join(lines) + "\n")


def render_sshd_phase_artifacts(
    phase_dir: pathlib.Path,
    phase_name: str,
    title: str,
    events: list[TraceEvent],
    stats_text: str,
    last_fault_text: str,
    input_stream: tuple[str, ...],
    transcript: str,
    raw: bool,
) -> PhaseResult:
    phase_dir.mkdir(parents=True, exist_ok=True)
    event_views = build_event_views(events)
    key_views = select_sshd_phase_views(phase_name, event_views)
    write_text(phase_dir / "key_trace.txt", render_event_table(key_views))
    walkthrough = build_sshd_phase_walkthrough(phase_name, key_views, transcript)
    create_phase_summary(
        phase_dir / "summary.txt",
        title,
        input_stream,
        events,
        key_views,
        stats_text,
        walkthrough,
    )
    if raw:
        trace_lines = [
            f"{event.seq}\t{event.time_ns}\t{event.tid}\t{event.kind}\t{event.arg0}\t{event.arg1}"
            for event in events
        ]
        write_text(phase_dir / "starry_trace.txt", "\n".join(trace_lines) + ("\n" if trace_lines else ""))
        write_text(phase_dir / "starry_stats.txt", stats_text)
        write_text(phase_dir / "starry_last_fault.txt", last_fault_text)
    return PhaseResult(
        name=phase_name,
        title=title,
        out_dir=phase_dir,
        events=events,
        event_views=event_views,
        key_events=[view.event for view in key_views],
        key_views=key_views,
        stats_text=stats_text,
        last_fault_text=last_fault_text,
        input_stream=input_stream,
        walkthrough=walkthrough,
    )


def render_sshd_key_trace(path: pathlib.Path, phase_results: tuple[PhaseResult, ...]) -> list[EventView]:
    sections: list[str] = []
    combined: list[EventView] = []
    for phase in phase_results:
        sections.append(f"== {phase.name}: {phase.title} ==")
        sections.append(render_event_table(phase.key_views))
        sections.append("")
        combined.extend(phase.key_views)
    write_text(path, "\n".join(section for section in sections if section is not None).rstrip() + "\n")
    return combined


def normalize_events(events: list[TraceEvent]) -> list[str]:
    tid_map: dict[int, str] = {}
    lines: list[str] = []
    for event in events:
        tid_label = tid_map.setdefault(event.tid, f"T{len(tid_map)}")
        lines.append(f"{tid_label}\t{event.kind}\t{event.arg0}\t{event.arg1}")
    return lines


def normalize_event_views(views: list[EventView]) -> list[str]:
    tid_map: dict[int, str] = {}
    lines: list[str] = []
    for view in views:
        tid_label = tid_map.setdefault(view.event.tid, f"T{len(tid_map)}")
        lines.append(f"{tid_label}\t{view.label}\t{view.detail}")
    return lines


def digest_lines(lines: list[str]) -> str:
    data = "\n".join(lines).encode("utf-8")
    return hashlib.sha256(data).hexdigest()[:16]


def compare_lines(reference: list[str], current: list[str]) -> tuple[bool, str]:
    shared = min(len(reference), len(current))
    for index in range(shared):
        if reference[index] != current[index]:
            return (
                False,
                f"first diff at line {index + 1}: ref={reference[index]!r} current={current[index]!r}",
            )
    if len(reference) != len(current):
        return (
            False,
            f"line count differs: ref={len(reference)} current={len(current)}",
        )
    return True, "exact match"


def parse_tab_values(text: str) -> dict[str, str]:
    result: dict[str, str] = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or "\t" not in line:
            continue
        key, value = line.split("\t", 1)
        result[key] = value
    return result


def shorten_payload(payload: bytes, limit: int = 60) -> str:
    rendered = payload.decode("utf-8", errors="replace").replace("\n", "\\n")
    if len(rendered) <= limit:
        return rendered
    return rendered[: limit - 3] + "..."


def start_udp_echo_peer() -> PeerController:
    results: "queue.Queue[PeerResult]" = queue.Queue()

    def worker() -> None:
        listener = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(("127.0.0.1", UDP_PORT))
        listener.settimeout(10)
        try:
            payload, addr = listener.recvfrom(4096)
            listener.sendto(payload, addr)
            results.put(
                PeerResult(
                    notes=(
                        f"runner UDP peer received {len(payload)} byte(s) and echoed `{shorten_payload(payload)}`.",
                    )
                )
            )
        except Exception as exc:
            results.put(PeerResult(notes=(f"runner UDP peer error: {exc}",)))
        finally:
            listener.close()

    thread = threading.Thread(target=worker, daemon=True)
    thread.start()
    return PeerController(thread=thread, results=results)


def start_tcp_echo_peer() -> PeerController:
    results: "queue.Queue[PeerResult]" = queue.Queue()

    def worker() -> None:
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(("127.0.0.1", TCP_PORT))
        listener.listen(1)
        listener.settimeout(10)
        try:
            conn, _addr = listener.accept()
            with conn:
                conn.settimeout(10)
                payload = conn.recv(4096)
                conn.sendall(payload)
                conn.shutdown(socket.SHUT_WR)
            results.put(
                PeerResult(
                    notes=(
                        f"runner TCP peer echoed {len(payload)} byte(s): `{shorten_payload(payload)}`.",
                    )
                )
            )
        except Exception as exc:
            results.put(PeerResult(notes=(f"runner TCP peer error: {exc}",)))
        finally:
            listener.close()

    thread = threading.Thread(target=worker, daemon=True)
    thread.start()
    return PeerController(thread=thread, results=results)


def start_http_peer() -> PeerController:
    results: "queue.Queue[PeerResult]" = queue.Queue()
    body = b"hello-http!"
    response = (
        b"HTTP/1.1 200 OK\r\n"
        + f"Content-Length: {len(body)}\r\n".encode("ascii")
        + b"Connection: close\r\n\r\n"
        + body
    )

    def worker() -> None:
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(("127.0.0.1", HTTP_PORT))
        listener.listen(1)
        listener.settimeout(10)
        try:
            conn, _addr = listener.accept()
            with conn:
                conn.settimeout(10)
                request = conn.recv(4096)
                conn.sendall(response)
                conn.shutdown(socket.SHUT_WR)
            first_line = request.splitlines()[0].decode("utf-8", errors="replace") if request else "no request line"
            results.put(
                PeerResult(
                    notes=(
                        f"runner HTTP peer served `{first_line}` with body `hello-http!`.",
                    )
                )
            )
        except Exception as exc:
            results.put(PeerResult(notes=(f"runner HTTP peer error: {exc}",)))
        finally:
            listener.close()

    thread = threading.Thread(target=worker, daemon=True)
    thread.start()
    return PeerController(thread=thread, results=results)


def start_shell_peer(port: int, label: str) -> PeerController:
    results: "queue.Queue[PeerResult]" = queue.Queue()
    script_lines = (r"printf${IFS}ssh-lab\\n", r"sleep${IFS}1&wait", "exit")

    def worker() -> None:
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(("127.0.0.1", port))
        listener.listen(1)
        listener.settimeout(10)
        try:
            conn, _addr = listener.accept()
            with conn:
                conn.settimeout(10)
                time.sleep(1.0)
                for line in script_lines:
                    for ch in (line + "\r"):
                        conn.sendall(ch.encode("utf-8"))
                        time.sleep(0.01)
                    time.sleep(0.2)
                conn.shutdown(socket.SHUT_WR)
                chunks: list[bytes] = []
                while True:
                    payload = conn.recv(4096)
                    if not payload:
                        break
                    chunks.append(payload)
            transcript = clean_remote_shell_transcript(b"".join(chunks).decode("utf-8", errors="ignore"))
            note = (
                f"runner {label} peer sent a shell script equivalent to `printf ssh-lab; sleep 1 & wait; exit` and captured {len(transcript.splitlines())} output line(s).",
            )
            results.put(PeerResult(notes=note, transcript=transcript))
        except Exception as exc:
            results.put(PeerResult(notes=(f"runner {label} peer error: {exc}",)))
        finally:
            listener.close()

    thread = threading.Thread(target=worker, daemon=True)
    thread.start()
    return PeerController(thread=thread, results=results)


def wait_for_tcp_port(host: str, port: int, timeout: float) -> None:
    deadline = time.monotonic() + timeout
    last_error: Exception | None = None
    while time.monotonic() < deadline:
        try:
            with socket.create_connection((host, port), timeout=0.5):
                return
        except OSError as exc:
            last_error = exc
            time.sleep(0.1)
    raise TimeoutError(f"timed out waiting for {host}:{port}: {last_error}")


def sshd_setup_commands(public_key: str) -> tuple[str, ...]:
    return (
        "mkdir /root/.ssh 2>/dev/null || true",
        "chmod 700 /root",
        "chmod 700 /root/.ssh",
        f"printf '%s\\n' {shell_quote(public_key)} > {AUTHORIZED_KEYS_GUEST}",
        f"chmod 600 {AUTHORIZED_KEYS_GUEST}",
        f"rm -f {DROPBEAR_LOG_GUEST} {DROPBEARKEY_LOG_GUEST} {DROPBEAR_HOSTKEY_GUEST}",
        f"{DROPBEARKEY_GUEST} -t ed25519 -f {DROPBEAR_HOSTKEY_GUEST} >{DROPBEARKEY_LOG_GUEST} 2>&1",
        f"chmod 600 {DROPBEAR_HOSTKEY_GUEST}",
        f"{DROPBEAR_GUEST} -E -F -s -p {SSHD_PORT} -r {DROPBEAR_HOSTKEY_GUEST} >{DROPBEAR_LOG_GUEST} 2>&1 &",
        "sleep 1",
    )


def ssh_common_command(private_key: pathlib.Path) -> list[str]:
    return [
        "ssh",
        "-p",
        str(SSHD_PORT),
        "-i",
        str(private_key),
        "-o",
        "BatchMode=yes",
        "-o",
        "IdentitiesOnly=yes",
        "-o",
        "StrictHostKeyChecking=no",
        "-o",
        "UserKnownHostsFile=/dev/null",
        "-o",
        "LogLevel=ERROR",
        "-o",
        "PreferredAuthentications=publickey",
        "-o",
        "ConnectTimeout=10",
    ]


def run_host_ssh_command(
    private_key: pathlib.Path,
    remote_command: str,
    timeout: float,
    success_token: str,
) -> PeerResult:
    command = ssh_common_command(private_key) + ["root@127.0.0.1", remote_command]
    completed = subprocess.run(
        command,
        capture_output=True,
        text=True,
        timeout=timeout,
    )
    rendered = clean_remote_shell_transcript((completed.stdout or "") + (completed.stderr or ""))
    if completed.returncode != 0 and success_token not in rendered:
        detail = rendered or f"ssh exited with status {completed.returncode}"
        raise RuntimeError(f"host ssh command failed: {detail}")
    notes = [
        "host OpenSSH authenticated with a temporary ed25519 key over the forwarded SSH port.",
        f"the host-side command transcript captured {len([line for line in rendered.splitlines() if line.strip()])} non-empty line(s).",
    ]
    if completed.returncode != 0:
        notes.append(
            f"the host ssh client exited with status {completed.returncode} after the remote command transcript completed."
        )
    return PeerResult(notes=tuple(notes), transcript=rendered, returncode=completed.returncode)


def run_host_ssh_demo(
    private_key: pathlib.Path,
    timeout: float,
    input_lines: tuple[str, ...],
    success_token: str,
) -> PeerResult:
    command = ssh_common_command(private_key) + ["-tt", "root@127.0.0.1"]
    master_fd, slave_fd = os.openpty()
    flags = fcntl.fcntl(master_fd, fcntl.F_GETFL)
    fcntl.fcntl(master_fd, fcntl.F_SETFL, flags | os.O_NONBLOCK)
    proc = subprocess.Popen(
        command,
        stdin=slave_fd,
        stdout=slave_fd,
        stderr=slave_fd,
        close_fds=True,
        start_new_session=True,
    )
    os.close(slave_fd)

    transcript = bytearray()
    lines = [line + "\r" for line in input_lines]
    line_index = 0
    char_index = 0
    next_send_at = time.monotonic() + 1.0
    delay_between_chars = 0.01
    delay_between_lines = 0.2
    deadline = time.monotonic() + timeout

    try:
        while time.monotonic() < deadline:
            now = time.monotonic()
            if line_index < len(lines) and now >= next_send_at:
                line = lines[line_index]
                os.write(master_fd, line[char_index].encode("utf-8"))
                char_index += 1
                if char_index == len(line):
                    line_index += 1
                    char_index = 0
                    next_send_at = now + delay_between_lines
                else:
                    next_send_at = now + delay_between_chars

            readable, _, _ = select.select([master_fd], [], [], 0.05)
            if master_fd in readable:
                try:
                    chunk = os.read(master_fd, 4096)
                except OSError as exc:
                    if exc.errno == errno.EIO:
                        chunk = b""
                    else:
                        raise
                if chunk:
                    transcript.extend(chunk)

            if proc.poll() is not None and line_index >= len(lines):
                try:
                    chunk = os.read(master_fd, 4096)
                    if chunk:
                        transcript.extend(chunk)
                        continue
                except OSError as exc:
                    if exc.errno != errno.EIO:
                        raise
                break
        else:
            proc.terminate()
            raise TimeoutError("host ssh demo timed out")
    finally:
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=1)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=1)
        os.close(master_fd)

    if proc.poll() is None:
        proc.wait(timeout=1)
    rendered = clean_remote_shell_transcript(transcript.decode("utf-8", errors="ignore"))
    if proc.returncode != 0 and success_token not in rendered:
        detail = rendered or f"ssh exited with status {proc.returncode}"
        raise RuntimeError(f"host ssh login failed: {detail}")
    notes = [
        "host OpenSSH authenticated with a temporary ed25519 key and opened a real remote pty-backed shell.",
        f"the host-side ssh transcript captured {len([line for line in rendered.splitlines() if line.strip()])} non-empty line(s).",
    ]
    if proc.returncode != 0:
        notes.append(f"the host ssh client exited with status {proc.returncode} after the remote transcript completed.")
    return PeerResult(notes=tuple(notes), transcript=rendered, returncode=proc.returncode)


def start_demo_peer(demo: Demo) -> PeerController | None:
    if demo.name == "udp":
        return start_udp_echo_peer()
    if demo.name == "tcp":
        return start_tcp_echo_peer()
    if demo.name == "http":
        return start_http_peer()
    if demo.name == "ssh-poll":
        return start_shell_peer(SSH_POLL_PORT, "ssh-poll")
    if demo.name == "ssh-select":
        return start_shell_peer(SSH_SELECT_PORT, "ssh-select")
    return None


def summarize_syscalls(events: list[TraceEvent]) -> list[str]:
    counts: collections.Counter[str] = collections.Counter()
    for event in events:
        if event.kind == "SysEnter":
            counts[syscall_name(event.arg0)] += 1
    ordered = sorted(counts.items(), key=lambda item: (-item[1], item[0]))
    return [f"{name}: {count}" for name, count in ordered[:8]]


def summarize_signals(events: list[TraceEvent]) -> list[str]:
    counts: collections.Counter[str] = collections.Counter()
    for event in events:
        if event.kind in {"SignalSend", "SignalHandle"}:
            counts[format_signal(event.arg0)] += 1
    ordered = sorted(counts.items(), key=lambda item: (-item[1], item[0]))
    return [f"{name}: {count}" for name, count in ordered]


def parse_fd_snapshot(text: str) -> int | None:
    entries = 0
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("fd\t") or stripped.startswith("fd "):
            continue
        entries += 1
    return entries or None


def find_syscall_view(
    views: list[EventView],
    *,
    syscall: str,
    label: str = "SysEnter",
    tid: int | None = None,
) -> EventView | None:
    for view in views:
        if view.label != label:
            continue
        if syscall_name(view.event.arg0) != syscall:
            continue
        if tid is not None and view.event.tid != tid:
            continue
        return view
    return None


def build_walkthrough(
    demo: Demo,
    event_views: list[EventView],
    key_views: list[EventView],
    artifact_outputs: dict[str, str],
    peer_notes: tuple[str, ...],
    phase_results: tuple[PhaseResult, ...] = (),
) -> list[str]:
    counts = collections.Counter(view.label for view in key_views)
    task_exits = [view for view in key_views if view.label == "TaskExit"]
    signal_events = [view for view in key_views if view.label in {"SignalSend", "SignalHandle"}]
    if demo.name == "pipe":
        lines = [
            f"pipeline setup touched {counts['FdOpen']} fd-open event(s) and {counts['FdClose']} fd-close event(s).",
            f"the blocking path slept {counts['PollSleep']} time(s) and woke {counts['PollWake']} time(s).",
        ]
        if task_exits:
            lines.append(f"{len(task_exits)} task exit event(s) closed out the pipeline workload.")
        return lines
    if demo.name == "wait":
        child_exit = next((view for view in task_exits), None)
        pg_set = next((view for view in key_views if view.label == "ProcessGroupSet"), None)
        wait_reap = next((view for view in key_views if view.label == "WaitReap"), None)
        child_tid = child_exit.event.tid if child_exit is not None else None
        sigchld_send = next(
            (view for view in key_views if view.label == "SignalSend" and view.event.arg0 == "0x11"),
            None,
        )
        sigchld_handle = next(
            (view for view in key_views if view.label == "SignalHandle" and view.event.arg0 == "0x11"),
            None,
        )
        parent_tid = None
        if sigchld_send is not None:
            parent_tid = parse_usize(sigchld_send.event.arg1)
        elif sigchld_handle is not None:
            parent_tid = sigchld_handle.event.tid

        clone_exit = find_syscall_view(event_views, syscall="clone", label="SysExit", tid=parent_tid)
        wait_enter = find_syscall_view(event_views, syscall="wait4", tid=parent_tid)
        suspend_enter = find_syscall_view(event_views, syscall="rt_sigsuspend", tid=parent_tid)
        child_exec = find_syscall_view(event_views, syscall="execve", tid=child_tid)
        child_sleep = (
            find_syscall_view(event_views, syscall="nanosleep", tid=child_tid)
            or find_syscall_view(event_views, syscall="clock_nanosleep", tid=child_tid)
        )

        lines: list[str] = []
        if parent_tid is not None and child_tid is not None:
            lines.append(
                f"shell task tid={parent_tid} launched a background child tid={child_tid} for `sleep 1`."
            )
        elif clone_exit is not None and parse_i64(clone_exit.event.arg1) > 0:
            lines.append(
                f"the shell cloned child tid={parse_i64(clone_exit.event.arg1)} to start the background job."
            )

        if pg_set is not None:
            lines.append(f"job-control setup included {pg_set.detail} before the shell went into its wait path.")

        if wait_enter is not None and suspend_enter is not None and parent_tid is not None:
            lines.append(
                f"parent tid={parent_tid} entered wait4(pid=-1) and then blocked in rt_sigsuspend waiting for child completion."
            )
        elif counts["PollSleep"] or counts["PollWake"]:
            lines.append(
                f"the wait path blocked {counts['PollSleep']} time(s) before wakeup {counts['PollWake']} time(s)."
            )

        if child_tid is not None and child_exec is not None and child_sleep is not None:
            sleep_name = syscall_name(child_sleep.event.arg0)
            lines.append(
                f"child tid={child_tid} execve'd the `sleep` workload and then called {sleep_name}, which is the core blocking step of `sleep 1`."
            )
        elif child_sleep is not None and child_tid is not None:
            lines.append(
                f"child tid={child_tid} reached {syscall_name(child_sleep.event.arg0)} and stayed asleep until the timer expired."
            )

        if child_exit is not None and sigchld_send is not None and parent_tid is not None:
            lines.append(
                f"when child tid={child_tid} exited with {child_exit.detail}, the kernel sent SIGCHLD to parent tid={parent_tid}."
            )
        elif child_exit is not None:
            lines.append(f"child completion showed up as {child_exit.detail}.")

        if wait_reap is not None:
            lines.append(f"the wait path finished by observing {wait_reap.detail}.")

        if sigchld_handle is not None and parent_tid is not None:
            lines.append(
                f"parent tid={parent_tid} handled SIGCHLD, its wait path resumed, and the shell regained control."
            )
        elif signal_events:
            lines.append("signal activity confirms the wait path observed child completion.")
        return lines
    if demo.name == "fd":
        fd_count = parse_fd_snapshot(artifact_outputs.get("starry_fd.txt", ""))
        lines = [
            "the demo captured both the user-side /proc/self/fd view and the kernel-side /proc/starry/fd snapshot.",
        ]
        if fd_count is not None:
            lines.append(f"the kernel snapshot listed {fd_count} live fd entries at capture time.")
        if counts["FdOpen"] or counts["FdClose"]:
            lines.append(
                f"fd lifecycle activity during capture: open={counts['FdOpen']} close={counts['FdClose']}."
            )
        return lines
    if demo.name == "fault":
        page_fault = next((view for view in key_views if view.label == "PageFault"), None)
        task_exit = next((view for view in key_views if view.label == "TaskExit"), None)
        lines = []
        if page_fault is not None:
            lines.append(f"the synthetic fault hook recorded {page_fault.detail}.")
        if signal_events:
            rendered = ", ".join(view.detail for view in signal_events[:2])
            lines.append(f"signal flow: {rendered}.")
        if task_exit is not None:
            lines.append(f"the crashing task ended with {task_exit.detail}.")
        return lines
    if demo.name == "waitctl":
        wait_stop = next((view for view in key_views if view.label == "WaitStop"), None)
        wait_continue = next((view for view in key_views if view.label == "WaitContinue"), None)
        wait_reap = next((view for view in key_views if view.label == "WaitReap"), None)
        lines = [
            "the helper forked one child, stopped it with SIGTSTP, resumed it with SIGCONT, and then terminated it with SIGINT.",
        ]
        if wait_stop is not None:
            lines.append(f"`wait4(..., WUNTRACED)` surfaced the stop through {wait_stop.detail}.")
        if wait_continue is not None:
            lines.append(f"`wait4(..., WCONTINUED)` surfaced the resume through {wait_continue.detail}.")
        if wait_reap is not None:
            lines.append(f"the final blocking wait reaped the child through {wait_reap.detail}.")
        if "waitctl-lab" in artifact_outputs.get("demo-step-1.txt", ""):
            lines.append("the helper printed `waitctl-lab`, so all three wait-status phases completed end to end.")
        return lines
    if demo.name == "udp":
        lines = [
            f"the guest sent one datagram to the runner-side UDP echo peer at {RUNNER_HOST}:{UDP_PORT}.",
            "the same guest socket path then received the echoed payload and printed it back to stdout.",
        ]
        lines.extend(peer_notes)
        return lines
    if demo.name == "tcp":
        lines = [
            f"the guest opened one TCP connection to the runner-side echo peer at {RUNNER_HOST}:{TCP_PORT}.",
            "the client wrote `tcp-lab` and then read the echoed line back into a temporary file before printing it.",
        ]
        lines.extend(peer_notes)
        return lines
    if demo.name == "http":
        lines = [
            f"`wget` connected to the runner-side HTTP peer at {RUNNER_HOST}:{HTTP_PORT}.",
            "the guest printed the fixed response body `hello-http!`, which makes the TCP path easier to demo as an application request/response flow.",
        ]
        lines.extend(peer_notes)
        return lines
    if demo.name == "pty":
        pty_open = next((view for view in key_views if view.label == "PtyOpen"), None)
        session_create = next((view for view in key_views if view.label == "SessionCreate"), None)
        tty_ctls = [view for view in key_views if view.label == "TtyCtl"]
        lines: list[str] = []
        if pty_open is not None:
            lines.append(f"the helper opened a fresh pseudo-terminal pair via {pty_open.detail}.")
        if session_create is not None:
            lines.append(f"the child shell process created a new session with {session_create.detail}.")
        if tty_ctls:
            rendered = ", ".join(view.detail for view in tty_ctls[:3])
            lines.append(f"tty job-control setup flowed through {rendered}.")
        if counts["PollSleep"] or counts["PollWake"]:
            lines.append(
                f"the relay path slept {counts['PollSleep']} time(s) and woke {counts['PollWake']} time(s) while moving bytes between master and slave."
            )
        if artifact_outputs.get("demo-step-1.txt", "").strip():
            lines.append("the pty-backed `/bin/sh -c 'echo pty-lab'` path printed `pty-lab`, which confirms the shell output crossed the slave/master boundary end to end.")
        lines.append("the relay returned without an outer timeout, so the master side observed the slave close and finished through the kernel's pty EOF/HUP path.")
        return lines
    if demo.name == "jobctl":
        pty_open = next((view for view in key_views if view.label == "PtyOpen"), None)
        session_create = next((view for view in key_views if view.label == "SessionCreate"), None)
        tty_ctls = [view for view in key_views if view.label == "TtyCtl"]
        wait_stop = next((view for view in key_views if view.label == "WaitStop"), None)
        wait_continue = next((view for view in key_views if view.label == "WaitContinue"), None)
        wait_reap = next((view for view in key_views if view.label == "WaitReap"), None)
        sigtstp = next(
            (view for view in key_views if view.label == "SignalHandle" and view.detail.startswith("handle SIGTSTP")),
            None,
        )
        sigcont = next(
            (view for view in key_views if view.label == "SignalHandle" and view.detail.startswith("handle SIGCONT")),
            None,
        )
        sigint = next(
            (view for view in key_views if view.label == "SignalHandle" and view.detail.startswith("handle SIGINT")),
            None,
        )
        lines: list[str] = []
        if pty_open is not None:
            lines.append(f"the helper opened a fresh pseudo-terminal pair via {pty_open.detail}.")
        if session_create is not None:
            lines.append(f"the interactive shell established its own session with {session_create.detail}.")
        if tty_ctls:
            rendered = ", ".join(view.detail for view in tty_ctls[:3])
            lines.append(f"controlling-tty setup flowed through {rendered}.")
        if sigtstp is not None:
            lines.append("typing Ctrl-Z on the pty generated SIGTSTP for the foreground job.")
        if wait_stop is not None:
            lines.append(f"the shell's wait4 path reported the stop through {wait_stop.detail}.")
        if sigcont is not None or wait_continue is not None:
            detail = wait_continue.detail if wait_continue is not None else "a SIGCONT-driven foreground resume"
            lines.append(f"`fg` resumed the stopped job, and the continue path showed up as {detail}.")
        if sigint is not None:
            lines.append("typing Ctrl-C after `fg` generated SIGINT for the resumed foreground job.")
        if wait_reap is not None:
            lines.append(f"the final child collection completed through {wait_reap.detail}.")
        if "jobctl-lab" in artifact_outputs.get("demo-step-1.txt", ""):
            lines.append("the shell printed `jobctl-lab` after the Ctrl-C/fg cycle, so the interactive job-control path really returned control to the shell.")
        return lines
    if demo.name in {"ssh-poll", "ssh-select"}:
        relay_name = "pselect6" if demo.name == "ssh-select" else "ppoll"
        pty_open = next((view for view in key_views if view.label == "PtyOpen"), None)
        session_create = next((view for view in key_views if view.label == "SessionCreate"), None)
        tty_ctls = [view for view in key_views if view.label == "TtyCtl"]
        pg_set = next((view for view in key_views if view.label == "ProcessGroupSet"), None)
        wait_reap = next((view for view in key_views if view.label == "WaitReap"), None)
        task_exit = next((view for view in key_views if view.label == "TaskExit"), None)
        transcript = artifact_outputs.get("demo-step-1.txt", "").strip()
        lines: list[str] = [
            f"the helper connected a TCP socket back to the runner and relayed it against a fresh pty using {relay_name}.",
        ]
        if pty_open is not None:
            lines.append(f"pty allocation showed up as {pty_open.detail}.")
        if session_create is not None:
            lines.append(f"the shell side created a new session with {session_create.detail}.")
        if tty_ctls:
            rendered = ", ".join(view.detail for view in tty_ctls[:3])
            lines.append(f"controlling-tty setup flowed through {rendered}.")
        if pg_set is not None:
            lines.append(f"the shell's background-job path issued {pg_set.detail}.")
        if wait_reap is not None:
            lines.append(f"the explicit `sleep 1 & wait` path completed through {wait_reap.detail}.")
        if transcript:
            lines.append(
                "the runner-captured shell transcript printed `ssh-lab`, which confirms bytes crossed socket -> pty -> shell -> pty -> socket end to end."
            )
        if counts["PollSleep"] or counts["PollWake"]:
            lines.append(
                f"the combined socket/tty relay slept {counts['PollSleep']} time(s) and woke {counts['PollWake']} time(s)."
            )
        if task_exit is not None:
            lines.append(f"the relay and shell closed out with {task_exit.detail}.")
        lines.extend(peer_notes)
        return lines
    if demo.name == "sshd":
        transcript = artifact_outputs.get("demo-step-1.txt", "").strip()
        phase_map = {phase.name: phase for phase in phase_results}
        connect_phase = phase_map.get("phase-1-connect")
        pty_phase = phase_map.get("phase-2-pty")
        shell_phase = phase_map.get("phase-3-shell")
        lines: list[str] = [
            f"the guest ran a real Dropbear SSH server on port {SSHD_PORT}, and the host OpenSSH client logged in over QEMU user-net forwarding through three focused trace windows.",
        ]
        if connect_phase is not None:
            lines.append("phase 1 isolated socket accept/authentication, so the network half of SSH is visible without later pty noise.")
        if pty_phase is not None:
            lines.append("phase 2 isolated pty/session/job-control bootstrap, so the shell login path reads like a standalone terminal bring-up.")
            lines.extend(f"(phase 2) {line}" for line in pty_phase.walkthrough[:3])
        if shell_phase is not None:
            lines.append("phase 3 isolated the interactive shell workload, including the background child, SIGCHLD, wait4, and session teardown.")
            lines.extend(f"(phase 3) {line}" for line in shell_phase.walkthrough[:4])
        if transcript:
            lines.append(
                "the real SSH transcript printed `sshd-lab`, which confirms the path guest sshd -> pty -> shell -> pty -> encrypted socket -> host ssh client end to end."
            )
        if counts["PollSleep"] or counts["PollWake"]:
            lines.append(
                f"the combined socket/tty path slept {counts['PollSleep']} time(s) and woke {counts['PollWake']} time(s)."
            )
        lines.extend(peer_notes)
        return lines
    return [view.detail for view in key_views[:5]]


def create_summary(
    path: pathlib.Path,
    demo: Demo,
    artifact_dir: pathlib.Path,
    events: list[TraceEvent],
    event_views: list[EventView],
    key_views: list[EventView],
    stats_text: str,
    last_fault_text: str,
    input_stream: tuple[str, ...],
    artifact_outputs: dict[str, str],
    peer_notes: tuple[str, ...],
    phase_results: tuple[PhaseResult, ...] = (),
) -> None:
    counts = collections.Counter(event.kind for event in events)
    present = [kind for kind in demo.expected_events if counts[kind] > 0]
    missing = [kind for kind in demo.expected_events if counts[kind] == 0]
    stats = parse_tab_values(stats_text)
    walkthrough = build_walkthrough(demo, event_views, key_views, artifact_outputs, peer_notes, phase_results)
    syscall_summary = summarize_syscalls(events)
    signal_summary = summarize_signals(events)
    focus_page_fault = None
    if demo.focus_page_fault_arg0 is not None:
        focus_page_fault = next(
            (
                event
                for event in reversed(events)
                if event.kind == "PageFault" and event.arg0 == demo.focus_page_fault_arg0
            ),
            None,
        )

    lines = [
        f"demo: {demo.name}",
        f"goal: {demo.goal}",
        f"artifacts: {artifact_dir}",
        f"trace_events: {len(events)}",
        "",
        "baseline:",
        f"- arch: {BASELINE_ARCH}",
        f"- app_features: {BASELINE_APP_FEATURES}",
        f"- accel: {BASELINE_ACCEL}",
        f"- net: {demo.net}",
        f"- icount: {BASELINE_ICOUNT}",
        f"- smp: {BASELINE_SMP}",
        f"- dev_random_seed: {BASELINE_RANDOM_SEED}",
        "",
        "commands:",
    ]
    lines.extend(f"- {cmd}" for cmd in demo.commands)
    lines.append("")
    lines.append("input stream:")
    lines.extend(f"- {cmd}" for cmd in input_stream)
    lines.append("")
    lines.append("expected events:")
    lines.extend(f"- {kind}" for kind in demo.expected_events)
    lines.append("")
    lines.append("focus events:")
    lines.extend(f"- {kind}" for kind in demo.focus_events)
    if demo.focus_syscalls:
        lines.append("")
        lines.append("focus syscalls:")
        lines.extend(f"- {name}" for name in demo.focus_syscalls)
    lines.append("")
    lines.append("walkthrough:")
    if walkthrough:
        lines.extend(f"- {line}" for line in walkthrough)
    else:
        lines.append("- none")
    lines.append("")
    lines.append("observed expected events:")
    lines.extend(f"- {kind}" for kind in present)
    lines.append("")
    lines.append("missing expected events:")
    if missing:
        lines.extend(f"- {kind}" for kind in missing)
    else:
        lines.append("- none")
    lines.append("")
    lines.append("trace buffer:")
    for key in ("enabled", "emitted", "overwritten", "buffered"):
        if key in stats:
            lines.append(f"- {key}: {stats[key]}")
    if focus_page_fault is not None:
        lines.append("")
        lines.append("demo fault:")
        lines.append(f"- tid: {focus_page_fault.tid}")
        lines.append(f"- addr: {focus_page_fault.arg0}")
        lines.append(f"- flags: {focus_page_fault.arg1}")
    else:
        last_page_fault = next((event for event in reversed(events) if event.kind == "PageFault"), None)
        if last_page_fault is not None:
            lines.append("")
            lines.append("last page fault:")
            lines.append(f"- tid: {last_page_fault.tid}")
            lines.append(f"- addr: {last_page_fault.arg0}")
            lines.append(f"- flags: {last_page_fault.arg1}")
        elif last_fault_text.strip() != "none":
            lines.append("")
            lines.append("last fault snapshot:")
            for line in last_fault_text.splitlines():
                if line.strip():
                    lines.append(f"- {line.replace(chr(9), ': ')}")
    lines.append("")
    lines.append("syscall hotspots:")
    if syscall_summary:
        lines.extend(f"- {line}" for line in syscall_summary)
    else:
        lines.append("- none")
    lines.append("")
    lines.append("signals observed:")
    if signal_summary:
        lines.extend(f"- {line}" for line in signal_summary)
    else:
        lines.append("- none")
    if peer_notes:
        lines.append("")
        lines.append("runner observations:")
        lines.extend(f"- {line}" for line in peer_notes)
    if phase_results:
        lines.append("")
        lines.append("ssh phases:")
        for phase in phase_results:
            lines.append(f"- {phase.name}: {phase.title}")
            for line in phase.walkthrough[:3]:
                lines.append(f"  {line}")
    lines.append("")
    lines.append("key trace preview:")
    if key_views:
        for view in key_views[:8]:
            lines.append(
                f"- seq={view.event.seq} tid={view.event.tid} {view.label}: {view.detail}"
            )
    else:
        lines.append("- none")
    lines.append("")
    lines.append("event counts:")
    for kind, count in sorted(counts.items()):
        lines.append(f"- {kind}: {count}")
    lines.append("")
    lines.append("saved files:")
    for child in sorted(artifact_dir.iterdir()):
        lines.append(f"- {child.name}")
    write_text(path, "\n".join(lines) + "\n")


def collect_trace_artifacts(session: "Session", command_timeout: float) -> dict[str, str]:
    outputs: dict[str, str] = {}
    for name, command in ARTIFACT_COMMANDS:
        output = session.run_command(command, command_timeout)
        outputs[name] = clean_capture(output, command)
    return outputs


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("demo", choices=sorted(DEMOS))
    parser.add_argument("--arch", default="riscv64")
    parser.add_argument("--out-dir", default="lab-out")
    parser.add_argument("--boot-timeout", type=float, default=30.0)
    parser.add_argument("--command-timeout", type=float, default=15.0)
    parser.add_argument("--raw", action="store_true")
    parser.add_argument("--repeat", type=int, default=1)
    parser.add_argument("--skip-build", action="store_true")
    return parser.parse_args()

def execute_run(
    demo: Demo,
    arch: str,
    out_dir: pathlib.Path,
    boot_timeout: float,
    command_timeout: float,
    raw: bool,
) -> RunResult:
    ensure_guest_helpers(demo, arch)
    proc = spawn_qemu(arch, demo.net)
    try:
        wait_for_qemu_start(proc, boot_timeout)
        sock = socket.create_connection(("localhost", SERIAL_PORT), timeout=boot_timeout)
        session = Session(sock)
        session.wait_for_prompt(boot_timeout)
        input_stream: list[str] = []
        phase_results: tuple[PhaseResult, ...] = ()
        for command in demo.setup_commands:
            input_stream.append(command)
            session.run_command(command, command_timeout)
        demo_outputs: list[tuple[pathlib.Path, str]] = []
        peer_notes: tuple[str, ...] = ()
        if demo.name == "sshd":
            private_key, public_key = ensure_ssh_client_key()
            for command in sshd_setup_commands(public_key):
                input_stream.append(command)
                session.run_command(command, command_timeout)
            wait_for_tcp_port("127.0.0.1", SSHD_PORT, timeout=min(command_timeout, 10.0))
            ssh_phase_specs = (
                (
                    "phase-1-connect",
                    "SSH accept/connect",
                    ("echo 1 > /proc/starry/reset",),
                    f"HOST:ssh -p {SSHD_PORT} -i {private_key} root@127.0.0.1 printf '{SSHD_PHASE1_TOKEN}\\n'",
                    "echo 1 > /proc/starry/off",
                    lambda: run_host_ssh_command(
                        private_key,
                        f"printf '{SSHD_PHASE1_TOKEN}\\n'",
                        command_timeout,
                        SSHD_PHASE1_TOKEN,
                    ),
                ),
                (
                    "phase-2-pty",
                    "SSH pty/session/job-control bootstrap",
                    ("echo 1 > /proc/starry/reset",),
                    f"HOST:ssh -tt -p {SSHD_PORT} -i {private_key} root@127.0.0.1 [phase-2]",
                    "echo 1 > /proc/starry/off",
                    lambda: run_host_ssh_demo(
                        private_key,
                        command_timeout,
                        SSHD_PHASE2_LINES,
                        SSHD_PHASE2_TOKEN,
                    ),
                ),
                (
                    "phase-3-shell",
                    "SSH interactive shell + wait4",
                    ("echo 1 > /proc/starry/reset",),
                    f"HOST:ssh -tt -p {SSHD_PORT} -i {private_key} root@127.0.0.1 [phase-3]",
                    "echo 1 > /proc/starry/off",
                    lambda: run_host_ssh_demo(
                        private_key,
                        command_timeout,
                        SSHD_PHASE3_LINES,
                        SSHD_PHASE3_TOKEN,
                    ),
                ),
            )
            phase_results_list: list[PhaseResult] = []
            ssh_peer_notes: list[str] = []
            phase3_peer_result: PeerResult | None = None
            try:
                for phase_name, phase_title, phase_start, host_command, phase_end, runner in ssh_phase_specs:
                    for command in phase_start:
                        input_stream.append(f"{command} [{phase_name}]")
                        session.run_command(command, command_timeout)
                    input_stream.append(host_command)
                    phase_peer_result = runner()
                    for note in phase_peer_result.notes:
                        ssh_peer_notes.append(f"{phase_name}: {note}")
                    input_stream.append(f"{phase_end} [{phase_name}]")
                    session.run_command(phase_end, command_timeout)
                    phase_outputs = collect_trace_artifacts(session, command_timeout)
                    phase_events = parse_trace(phase_outputs["starry_trace.txt"])
                    phase_result = render_sshd_phase_artifacts(
                        out_dir / phase_name,
                        phase_name,
                        phase_title,
                        phase_events,
                        phase_outputs["starry_stats.txt"],
                        phase_outputs["starry_last_fault.txt"],
                        (host_command,),
                        phase_peer_result.transcript,
                        raw,
                    )
                    phase_results_list.append(phase_result)
                    if phase_name == "phase-3-shell":
                        phase3_peer_result = phase_peer_result
            except Exception as exc:
                auth_keys = clean_capture(
                    session.run_command(f"cat {AUTHORIZED_KEYS_GUEST} 2>/dev/null || true", command_timeout),
                    f"cat {AUTHORIZED_KEYS_GUEST} 2>/dev/null || true",
                )
                auth_perms = clean_capture(
                    session.run_command("ls -ld /root /root/.ssh /root/.ssh/authorized_keys 2>/dev/null || true", command_timeout),
                    "ls -ld /root /root/.ssh /root/.ssh/authorized_keys 2>/dev/null || true",
                )
                dropbearkey_log = clean_capture(
                    session.run_command(f"cat {DROPBEARKEY_LOG_GUEST} 2>/dev/null || true", command_timeout),
                    f"cat {DROPBEARKEY_LOG_GUEST} 2>/dev/null || true",
                )
                dropbear_log = clean_capture(
                    session.run_command(f"cat {DROPBEAR_LOG_GUEST} 2>/dev/null || true", command_timeout),
                    f"cat {DROPBEAR_LOG_GUEST} 2>/dev/null || true",
                )
                if dropbearkey_log:
                    raise RuntimeError(
                        f"{exc}\nguest authorized_keys:\n{auth_keys}\nguest auth perms:\n{auth_perms}\n"
                        f"guest dropbearkey log:\n{dropbearkey_log}\nguest dropbear log:\n{dropbear_log}"
                    ) from exc
                if dropbear_log:
                    raise RuntimeError(
                        f"{exc}\nguest authorized_keys:\n{auth_keys}\nguest auth perms:\n{auth_perms}\n"
                        f"guest dropbear log:\n{dropbear_log}"
                    ) from exc
                raise
            phase_results = tuple(phase_results_list)
            peer_notes = tuple(ssh_peer_notes)
            cleaned_output = normalize_demo_output(
                demo,
                "" if phase3_peer_result is None else phase3_peer_result.transcript,
            )
            step_path = out_dir / "demo-step-1.txt"
            write_text(step_path, cleaned_output)
            demo_outputs.append((step_path, cleaned_output))
        else:
            input_stream.append("echo 1 > /proc/starry/reset")
            session.run_command(input_stream[-1], command_timeout)

            peer = start_demo_peer(demo)
            last_index = len(demo.commands)
            for index, command in enumerate(demo.commands, start=1):
                command_to_run = command
                if index == last_index:
                    command_to_run = f"{command}; echo 1 > /proc/starry/off"
                input_stream.append(command_to_run)
                output = session.run_command(command_to_run, command_timeout)
                cleaned_output = normalize_demo_output(demo, clean_capture(output, command_to_run))
                step_path = out_dir / f"demo-step-{index}.txt"
                write_text(step_path, cleaned_output)
                demo_outputs.append((step_path, cleaned_output))
            peer_result = peer.finish(command_timeout) if peer is not None else PeerResult(notes=())
            peer_notes = peer_result.notes
            if peer_result.transcript:
                for step_path, cleaned_output in demo_outputs:
                    if cleaned_output.strip() and demo.name not in {"ssh-poll", "ssh-select"}:
                        continue
                    write_text(step_path, peer_result.transcript)
                    break
            elif peer_notes:
                for step_path, cleaned_output in demo_outputs:
                    if cleaned_output.strip():
                        continue
                    fallback = ["(no guest stdout captured)"]
                    fallback.extend(peer_notes)
                    write_text(step_path, "\n".join(fallback) + "\n")
                    break

        artifact_outputs: dict[str, str] = {
            path.name: path.read_text(encoding="utf-8") for path, _cleaned in demo_outputs
        }
        if demo.name == "sshd":
            total_emitted = 0
            total_overwritten = 0
            total_buffered = 0
            for phase in phase_results:
                stats = parse_tab_values(phase.stats_text)
                total_emitted += int(stats.get("emitted", "0"))
                total_overwritten += int(stats.get("overwritten", "0"))
                total_buffered += int(stats.get("buffered", "0"))
            stats_text = (
                f"enabled\t0\nemitted\t{total_emitted}\noverwritten\t{total_overwritten}\n"
                f"buffered\t{total_buffered}\n"
            )
            last_fault_text = phase_results[-1].last_fault_text if phase_results else "none\n"
            events = [event for phase in phase_results for event in phase.events]
            event_views = [view for phase in phase_results for view in phase.event_views]
            key_views = render_sshd_key_trace(out_dir / "key_trace.txt", phase_results)
            key_events = [view.event for view in key_views]
            artifact_outputs["starry_stats.txt"] = stats_text
            artifact_outputs["starry_last_fault.txt"] = last_fault_text
        else:
            for name, command in ARTIFACT_COMMANDS:
                output = session.run_command(command, command_timeout)
                artifact_outputs[name] = clean_capture(output, command)
                if raw:
                    write_text(out_dir / name, artifact_outputs[name])
            trace_text = artifact_outputs["starry_trace.txt"]
            stats_text = artifact_outputs["starry_stats.txt"]
            last_fault_text = artifact_outputs["starry_last_fault.txt"]
            events = parse_trace(trace_text)
            event_views = build_event_views(events)
            key_views = render_key_trace(out_dir / "key_trace.txt", demo, event_views)
            key_events = [view.event for view in key_views]
        if raw and demo.name == "sshd":
            for filename, guest_path in (
                ("lab_dropbear.log", DROPBEAR_LOG_GUEST),
                ("lab_dropbearkey.log", DROPBEARKEY_LOG_GUEST),
            ):
                command = f"cat {guest_path} 2>/dev/null || true"
                output = session.run_command(command, command_timeout)
                artifact_outputs[filename] = clean_capture(output, command)
                write_text(out_dir / filename, artifact_outputs[filename])

        if raw:
            write_text(out_dir / "session.log", session.log)
        create_summary(
            out_dir / "summary.txt",
            demo,
            out_dir,
            events,
            event_views,
            key_views,
            stats_text,
            last_fault_text,
            tuple(input_stream),
            artifact_outputs,
            peer_notes,
            phase_results,
        )

        sock.sendall(b"exit\r\n")
        return RunResult(
            out_dir=out_dir,
            events=events,
            event_views=event_views,
            stats_text=stats_text,
            last_fault_text=last_fault_text,
            key_events=key_events,
            key_views=key_views,
            input_stream=tuple(input_stream),
            net=demo.net,
            peer_notes=peer_notes,
            phase_results=phase_results,
        )
    finally:
        try:
            proc.wait(timeout=1)
        except subprocess.TimeoutExpired:
            proc.terminate()
            proc.wait()


def create_repeatability_report(path: pathlib.Path, demo: Demo, runs: list[RunResult]) -> None:
    reference = runs[0]
    ref_full = normalize_events(reference.events)
    ref_key = normalize_events(reference.key_events)
    ref_full_semantic = normalize_event_views(reference.event_views)
    ref_key_semantic = normalize_event_views(reference.key_views)

    lines = [
        f"demo: {demo.name}",
        f"repeats: {len(runs)}",
        "",
        "baseline:",
        f"- arch: {BASELINE_ARCH}",
        f"- app_features: {BASELINE_APP_FEATURES}",
        f"- accel: {BASELINE_ACCEL}",
        f"- net: {reference.net}",
        f"- icount: {BASELINE_ICOUNT}",
        f"- smp: {BASELINE_SMP}",
        f"- dev_random_seed: {BASELINE_RANDOM_SEED}",
        "",
        "input stream:",
    ]
    lines.extend(f"- {cmd}" for cmd in reference.input_stream)
    lines.append("")
    lines.append("runs:")
    for index, run in enumerate(runs, start=1):
        full_norm = normalize_events(run.events)
        key_norm = normalize_events(run.key_events)
        full_semantic = normalize_event_views(run.event_views)
        key_semantic = normalize_event_views(run.key_views)
        lines.append(f"- run-{index:02d}: {run.out_dir.name}")
        lines.append(f"  full_events={len(run.events)} full_digest={digest_lines(full_norm)}")
        lines.append(f"  full_semantic_digest={digest_lines(full_semantic)}")
        lines.append(f"  key_events={len(run.key_events)} key_digest={digest_lines(key_norm)}")
        lines.append(f"  key_semantic_digest={digest_lines(key_semantic)}")
    lines.append("")
    lines.append("comparisons against run-01:")
    for index, run in enumerate(runs[1:], start=2):
        full_norm = normalize_events(run.events)
        key_norm = normalize_events(run.key_events)
        full_semantic = normalize_event_views(run.event_views)
        key_semantic = normalize_event_views(run.key_views)
        full_match, full_note = compare_lines(ref_full, full_norm)
        key_match, key_note = compare_lines(ref_key, key_norm)
        full_semantic_match, full_semantic_note = compare_lines(ref_full_semantic, full_semantic)
        key_semantic_match, key_semantic_note = compare_lines(ref_key_semantic, key_semantic)
        lines.append(f"- run-{index:02d}")
        lines.append(f"  full_trace_match={int(full_match)}")
        lines.append(f"  full_trace_note={full_note}")
        lines.append(f"  full_trace_semantic_match={int(full_semantic_match)}")
        lines.append(f"  full_trace_semantic_note={full_semantic_note}")
        lines.append(f"  key_trace_match={int(key_match)}")
        lines.append(f"  key_trace_note={key_note}")
        lines.append(f"  key_trace_semantic_match={int(key_semantic_match)}")
        lines.append(f"  key_trace_semantic_note={key_semantic_note}")
    write_text(path, "\n".join(lines) + "\n")


def main() -> int:
    args = parse_args()
    demo = DEMOS[args.demo]

    if args.arch != BASELINE_ARCH:
        raise SystemExit(f"Starry Lab deterministic baseline only supports arch={BASELINE_ARCH}")
    if args.repeat < 1:
        raise SystemExit("--repeat must be at least 1")

    if not args.skip_build:
        run_build(args.arch)

    stamp = dt.datetime.now().strftime("%Y%m%d-%H%M%S")
    if args.repeat == 1:
        out_dir = pathlib.Path(args.out_dir) / f"{demo.name}-{stamp}"
        out_dir.mkdir(parents=True, exist_ok=True)
        execute_run(demo, args.arch, out_dir, args.boot_timeout, args.command_timeout, args.raw)
        print(out_dir)
        return 0

    out_dir = pathlib.Path(args.out_dir) / f"{demo.name}-repeat-{stamp}"
    out_dir.mkdir(parents=True, exist_ok=True)
    runs: list[RunResult] = []
    for index in range(1, args.repeat + 1):
        run_dir = out_dir / f"run-{index:02d}"
        run_dir.mkdir(parents=True, exist_ok=True)
        runs.append(
            execute_run(demo, args.arch, run_dir, args.boot_timeout, args.command_timeout, args.raw)
        )

    create_repeatability_report(out_dir / "repeatability.txt", demo, runs)
    print(out_dir)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
