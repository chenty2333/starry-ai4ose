#!/usr/bin/env python3

import argparse
import collections
import datetime as dt
import errno
import fcntl
import hashlib
import json
import os
import pathlib
import queue
import re
import select
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import textwrap
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
QMP_SOCKET = LAB_BIN_DIR / "qmp.sock"
PTY_HELPER_SOURCE = REPO_ROOT / "scripts" / "lab-helpers" / "pty_relay.c"
WAITCTL_HELPER_SOURCE = REPO_ROOT / "scripts" / "lab-helpers" / "waitctl.c"
TTYSIG_HELPER_SOURCE = REPO_ROOT / "scripts" / "lab-helpers" / "ttysig.c"
COWCTL_HELPER_SOURCE = REPO_ROOT / "scripts" / "lab-helpers" / "cowctl.c"
FILEMAP_HELPER_SOURCE = REPO_ROOT / "scripts" / "lab-helpers" / "filemapctl.c"
SHMCHECK_HELPER_SOURCE = REPO_ROOT / "scripts" / "lab-helpers" / "shmcheck.c"
FBDRAW_HELPER_SOURCE = REPO_ROOT / "scripts" / "lab-helpers" / "fbdraw.c"
EVWATCH_HELPER_SOURCE = REPO_ROOT / "scripts" / "lab-helpers" / "evwatch.c"
MINIGUI_HELPER_SOURCE = REPO_ROOT / "scripts" / "lab-helpers" / "minigui.c"
SNAKE_HELPER_SOURCE = REPO_ROOT / "scripts" / "lab-helpers" / "snake.c"
XCALC_HELPER_SOURCE = REPO_ROOT / "scripts" / "lab-helpers" / "xcalc_lab.c"
PTY_HELPER_GUEST = "/usr/bin/lab_pty_relay"
WAITCTL_HELPER_GUEST = "/usr/bin/lab_waitctl"
TTYSIG_HELPER_GUEST = "/usr/bin/lab_ttysig"
COWCTL_HELPER_GUEST = "/usr/bin/lab_cowctl"
FILEMAP_HELPER_GUEST = "/usr/bin/lab_filemapctl"
SHMCHECK_HELPER_GUEST = "/usr/bin/lab_shmcheck"
FBDRAW_HELPER_GUEST = "/usr/bin/lab_fbdraw"
EVWATCH_HELPER_GUEST = "/usr/bin/lab_evwatch"
MINIGUI_HELPER_GUEST = "/usr/bin/lab_minigui"
SNAKE_HELPER_GUEST = "/usr/bin/lab_snake"
XCALC_HELPER_GUEST = "/usr/bin/lab_xcalc"
DROPBEAR_ATTR = "nixpkgs#pkgsCross.riscv64-musl.dropbear"
XLIB11_DEV_ATTR = "nixpkgs#pkgsCross.riscv64-musl.libX11.dev"
DROPBEAR_STAGE_DIR = LAB_BIN_DIR / "dropbear"
SSH_KEY_STAGE_DIR = LAB_BIN_DIR / "ssh"
X11_STAGE_DIR = LAB_BIN_DIR / "x11"
X11_STAGE_ROOT = X11_STAGE_DIR / f"root-{BASELINE_ARCH}"
X11_STAGE_TAR = X11_STAGE_DIR / f"x11-stage-{BASELINE_ARCH}.tar"
X11_STAGE_META = X11_STAGE_DIR / "x11-stage.meta"
X11_HELPER_LOCAL = X11_STAGE_DIR / "lab_x11demo.sh"
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
SSHD_PHASE4_TOKEN = "sshd-jobctl-lab"
SSHD_PHASE5A_TOKEN = "sshd-sigttou-lab"
SSHD_PHASE5B_TOKEN = "sshd-sigttin-lab"
WAITCTL_STOP_TOKEN = "waitctl-stop-lab"
WAITCTL_CONTINUE_TOKEN = "waitctl-continue-lab"
WAITCTL_REAP_TOKEN = "waitctl-reap-lab"
X11_SERVER_TOKEN = "__LAB_X11_SERVER__"
X11_CLIENT_TOKEN = "x11-lab"
X11_APK_LOG_GUEST = "/tmp/lab_x11_apk.log"
X11_SERVER_LOG_GUEST = "/tmp/lab_x11.log"
X11_CLIENT_LOG_GUEST = "/tmp/lab_xcalc.log"
X11_SERVER_PID_GUEST = "/tmp/lab_x11.pid"
X11_CLIENT_PID_GUEST = "/tmp/lab_xcalc.pid"
X11_INPUT_LOG_GUEST = "/tmp/lab_xcalc.log.raw"
X11_INPUT_PID_GUEST = "/tmp/lab_xinput.pid"
X11_INPUT_OFFSET_GUEST = "/tmp/lab_xinput.offset"
X11_CONFIG_NAME = "xorg.conf"
X11_CONFIG_GUEST = "/etc/X11/xorg.conf"
X11_STAGE_TAR_GUEST = "/usr/share/starry-lab/x11-stage.tar"
X11_LINKS_GUEST = "/usr/share/starry-lab/x11-links.txt"
X11_HELPER_GUEST = "/usr/bin/lab_x11demo"
X11_INPUT_TOKEN = "x11-input-lab"
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
SSHD_PHASE4_LINES: tuple[str, ...] = (
    "PS1=",
    "export PS1",
    "set -m",
    "sleep 30",
    "__LAB_DELAY__:0.5",
    "\x1a",
    "__LAB_DELAY__:0.2",
    "jobs",
    "fg",
    "__LAB_DELAY__:1.0",
    "\x03",
    f"printf '{SSHD_PHASE4_TOKEN}\\n'",
    "exit",
)
SSHD_PHASE5A_LINES: tuple[str, ...] = (
    "PS1=",
    "export PS1",
    "set -m",
    "stty tostop",
    f"{TTYSIG_HELPER_GUEST} write &",
    "__LAB_DELAY__:1.3",
    "jobs",
    "fg",
    "__LAB_DELAY__:0.2",
    f"printf '{SSHD_PHASE5A_TOKEN}\\n'",
    "exit",
)
SSHD_PHASE5B_LINES: tuple[str, ...] = (
    "PS1=",
    "export PS1",
    "set -m",
    f"{TTYSIG_HELPER_GUEST} read &",
    "__LAB_DELAY__:1.3",
    "jobs",
    "fg",
    "ttin-input",
    "__LAB_DELAY__:0.2",
    f"printf '{SSHD_PHASE5B_TOKEN}\\n'",
    "exit",
)
X11_CONFIG_LINES: tuple[str, ...] = (
    'Section "ServerFlags"',
    '    Option "AutoAddDevices" "false"',
    'EndSection',
    'Section "InputDevice"',
    '    Identifier "Keyboard0"',
    '    Driver "evdev"',
    '    Option "Device" "/dev/input/event0"',
    'EndSection',
    'Section "InputDevice"',
    '    Identifier "Mouse0"',
    '    Driver "evdev"',
    '    Option "Device" "/dev/input/event1"',
    'EndSection',
    'Section "Device"',
    '    Identifier "FB0"',
    '    Driver "fbdev"',
    '    Option "fbdev" "/dev/fb0"',
    'EndSection',
    'Section "Monitor"',
    '    Identifier "Monitor0"',
    'EndSection',
    'Section "Screen"',
    '    Identifier "Screen0"',
    '    Device "FB0"',
    '    Monitor "Monitor0"',
    'EndSection',
    'Section "ServerLayout"',
    '    Identifier "Layout0"',
    '    Screen "Screen0"',
    '    InputDevice "Keyboard0" "CoreKeyboard"',
    '    InputDevice "Mouse0" "CorePointer"',
    'EndSection',
)
X11_APK_REPOSITORIES: tuple[str, ...] = (
    "https://dl-cdn.alpinelinux.org/alpine/v3.23/main",
    "https://dl-cdn.alpinelinux.org/alpine/v3.23/community",
)
X11_STAGE_VERSION = 5
X11_APK_PACKAGES = (
    "xorg-server xf86-video-fbdev xf86-input-evdev "
    "xwininfo xsetroot xdpyinfo xev "
    "font-adobe-75dpi font-adobe-100dpi font-bitstream-75dpi font-bitstream-100dpi"
)
X11_STAGE_TOPLEVEL: tuple[str, ...] = ("usr", "etc")

TTY_CTL_NAMES: dict[int, str] = {
    1: "TIOCSCTTY",
    2: "TIOCSPGRP",
    3: "TIOCNOTTY",
}

FB_IOCTL_NAMES: dict[int, str] = {
    0x4600: "FBIOGET_VSCREENINFO",
    0x4601: "FBIOPUT_VSCREENINFO",
    0x4602: "FBIOGET_FSCREENINFO",
    0x4604: "FBIOGETCMAP",
    0x4605: "FBIOPUTCMAP",
}

INPUT_NODE_NAMES: dict[int, str] = {
    1: "event",
    2: "mice",
}

INPUT_EVENT_TYPE_NAMES: dict[int, str] = {
    0x01: "EV_KEY",
    0x02: "EV_REL",
}

INPUT_EVENT_CODE_NAMES: dict[tuple[int, int], str] = {
    (0x01, 30): "KEY_A",
    (0x01, 31): "KEY_S",
    (0x01, 32): "KEY_D",
    (0x01, 17): "KEY_W",
    (0x01, 103): "KEY_UP",
    (0x01, 108): "KEY_DOWN",
    (0x01, 105): "KEY_LEFT",
    (0x01, 106): "KEY_RIGHT",
    (0x01, 272): "BTN_LEFT",
    (0x02, 0): "REL_X",
    (0x02, 1): "REL_Y",
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
    graphic: str = "n"
    input: str = "n"


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
X11_CONFIG_SETUP_COMMANDS = build_script_setup(X11_CONFIG_GUEST, X11_CONFIG_LINES)


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
    "cow": Demo(
        name="cow",
        goal="Exercise anonymous private mmap, permission flips, fork-driven copy-on-write, and cleanup.",
        commands=(COWCTL_HELPER_GUEST,),
        expected_events=("SysEnter", "SysExit", "PageFault", "WaitReap", "TaskExit"),
        focus_events=("PageFault", "WaitReap", "SignalSend", "SignalHandle", "TaskExit"),
        focus_syscalls=("mmap", "mprotect", "clone", "wait4", "munmap"),
        setup_commands=(),
        focus_page_fault_arg0=None,
        focus_signal_arg0=None,
        net="n",
    ),
    "filemap": Demo(
        name="filemap",
        goal="Exercise file-backed MAP_SHARED and MAP_PRIVATE mappings and show page-cache-backed coherence through file I/O.",
        commands=(FILEMAP_HELPER_GUEST,),
        expected_events=("SysEnter", "SysExit", "PageFault", "WaitReap", "TaskExit"),
        focus_events=("PageFault", "WaitReap", "SignalSend", "SignalHandle", "TaskExit"),
        focus_syscalls=("openat", "ftruncate", "mmap", "pread64", "pwrite64", "munmap", "close"),
        setup_commands=(),
        focus_page_fault_arg0=None,
        focus_signal_arg0=None,
        net="n",
    ),
    "shm": Demo(
        name="shm",
        goal="Exercise SysV shared memory attach, fork inheritance, detach, IPC_RMID, and final removal.",
        commands=(SHMCHECK_HELPER_GUEST,),
        expected_events=("SysEnter", "SysExit", "PageFault", "WaitReap", "TaskExit"),
        focus_events=("PageFault", "WaitReap", "SignalSend", "SignalHandle", "TaskExit"),
        focus_syscalls=("shmget", "shmat", "clone", "shmdt", "shmctl", "wait4"),
        setup_commands=(),
        focus_page_fault_arg0=None,
        focus_signal_arg0=None,
        net="n",
    ),
    "fb": Demo(
        name="fb",
        goal="Show raw framebuffer bring-up through /dev/fb0 ioctls, mmap, and direct pixel writes.",
        commands=(FBDRAW_HELPER_GUEST,),
        expected_events=("FbIoctl", "FbMap", "DisplayFlush", "PageFault", "WaitReap", "TaskExit"),
        focus_events=("FbIoctl", "FbMap", "DisplayFlush", "PageFault", "WaitReap", "TaskExit"),
        focus_syscalls=("openat", "ioctl", "mmap", "munmap", "close"),
        setup_commands=(),
        focus_page_fault_arg0=None,
        focus_signal_arg0=None,
        net="n",
        graphic="y",
        input="n",
    ),
    "ev": Demo(
        name="ev",
        goal="Show raw evdev input through /dev/input/event0 and /dev/input/mice using poll/read on injected keyboard and mouse activity.",
        commands=(EVWATCH_HELPER_GUEST,),
        expected_events=("InputOpen", "InputPollWake", "InputRead", "PollSleep", "PollWake", "WaitReap", "TaskExit"),
        focus_events=("InputOpen", "InputPollWake", "InputRead", "PollSleep", "PollWake", "WaitReap", "TaskExit"),
        focus_syscalls=("openat", "ioctl", "read", "close"),
        setup_commands=(),
        focus_page_fault_arg0=None,
        focus_signal_arg0=None,
        net="n",
        graphic="y",
        input="y",
    ),
    "gui": Demo(
        name="gui",
        goal="Show a tiny interactive userspace program that combines fbdev drawing with evdev-driven movement and clicks.",
        commands=(MINIGUI_HELPER_GUEST,),
        expected_events=("FbIoctl", "FbMap", "DisplayFlush", "InputOpen", "InputPollWake", "InputRead", "PageFault", "WaitReap", "TaskExit"),
        focus_events=("FbIoctl", "FbMap", "DisplayFlush", "InputOpen", "InputPollWake", "InputRead", "PageFault", "PollSleep", "PollWake", "WaitReap", "TaskExit"),
        focus_syscalls=("openat", "ioctl", "mmap", "read", "munmap", "close"),
        setup_commands=(),
        focus_page_fault_arg0=None,
        focus_signal_arg0=None,
        net="n",
        graphic="y",
        input="y",
    ),
    "snake": Demo(
        name="snake",
        goal="Show a playable snake game built directly on fbdev and evdev, with a deterministic scripted run for repeatable lab output.",
        commands=(f"{SNAKE_HELPER_GUEST} --scripted",),
        expected_events=("FbIoctl", "FbMap", "DisplayFlush", "InputOpen", "InputPollWake", "InputRead", "PageFault", "WaitReap", "TaskExit"),
        focus_events=("FbIoctl", "FbMap", "DisplayFlush", "InputOpen", "InputPollWake", "InputRead", "PageFault", "PollSleep", "PollWake", "WaitReap", "TaskExit"),
        focus_syscalls=("openat", "ioctl", "mmap", "read", "munmap", "close"),
        setup_commands=(),
        focus_page_fault_arg0=None,
        focus_signal_arg0=None,
        net="n",
        graphic="y",
        input="y",
    ),
    "x11": Demo(
        name="x11",
        goal="Bring up X11 over fbdev+evdev, launch the Starry Lab teaching calculator, and capture a guest framebuffer screenshot as proof of GUI output.",
        commands=(),
        expected_events=("FbIoctl", "FbMap", "DisplayFlush", "InputOpen", "InputPollWake", "InputRead", "PageFault", "PollSleep", "PollWake", "WaitReap", "TaskExit"),
        focus_events=("FbIoctl", "FbMap", "DisplayFlush", "InputOpen", "InputPollWake", "InputRead", "PageFault", "PollSleep", "PollWake", "WaitReap", "TaskExit"),
        focus_syscalls=("openat", "ioctl", "mmap", "read", "write", "socket", "connect", "close"),
        setup_commands=(),
        focus_page_fault_arg0=None,
        focus_signal_arg0=None,
        net="n",
        graphic="y",
        input="y",
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
        commands=(WAITCTL_HELPER_GUEST,),
        expected_events=("SignalSend", "SignalHandle", "WaitStop", "WaitContinue", "WaitReap", "TaskExit"),
        focus_events=("SignalSend", "SignalHandle", "WaitStop", "WaitContinue", "WaitReap", "TaskExit"),
        focus_syscalls=("wait4", "kill", "close"),
        setup_commands=(),
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
            "WaitStop",
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
            "WaitStop",
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
    "mmap": "addr",
    "mprotect": "addr",
    "munmap": "addr",
    "clone": "flags",
    "pread64": "fd",
    "pwrite64": "fd",
    "ftruncate": "fd",
    "shmget": "key",
    "shmat": "shmid",
    "shmdt": "shmaddr",
    "shmctl": "shmid",
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


def compile_x11_helper(source: pathlib.Path, output_name: str, arch: str) -> pathlib.Path:
    LAB_BIN_DIR.mkdir(parents=True, exist_ok=True)
    output = LAB_BIN_DIR / f"{output_name}-{arch}"
    if output.exists() and output.stat().st_mtime >= source.stat().st_mtime:
        output.chmod(0o755)
        return output

    try:
        libx11_dev = nix_build_output(XLIB11_DEV_ATTR)
    except subprocess.CalledProcessError:
        candidates = sorted(
            pathlib.Path("/nix/store").glob(f"*-libx11-{arch}-unknown-linux-musl-*-dev")
        )
        if not candidates:
            raise
        libx11_dev = candidates[-1]
    include_dirs = [libx11_dev / "include"]
    propagated = libx11_dev / "nix-support" / "propagated-build-inputs"
    if propagated.exists():
        for raw in propagated.read_text(encoding="utf-8").split():
            path = pathlib.Path(raw) / "include"
            if path.exists():
                include_dirs.append(path)
    pc_values: dict[str, str] = {}
    for line in (libx11_dev / "lib" / "pkgconfig" / "x11.pc").read_text(encoding="utf-8").splitlines():
        if "=" in line and not line.startswith(("Cflags:", "Libs:", "Requires")):
            key, value = line.split("=", 1)
            pc_values[key.strip()] = value.strip()
    prefix = pc_values.get("prefix", "")
    lib_dir = pathlib.Path(pc_values.get("libdir", "").replace("${prefix}", prefix))
    if not lib_dir.exists():
        raise RuntimeError(f"failed to locate libX11 link directory from x11.pc: {lib_dir}")
    compiler = f"{arch}-linux-musl-gcc"
    include_flags = [flag for path in include_dirs for flag in (f"-I{path}",)]
    subprocess.run(
        [
            compiler,
            "-O2",
            "-Wall",
            "-Wextra",
            "-s",
            "-o",
            str(output),
            str(source),
            *include_flags,
            f"-L{lib_dir}",
            "-Wl,-rpath,/usr/lib",
            "-lX11",
        ],
        check=True,
    )
    subprocess.run(
        [
            "patchelf",
            "--set-interpreter",
            "/lib/ld-musl-riscv64.so.1",
            "--set-rpath",
            "/usr/lib",
            str(output),
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


def ensure_x11_stage_root(arch: str) -> pathlib.Path:
    X11_STAGE_DIR.mkdir(parents=True, exist_ok=True)
    stamp = X11_STAGE_ROOT / ".stage-ok"
    desired_stamp = f"v{X11_STAGE_VERSION}\n{X11_APK_PACKAGES}\n"
    if stamp.exists() and stamp.read_text(encoding="utf-8") == desired_stamp:
        return X11_STAGE_ROOT

    if X11_STAGE_ROOT.exists():
        shutil.rmtree(X11_STAGE_ROOT)
    X11_STAGE_ROOT.mkdir(parents=True, exist_ok=True)

    repos = X11_STAGE_DIR / "repositories"
    write_text(repos, "\n".join(X11_APK_REPOSITORIES) + "\n")
    apk_cmd = (
        "set -e; "
        "ROOT=\"$1\"; "
        "set +e; "
        f"apk --usermode --arch {arch} --allow-untrusted "
        f'--root "$ROOT" --repositories-file "{repos}" --initdb add {X11_APK_PACKAGES}; '
        'rc=$?; [ "$rc" -eq 0 ] || [ "$rc" -eq 4 ]'
    )
    proc = subprocess.run(
        ["nix", "shell", "nixpkgs#apk-tools", "-c", "sh", "-lc", apk_cmd, "sh", str(X11_STAGE_ROOT)],
        check=False,
        cwd=REPO_ROOT,
        text=True,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"failed to stage host-side X11 userland (apk exit {proc.returncode})")

    apk_log = X11_STAGE_ROOT / "var" / "log" / "apk.log"
    if apk_log.is_dir():
        shutil.rmtree(apk_log)
    elif apk_log.exists():
        apk_log.unlink()

    stamp.write_text(desired_stamp, encoding="utf-8")
    return X11_STAGE_ROOT


def ensure_x11_stage_tar(arch: str) -> pathlib.Path:
    desired_stamp = f"v{X11_STAGE_VERSION}\n{arch}\n{X11_APK_PACKAGES}\n"
    if X11_STAGE_TAR.exists():
        if X11_STAGE_META.exists():
            if X11_STAGE_META.read_text(encoding="utf-8") == desired_stamp:
                return X11_STAGE_TAR
        else:
            X11_STAGE_META.write_text(desired_stamp, encoding="utf-8")
            return X11_STAGE_TAR
        with tempfile.TemporaryDirectory(prefix="starry-x11-stage-") as tmp_dir:
            tmp_root = pathlib.Path(tmp_dir)
            subprocess.run(
                ["tar", "-xf", str(X11_STAGE_TAR), "-C", str(tmp_root)],
                check=True,
                cwd=REPO_ROOT,
            )
            apk_log = tmp_root / "var" / "log" / "apk.log"
            if apk_log.is_dir():
                shutil.rmtree(apk_log)
            elif apk_log.exists():
                apk_log.unlink()
            entries = [name for name in X11_STAGE_TOPLEVEL if (tmp_root / name).exists()]
            tmp_tar = X11_STAGE_DIR / f".x11-stage-{arch}.tar.tmp"
            subprocess.run(
                [
                    "tar",
                    "--numeric-owner",
                    "--owner=0",
                    "--group=0",
                    "-C",
                    str(tmp_root),
                    "-cf",
                    str(tmp_tar),
                    *entries,
                ],
                check=True,
                cwd=REPO_ROOT,
            )
            tmp_tar.replace(X11_STAGE_TAR)
            X11_STAGE_META.write_text(desired_stamp, encoding="utf-8")
            return X11_STAGE_TAR

    stage_root = ensure_x11_stage_root(arch)
    stamp = stage_root / ".stage-ok"
    if X11_STAGE_TAR.exists() and X11_STAGE_TAR.stat().st_mtime >= stamp.stat().st_mtime:
        X11_STAGE_META.write_text(desired_stamp, encoding="utf-8")
        return X11_STAGE_TAR

    entries = [name for name in X11_STAGE_TOPLEVEL if (stage_root / name).exists()]
    if not entries:
        raise RuntimeError(f"host-side X11 staging root is empty: {stage_root}")

    subprocess.run(
        [
            "tar",
            "--numeric-owner",
            "--owner=0",
            "--group=0",
            "-C",
            str(stage_root),
            "-cf",
            str(X11_STAGE_TAR),
            *entries,
        ],
        check=True,
        cwd=REPO_ROOT,
    )
    X11_STAGE_META.write_text(desired_stamp, encoding="utf-8")
    return X11_STAGE_TAR


def get_x11_stage_tar(arch: str) -> pathlib.Path:
    return ensure_x11_stage_tar(arch)


def ensure_x11_helper_script() -> pathlib.Path:
    X11_STAGE_DIR.mkdir(parents=True, exist_ok=True)
    config_text = "\n".join(X11_CONFIG_LINES)
    x11_stamp = X11_APK_PACKAGES.replace("'", "")
    script = (
        "#!/bin/sh\n"
        "set -e\n"
        f"STAGE_TAR={X11_STAGE_TAR_GUEST}\n"
        f"LINKS_MANIFEST={X11_LINKS_GUEST}\n"
        f"XCALC_BIN={XCALC_HELPER_GUEST}\n"
        f"CONF={X11_CONFIG_GUEST}\n"
        f"CONF_NAME={X11_CONFIG_NAME}\n"
        f"XLOG={X11_SERVER_LOG_GUEST}\n"
        f"CLOG={X11_CLIENT_LOG_GUEST}\n"
        f"XPID={X11_SERVER_PID_GUEST}\n"
        f"CPID={X11_CLIENT_PID_GUEST}\n"
        f"ILOG={X11_INPUT_LOG_GUEST}\n"
        f"IPID={X11_INPUT_PID_GUEST}\n"
        f"IOFF={X11_INPUT_OFFSET_GUEST}\n"
        "STAMP=/usr/share/starry-lab/.x11-ready\n"
        "BOOT_STAMP=/tmp/.x11-runtime-ready\n"
        "INSTALL_LOG=/tmp/lab_x11_install.log\n"
        f"EXPECTED_STAMP='{x11_stamp}'\n"
        "\n"
        "have_runtime() {\n"
        "    command -v X >/dev/null 2>&1 \\\n"
        "        && [ -x \"$XCALC_BIN\" ] \\\n"
        "        && [ -x /usr/libexec/Xorg ] \\\n"
        "        && [ -f /usr/include/X11/bitmaps/calculator ]\n"
        "}\n"
        "\n"
        "prepare_runtime() {\n"
        "    mkdir /usr/share/starry-lab 2>/dev/null || true\n"
        "    printf '%s\\n' \"$EXPECTED_STAMP\" >\"$STAMP\"\n"
        "}\n"
        "\n"
        "repair_runtime_links() {\n"
        "    [ -f \"$LINKS_MANIFEST\" ] || return 0\n"
        "    while read -r path target; do\n"
        "        [ -n \"$path\" ] || continue\n"
        "        dir=$(dirname \"$path\")\n"
        "        [ -d \"$dir\" ] || mkdir -p \"$dir\"\n"
        "        if [ -d \"$path\" ] && [ ! -L \"$path\" ]; then\n"
        "            rm -rf \"$path\"\n"
        "        else\n"
        "            rm -f \"$path\"\n"
        "        fi\n"
        "        ln -s \"$target\" \"$path\"\n"
        "    done <\"$LINKS_MANIFEST\"\n"
        "}\n"
        "\n"
        "preclean_runtime_links() {\n"
        "    [ -f \"$LINKS_MANIFEST\" ] || return 0\n"
        "    while read -r path target; do\n"
        "        [ -n \"$path\" ] || continue\n"
        "        if [ -d \"$path\" ] && [ ! -L \"$path\" ]; then\n"
        "            rm -rf \"$path\"\n"
        "        else\n"
        "            rm -f \"$path\"\n"
        "        fi\n"
        "    done <\"$LINKS_MANIFEST\"\n"
        "}\n"
        "\n"
        "ensure_installed() {\n"
        "    if [ ! -f \"$BOOT_STAMP\" ]; then\n"
        "        [ -f \"$STAGE_TAR\" ] || {\n"
        "            echo \"missing X11 payload: $STAGE_TAR\" >&2\n"
        "            exit 1\n"
        "        }\n"
        "        rm -rf /var/log/apk.log >/dev/null 2>&1 || true\n"
        "        rm -f \"$INSTALL_LOG\"\n"
        "        preclean_runtime_links\n"
        "        if ! tar -xf \"$STAGE_TAR\" -C / >\"$INSTALL_LOG\" 2>&1; then\n"
        "            cat \"$INSTALL_LOG\" >&2 || true\n"
        "            exit 1\n"
        "        fi\n"
        "        : >\"$BOOT_STAMP\"\n"
        "    fi\n"
        "    repair_runtime_links\n"
        "    prepare_runtime\n"
        "}\n"
        "\n"
        "require_runtime() {\n"
        "    if have_runtime; then\n"
        "        return 0\n"
        "    fi\n"
        "    echo \"incomplete X11 runtime after install\" >&2\n"
        "    return 1\n"
        "}\n"
        "\n"
        "write_config() {\n"
        "    [ -d /etc/X11 ] || mkdir /etc/X11\n"
        "    cat >\"$CONF\" <<'EOF'\n"
        f"{config_text}\n"
        "EOF\n"
        "}\n"
        "\n"
        "spawn_detached() {\n"
        "    log=$1\n"
        "    pidfile=$2\n"
        "    shift 2\n"
        "    sh -c 'trap \"\" HUP; exec \"$@\"' sh \"$@\" >\"$log\" 2>&1 </dev/null &\n"
        "    pid=$!\n"
        "    echo \"$pid\" >\"$pidfile\"\n"
        "}\n"
        "\n"
        "stop_all() {\n"
        "    pid=$(cat \"$IPID\" 2>/dev/null || true)\n"
        "    if [ -n \"$pid\" ]; then\n"
        "        kill \"$pid\" 2>/dev/null || true\n"
        "    fi\n"
        "    pid=$(cat \"$CPID\" 2>/dev/null || true)\n"
        "    if [ -n \"$pid\" ]; then\n"
        "        kill \"$pid\" 2>/dev/null || true\n"
        "    fi\n"
        "    pid=$(cat \"$XPID\" 2>/dev/null || true)\n"
        "    if [ -n \"$pid\" ]; then\n"
        "        kill \"$pid\" 2>/dev/null || true\n"
        "    fi\n"
        "    rm -f \"$IPID\" \"$IOFF\" \"$CPID\" \"$XPID\" /tmp/.X0-lock /tmp/.X11-unix/X0\n"
        "}\n"
        "\n"
        "start_server() {\n"
        "    ensure_installed || true\n"
        "    require_runtime\n"
        "    write_config\n"
        "    [ -d /tmp/.X11-unix ] || mkdir /tmp/.X11-unix\n"
        "    if [ -S /tmp/.X11-unix/X0 ]; then\n"
        "        pid=$(cat \"$XPID\" 2>/dev/null || true)\n"
        "        if [ -n \"$pid\" ] && kill -0 \"$pid\" 2>/dev/null; then\n"
        "            return 0\n"
        "        fi\n"
        "        if DISPLAY=:0 xdpyinfo >/dev/null 2>&1; then\n"
        "            return 0\n"
        "        fi\n"
        "    fi\n"
        "    rm -f \"$XLOG\" \"$XPID\" /tmp/.X0-lock /tmp/.X11-unix/X0\n"
        "    spawn_detached \"$XLOG\" \"$XPID\" X -retro\n"
        "    pid=$(cat \"$XPID\" 2>/dev/null || true)\n"
        "    saw_socket=0\n"
        "    for i in $(seq 1 120); do\n"
        "        if [ -S /tmp/.X11-unix/X0 ]; then\n"
        "            saw_socket=1\n"
        "            if DISPLAY=:0 xdpyinfo >/dev/null 2>&1; then\n"
        "                return 0\n"
        "            fi\n"
        "            if timeout 2 sh -c 'DISPLAY=:0 xwininfo -root >/dev/null 2>&1'; then\n"
        "                return 0\n"
        "            fi\n"
        "        fi\n"
        "        if ! kill -0 \"$pid\" 2>/dev/null; then\n"
        "            cat \"$XLOG\" >&2 || true\n"
        "            return 1\n"
        "        fi\n"
        "        sleep 0.1\n"
        "    done\n"
        "    if [ \"$saw_socket\" -eq 1 ]; then\n"
        "        return 0\n"
        "    fi\n"
        "    cat \"$XLOG\" >&2 || true\n"
        "    return 1\n"
        "}\n"
        "\n"
        "start_client() {\n"
        "    ensure_installed || true\n"
        "    require_runtime\n"
        "    rm -f \"$CLOG\" \"$CPID\"\n"
        "    raw_log=${CLOG}.raw\n"
        "    diag_log=${CLOG}.diag\n"
        "    rm -f \"$raw_log\" \"$diag_log\"\n"
        "    spawn_detached \"$raw_log\" \"$CPID\" env DISPLAY=:0 \"$XCALC_BIN\" --log-input -geometry 240x320+40+40\n"
        "    pid=$(cat \"$CPID\" 2>/dev/null || true)\n"
        "    tree_log=/tmp/lab_xwininfo.log\n"
        "    printf 'pid=%s\\n' \"$pid\" >\"$diag_log\"\n"
        "    ls -l \"/proc/$pid/fd\" >>\"$diag_log\" 2>&1 || true\n"
        "    for i in $(seq 1 80); do\n"
        "        timeout 2 sh -c 'DISPLAY=:0 xwininfo -root -tree' >\"$tree_log\" 2>&1 || true\n"
        "        if grep -q '\"xcalc\"' \"$tree_log\" 2>/dev/null; then\n"
        "            cat \"$diag_log\" \"$raw_log\" \"$tree_log\" 2>/dev/null >\"$CLOG\" || true\n"
        "            return 0\n"
        "        fi\n"
        "        if ! kill -0 \"$pid\" 2>/dev/null; then\n"
        "            cat \"$diag_log\" \"$raw_log\" \"$tree_log\" 2>/dev/null >\"$CLOG\" || true\n"
        "            cat \"$CLOG\" >&2 || true\n"
        "            return 1\n"
        "        fi\n"
        "        sleep 0.1\n"
        "    done\n"
        "    cat \"$diag_log\" \"$raw_log\" \"$tree_log\" 2>/dev/null >\"$CLOG\" || true\n"
        "    cat \"$CLOG\" >&2 || true\n"
        "    return 1\n"
        "}\n"
        "\n"
        "run_manual_client() {\n"
        "    stop_all\n"
        "    start_server\n"
        "    start_client\n"
        "    pid=$(cat \"$CPID\" 2>/dev/null || true)\n"
        "    if [ -n \"$pid\" ]; then\n"
        "        wait \"$pid\" 2>/dev/null || true\n"
        "    fi\n"
        "}\n"
        "\n"
        "start_input_probe() {\n"
        "    ensure_installed || true\n"
        "    require_runtime\n"
        "    rm -f \"$IPID\" \"$IOFF\"\n"
        "    raw_log=\"$ILOG\"\n"
        "    pid=$(cat \"$CPID\" 2>/dev/null || true)\n"
        "    if [ -z \"$pid\" ] || ! kill -0 \"$pid\" 2>/dev/null; then\n"
        "        return 1\n"
        "    fi\n"
        "    count=$(wc -c <\"$raw_log\" 2>/dev/null || echo 0)\n"
        "    printf '%s\\n' \"$count\" >\"$IOFF\"\n"
        "    echo \"$pid\" >\"$IPID\"\n"
        "    sleep 0.1\n"
        "    return 0\n"
        "}\n"
        "\n"
        "case \"${1:-start}\" in\n"
        "    install)\n"
        "        ensure_installed\n"
        "        ;;\n"
        "    server)\n"
        "        stop_all\n"
        "        start_server\n"
        f"        printf '{X11_SERVER_TOKEN}\\n'\n"
        "        ;;\n"
        "    client)\n"
        "        start_client\n"
        f"        printf '{X11_CLIENT_TOKEN}\\n'\n"
        "        ;;\n"
        "    input)\n"
        "        start_input_probe\n"
        f"        printf '{X11_INPUT_TOKEN}\\n'\n"
        "        ;;\n"
        "    start|demo)\n"
        "        run_manual_client\n"
        "        printf 'x11-manual-lab\\n'\n"
        "        ;;\n"
        "    stop)\n"
        "        stop_all\n"
        "        ;;\n"
        "    *)\n"
        "        echo \"usage: $0 [install|server|client|input|start|stop]\" >&2\n"
        "        exit 1\n"
        "        ;;\n"
        "esac\n"
    )
    X11_HELPER_LOCAL.write_text(script, encoding="utf-8")
    X11_HELPER_LOCAL.chmod(0o755)
    return X11_HELPER_LOCAL


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


@lru_cache(maxsize=4)
def tar_symlinks(tar_path: pathlib.Path) -> tuple[tuple[str, str], ...]:
    listing = subprocess.run(
        ["tar", "-tvf", str(tar_path)],
        capture_output=True,
        text=True,
        check=True,
        cwd=REPO_ROOT,
    )
    links: list[tuple[str, str]] = []
    for line in listing.stdout.splitlines():
        if not line.startswith("l"):
            continue
        if " -> " not in line:
            continue
        left, target = line.split(" -> ", 1)
        fields = left.split(None, 5)
        if len(fields) < 6:
            continue
        guest = "/" + fields[5].lstrip("/")
        links.append((guest, target))
    return tuple(links)


def ensure_x11_links_manifest(arch: str) -> pathlib.Path:
    X11_STAGE_DIR.mkdir(parents=True, exist_ok=True)
    manifest = X11_STAGE_DIR / f"x11-links-{arch}.txt"
    tar_path = get_x11_stage_tar(arch)
    lines = [f"{guest} {target}" for guest, target in tar_symlinks(tar_path)]
    content = "\n".join(lines) + ("\n" if lines else "")
    if not manifest.exists() or manifest.read_text(encoding="utf-8") != content:
        manifest.write_text(content, encoding="utf-8")
    return manifest


def repair_tar_symlinks_in_image(img: pathlib.Path, tar_path: pathlib.Path) -> None:
    for guest, target in tar_symlinks(tar_path):
        debugfs_run(img, f"rm {guest}")
        debugfs_run(img, f"symlink {guest} {target}", check=True)


def debugfs_exists(img: pathlib.Path, guest: str) -> bool:
    completed = subprocess.run(
        ["debugfs", "-R", f"stat {guest}", str(img)],
        capture_output=True,
        text=True,
    )
    output = (completed.stdout or "") + (completed.stderr or "")
    return completed.returncode == 0 and "File not found" not in output


def materialize_tar_into_image(img: pathlib.Path, tar_path: pathlib.Path) -> None:
    with tempfile.TemporaryDirectory(prefix="starry-stage-") as stage_dir:
        stage_root = pathlib.Path(stage_dir)
        subprocess.run(
            ["tar", "-xf", str(tar_path), "-C", str(stage_root)],
            check=True,
            cwd=REPO_ROOT,
        )
        dirs = sorted(
            (path for path in stage_root.rglob("*") if path.is_dir()),
            key=lambda path: len(path.relative_to(stage_root).parts),
        )
        for path in dirs:
            guest = "/" + str(path.relative_to(stage_root))
            debugfs_mkdir(img, guest)
        for path in sorted(stage_root.rglob("*")):
            guest = "/" + str(path.relative_to(stage_root))
            if path.is_symlink():
                debugfs_run(img, f"rm {guest}")
                debugfs_run(img, f"symlink {guest} {os.readlink(path)}", check=True)
            elif path.is_file():
                debugfs_write(img, path, guest)


def ensure_guest_helpers(demo: Demo, arch: str, img: pathlib.Path) -> None:
    if demo.name not in {"cow", "filemap", "shm", "fb", "ev", "gui", "snake", "x11", "pty", "jobctl", "waitctl", "ssh-poll", "ssh-select", "sshd"}:
        return
    if demo.name == "cow":
        helper = compile_helper(COWCTL_HELPER_SOURCE, "cowctl", arch)
        debugfs_write(img, helper, COWCTL_HELPER_GUEST)
    if demo.name == "filemap":
        helper = compile_helper(FILEMAP_HELPER_SOURCE, "filemapctl", arch)
        debugfs_write(img, helper, FILEMAP_HELPER_GUEST)
    if demo.name == "shm":
        helper = compile_helper(SHMCHECK_HELPER_SOURCE, "shmcheck", arch)
        debugfs_write(img, helper, SHMCHECK_HELPER_GUEST)
    if demo.name == "fb":
        helper = compile_helper(FBDRAW_HELPER_SOURCE, "fbdraw", arch)
        debugfs_write(img, helper, FBDRAW_HELPER_GUEST)
    if demo.name == "ev":
        helper = compile_helper(EVWATCH_HELPER_SOURCE, "evwatch", arch)
        debugfs_write(img, helper, EVWATCH_HELPER_GUEST)
    if demo.name == "x11":
        fb_helper = compile_helper(FBDRAW_HELPER_SOURCE, "fbdraw", arch)
        ev_helper = compile_helper(EVWATCH_HELPER_SOURCE, "evwatch", arch)
        xcalc_helper = compile_x11_helper(XCALC_HELPER_SOURCE, "xcalc-lab", arch)
        links_manifest = ensure_x11_links_manifest(arch)
        debugfs_write(img, fb_helper, FBDRAW_HELPER_GUEST)
        debugfs_write(img, ev_helper, EVWATCH_HELPER_GUEST)
        debugfs_write(img, xcalc_helper, XCALC_HELPER_GUEST)
        debugfs_mkdir(img, "/usr/share/starry-lab")
        debugfs_write(img, get_x11_stage_tar(arch), X11_STAGE_TAR_GUEST)
        debugfs_write(img, links_manifest, X11_LINKS_GUEST)
        debugfs_write(img, ensure_x11_helper_script(), X11_HELPER_GUEST)
    if demo.name == "gui":
        helper = compile_helper(MINIGUI_HELPER_SOURCE, "minigui", arch)
        debugfs_write(img, helper, MINIGUI_HELPER_GUEST)
    if demo.name == "snake":
        helper = compile_helper(SNAKE_HELPER_SOURCE, "snake", arch)
        debugfs_write(img, helper, SNAKE_HELPER_GUEST)
    if demo.name in {"pty", "jobctl", "ssh-poll", "ssh-select"}:
        helper = compile_helper(PTY_HELPER_SOURCE, "pty-relay", arch)
        debugfs_write(img, helper, PTY_HELPER_GUEST)
    if demo.name == "waitctl":
        helper = compile_helper(WAITCTL_HELPER_SOURCE, "waitctl", arch)
        debugfs_write(img, helper, WAITCTL_HELPER_GUEST)
    if demo.name == "sshd":
        ttysig = compile_helper(TTYSIG_HELPER_SOURCE, "ttysig", arch)
        debugfs_write(img, ttysig, TTYSIG_HELPER_GUEST)
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


def create_lab_disk(base_img: pathlib.Path, demo: Demo) -> pathlib.Path:
    disk_dir = LAB_BIN_DIR / "run-disks"
    disk_dir.mkdir(parents=True, exist_ok=True)
    fd, raw_path = tempfile.mkstemp(prefix=f"{demo.name}-", suffix=".img", dir=disk_dir)
    os.close(fd)
    run_disk = pathlib.Path(raw_path)
    shutil.copyfile(base_img, run_disk)
    return run_disk


def spawn_qemu(
    arch: str,
    net: str,
    graphic: str,
    input_devices: str,
    disk_img: pathlib.Path,
    hostfwd: str = "n",
    snapshot: str = "y",
) -> subprocess.Popen[str]:
    if graphic == "y" or input_devices == "y":
        LAB_BIN_DIR.mkdir(parents=True, exist_ok=True)
        try:
            QMP_SOCKET.unlink()
        except FileNotFoundError:
            pass
        qmp_args = f" -qmp unix:{QMP_SOCKET},server=on,wait=off"
    else:
        qmp_args = ""
    qemu_args = f"{'-snapshot ' if snapshot == 'y' else ''}-monitor none -serial tcp::{SERIAL_PORT},server=on{qmp_args}"
    return subprocess.Popen(
        [
            "make",
            f"ARCH={arch}",
            f"APP_FEATURES={BASELINE_APP_FEATURES}",
            f"NET={net}",
            f"GRAPHIC={graphic}",
            f"INPUT={input_devices}",
            f"HEADLESS_GRAPHIC={'y' if graphic == 'y' else 'n'}",
            f"DISK_IMG={disk_img}",
            f"HOSTFWD={hostfwd}",
            f"ACCEL={BASELINE_ACCEL}",
            f"ICOUNT={BASELINE_ICOUNT}",
            f"SMP={BASELINE_SMP}",
            "justrun",
            f"QEMU_ARGS={qemu_args}",
        ],
        stderr=subprocess.PIPE,
        text=True,
    )


def prepare_x11_base(arch: str, boot_timeout: float, command_timeout: float) -> pathlib.Path:
    def image_seeded(img: pathlib.Path) -> bool:
        required = (
            X11_HELPER_GUEST,
            XCALC_HELPER_GUEST,
            X11_STAGE_TAR_GUEST,
            X11_LINKS_GUEST,
            "/usr/bin/X",
            "/usr/bin/xwininfo",
            "/usr/libexec/Xorg",
        )
        return all(debugfs_exists(img, path) for path in required)

    base_img = ensure_working_disk(arch)
    X11_STAGE_DIR.mkdir(parents=True, exist_ok=True)
    prepared_img = X11_STAGE_DIR / f"x11-base-{arch}.img"
    stage_tar = get_x11_stage_tar(arch)
    newest_input = max(
        base_img.stat().st_mtime,
        stage_tar.stat().st_mtime,
        ensure_x11_helper_script().stat().st_mtime,
        ensure_x11_links_manifest(arch).stat().st_mtime,
        FBDRAW_HELPER_SOURCE.stat().st_mtime,
        EVWATCH_HELPER_SOURCE.stat().st_mtime,
        XCALC_HELPER_SOURCE.stat().st_mtime,
        pathlib.Path(__file__).stat().st_mtime,
    )
    if prepared_img.exists() and prepared_img.stat().st_mtime >= newest_input:
        repair_tar_symlinks_in_image(prepared_img, stage_tar)
        if image_seeded(prepared_img):
            return prepared_img

    shutil.copyfile(base_img, prepared_img)
    ensure_guest_helpers(DEMOS["x11"], arch, prepared_img)
    materialize_tar_into_image(prepared_img, stage_tar)
    repair_tar_symlinks_in_image(prepared_img, stage_tar)
    if not image_seeded(prepared_img):
        raise RuntimeError(f"failed to prepare X11 helper image {prepared_img}")
    return prepared_img


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
        "set -m",
        "stty tostop",
        "stty -tostop",
        "echo jobctl-lab",
        "echo ssh-lab",
        f"printf '{SSHD_PHASE4_TOKEN}\\n'",
        f"printf '{SSHD_PHASE5A_TOKEN}\\n'",
        f"printf '{SSHD_PHASE5B_TOKEN}\\n'",
        "PS1=",
        "export PS1",
        f"printf '{SSHD_PHASE2_TOKEN}\\n'",
        r"printf${IFS}sshd-lab\\n",
        r"printf${IFS}ssh-lab\\n",
        f"sh -c 'sleep 1 & wait $!; printf \"{SSHD_PHASE3_TOKEN}\\\\n\"'",
        f"{TTYSIG_HELPER_GUEST} write &",
        f"{TTYSIG_HELPER_GUEST} read &",
        "sleep 1 & wait",
        r"sleep${IFS}1&wait",
        "sleep 1 &",
        r"sleep${IFS}1&",
        "wait $!",
        r"wait${IFS}$!",
        "ttin-input",
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


def format_fb_ioctl(raw: str) -> str:
    value = parse_usize(raw)
    return FB_IOCTL_NAMES.get(value, raw)


def decode_input_event(raw: str) -> str:
    value = parse_usize(raw)
    if value == 0:
        return "unknown"
    event_type = (value >> 16) & 0xffff
    code = value & 0xffff
    ty_name = INPUT_EVENT_TYPE_NAMES.get(event_type, f"type={event_type}")
    code_name = INPUT_EVENT_CODE_NAMES.get((event_type, code))
    if code_name is None:
        return f"{ty_name}/code={code}"
    return f"{ty_name}/{code_name}"


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


def describe_fb_ioctl(event: TraceEvent) -> str:
    cmd = parse_usize(event.arg0)
    if cmd == 0x4600:
        packed = parse_usize(event.arg1)
        width = packed >> 16
        height = packed & 0xffff
        return f"{format_fb_ioctl(event.arg0)} -> {width}x{height}"
    if cmd == 0x4602:
        return f"{format_fb_ioctl(event.arg0)} -> line_length={format_small_int(event.arg1)}"
    return format_fb_ioctl(event.arg0)


def describe_fb_map(event: TraceEvent) -> str:
    return f"map /dev/fb0 size={format_small_int(event.arg0)}"


def describe_input_open(event: TraceEvent) -> str:
    node = INPUT_NODE_NAMES.get(parse_usize(event.arg1), "unknown")
    return f"open /dev/input/{node} -> fd={format_fd(event.arg0)}"


def describe_input_read(event: TraceEvent) -> str:
    return f"read {format_small_int(event.arg0)} byte(s) first={decode_input_event(event.arg1)}"


def describe_input_poll_wake(event: TraceEvent) -> str:
    return f"input became ready via {decode_input_event(event.arg1)}"


def describe_display_flush(_event: TraceEvent) -> str:
    return "first framebuffer flush reached the display backend"


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
        elif event.kind == "FbIoctl":
            detail = describe_fb_ioctl(event)
        elif event.kind == "FbMap":
            detail = describe_fb_map(event)
        elif event.kind == "InputOpen":
            detail = describe_input_open(event)
        elif event.kind == "InputRead":
            detail = describe_input_read(event)
        elif event.kind == "InputPollWake":
            detail = describe_input_poll_wake(event)
        elif event.kind == "DisplayFlush":
            detail = describe_display_flush(event)
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
    if demo.name == "cow":
        helper_parent_tid: int | None = None
        helper_child_tid: int | None = None
        for view in reversed(selected_views):
            if view.label != "SysExit":
                continue
            if syscall_name(view.event.arg0) != "clone":
                continue
            child_tid = parse_i64(view.event.arg1)
            if child_tid <= 0:
                continue
            helper_parent_tid = view.event.tid
            helper_child_tid = child_tid
            break
        if helper_parent_tid is not None and helper_child_tid is not None:
            keep_syscalls = {"mmap", "mprotect", "clone", "wait4", "munmap"}
            keep_labels = {"PageFault", "WaitReap", "TaskExit", "SignalSend", "SignalHandle"}
            keep: set[int] = set()
            pending_syscalls: dict[int, str] = {}
            region_start: int | None = None
            for view in views:
                if view.event.tid not in {helper_parent_tid, helper_child_tid}:
                    continue
                if (
                    view.label == "SysExit"
                    and view.event.tid == helper_parent_tid
                    and syscall_name(view.event.arg0) == "mmap"
                    and region_start is None
                    and parse_i64(view.event.arg1) > 0
                ):
                    region_start = parse_i64(view.event.arg1)
                if view.label in keep_labels:
                    if view.label == "PageFault":
                        if region_start is None:
                            continue
                        fault_addr = parse_usize(view.event.arg0)
                        if not (region_start <= fault_addr < region_start + 0x2000):
                            continue
                    keep.add(view.event.seq)
                    continue
                if view.label == "SysEnter":
                    name = syscall_name(view.event.arg0)
                    if name in keep_syscalls:
                        keep.add(view.event.seq)
                        pending_syscalls[view.event.tid] = name
                    continue
                if view.label == "SysExit":
                    name = syscall_name(view.event.arg0)
                    if pending_syscalls.get(view.event.tid) == name:
                        keep.add(view.event.seq)
                        pending_syscalls.pop(view.event.tid, None)
            selected_views = [view for view in views if view.event.seq in keep]
    if demo.name == "filemap":
        helper_tid: int | None = None
        region_starts: list[int] = []
        for view in reversed(selected_views):
            if view.label == "WaitReap":
                helper_tid = parse_usize(view.event.arg0)
                break
        if helper_tid is not None:
            keep_syscalls = {"openat", "ftruncate", "mmap", "pread64", "pwrite64", "munmap", "close"}
            keep_labels = {"PageFault", "WaitReap", "TaskExit", "SignalSend", "SignalHandle"}
            keep: set[int] = set()
            pending_syscalls: dict[int, str] = {}
            parent_tid = next(
                (view.event.tid for view in views if view.label == "WaitReap" and parse_usize(view.event.arg0) == helper_tid),
                None,
            )
            for view in views:
                if view.event.tid == helper_tid and view.label == "SysExit" and syscall_name(view.event.arg0) == "mmap":
                    start = parse_i64(view.event.arg1)
                    if start > 0:
                        region_starts.append(start)
                if view.event.tid == helper_tid:
                    if view.label in keep_labels:
                        if view.label == "PageFault":
                            fault_addr = parse_usize(view.event.arg0)
                            if not any(start <= fault_addr < start + 0x1000 for start in region_starts):
                                continue
                        keep.add(view.event.seq)
                        continue
                    if view.label == "SysEnter":
                        name = syscall_name(view.event.arg0)
                        if name in keep_syscalls:
                            keep.add(view.event.seq)
                            pending_syscalls[view.event.tid] = name
                        continue
                    if view.label == "SysExit":
                        name = syscall_name(view.event.arg0)
                        if pending_syscalls.get(view.event.tid) == name:
                            keep.add(view.event.seq)
                            pending_syscalls.pop(view.event.tid, None)
                        continue
                if parent_tid is not None and view.event.tid == parent_tid and view.label in {"WaitReap", "SignalSend", "SignalHandle"}:
                    keep.add(view.event.seq)
                    if view.label == "SignalHandle" and view.event.arg0 != "0x11":
                        keep.discard(view.event.seq)
            selected_views = [view for view in views if view.event.seq in keep]
    if demo.name == "shm":
        helper_parent_tid: int | None = None
        helper_child_tid: int | None = None
        region_start: int | None = None
        for view in reversed(selected_views):
            if view.label != "SysExit":
                continue
            if syscall_name(view.event.arg0) != "clone":
                continue
            child_tid = parse_i64(view.event.arg1)
            if child_tid <= 0:
                continue
            helper_parent_tid = view.event.tid
            helper_child_tid = child_tid
            break
        if helper_parent_tid is not None and helper_child_tid is not None:
            keep_syscalls = {"shmget", "shmat", "clone", "wait4", "shmdt", "shmctl"}
            keep_labels = {"PageFault", "WaitReap", "TaskExit", "SignalSend", "SignalHandle"}
            keep: set[int] = set()
            pending_syscalls: dict[int, str] = {}
            for view in views:
                if view.event.tid not in {helper_parent_tid, helper_child_tid}:
                    continue
                if (
                    view.label == "SysExit"
                    and view.event.tid == helper_parent_tid
                    and syscall_name(view.event.arg0) == "shmat"
                    and region_start is None
                    and parse_i64(view.event.arg1) > 0
                ):
                    region_start = parse_i64(view.event.arg1)
                if view.label in keep_labels:
                    if view.label == "PageFault":
                        if region_start is None:
                            continue
                        fault_addr = parse_usize(view.event.arg0)
                        if not (region_start <= fault_addr < region_start + 0x1000):
                            continue
                    keep.add(view.event.seq)
                    continue
                if view.label == "SysEnter":
                    name = syscall_name(view.event.arg0)
                    if name in keep_syscalls:
                        keep.add(view.event.seq)
                        pending_syscalls[view.event.tid] = name
                    continue
                if view.label == "SysExit":
                    name = syscall_name(view.event.arg0)
                    if pending_syscalls.get(view.event.tid) == name:
                        keep.add(view.event.seq)
                        pending_syscalls.pop(view.event.tid, None)
            selected_views = [view for view in views if view.event.seq in keep]
    if demo.name == "fb":
        helper_tid: int | None = None
        fb_fd: int | None = None
        mmap_exit_seq: int | None = None
        page_fault_budget = 8
        for view in reversed(selected_views):
            if view.label == "WaitReap":
                helper_tid = parse_usize(view.event.arg0)
                break
        if helper_tid is not None:
            keep_syscalls = {"openat", "ioctl", "mmap", "munmap", "close"}
            keep_labels = {"FbIoctl", "FbMap", "DisplayFlush", "PageFault", "WaitReap", "TaskExit", "SignalSend", "SignalHandle"}
            keep: set[int] = set()
            pending_syscalls: dict[int, str] = {}
            parent_tid = next(
                (view.event.tid for view in views if view.label == "WaitReap" and parse_usize(view.event.arg0) == helper_tid),
                None,
            )
            for view in views:
                if view.label == "DisplayFlush":
                    keep.add(view.event.seq)
                    continue
                if view.event.tid == helper_tid:
                    if (
                        view.label == "SysExit"
                        and syscall_name(view.event.arg0) == "openat"
                        and fb_fd is None
                        and parse_i64(view.event.arg1) >= 0
                    ):
                        fb_fd = parse_i64(view.event.arg1)
                    if (
                        view.label == "SysExit"
                        and syscall_name(view.event.arg0) == "mmap"
                        and parse_i64(view.event.arg1) > 0
                        and mmap_exit_seq is None
                    ):
                        mmap_exit_seq = view.event.seq
                    if view.label in keep_labels:
                        if view.label == "PageFault":
                            if mmap_exit_seq is None or view.event.seq <= mmap_exit_seq or page_fault_budget <= 0:
                                continue
                            page_fault_budget -= 1
                        keep.add(view.event.seq)
                        continue
                    if view.label == "SysEnter":
                        name = syscall_name(view.event.arg0)
                        if name in keep_syscalls:
                            if name in {"ioctl", "close"} and (fb_fd is None or parse_i64(view.event.arg1) != fb_fd):
                                continue
                            keep.add(view.event.seq)
                            pending_syscalls[view.event.tid] = name
                        continue
                    if view.label == "SysExit":
                        name = syscall_name(view.event.arg0)
                        if pending_syscalls.get(view.event.tid) == name:
                            keep.add(view.event.seq)
                            pending_syscalls.pop(view.event.tid, None)
                        continue
                if parent_tid is not None and view.event.tid == parent_tid and view.label in {"WaitReap", "SignalSend", "SignalHandle"}:
                    keep.add(view.event.seq)
                    if view.label == "SignalHandle" and view.event.arg0 != "0x11":
                        keep.discard(view.event.seq)
            selected_views = [view for view in views if view.event.seq in keep]
    if demo.name == "ev":
        helper_tid: int | None = None
        input_fds: set[int] = set()
        for view in reversed(selected_views):
            if view.label == "WaitReap":
                helper_tid = parse_usize(view.event.arg0)
                break
        if helper_tid is not None:
            keep_syscalls = {"openat", "ioctl", "read", "close"}
            keep_labels = {"InputOpen", "InputRead", "InputPollWake", "PollSleep", "PollWake", "WaitReap", "TaskExit", "SignalSend", "SignalHandle"}
            keep: set[int] = set()
            pending_syscalls: dict[int, str] = {}
            parent_tid = next(
                (view.event.tid for view in views if view.label == "WaitReap" and parse_usize(view.event.arg0) == helper_tid),
                None,
            )
            for view in views:
                if view.event.tid == helper_tid:
                    if (
                        view.label == "SysExit"
                        and syscall_name(view.event.arg0) == "openat"
                        and parse_i64(view.event.arg1) >= 0
                        and len(input_fds) < 2
                    ):
                        input_fds.add(parse_i64(view.event.arg1))
                    if view.label in keep_labels:
                        keep.add(view.event.seq)
                        continue
                    if view.label == "SysEnter":
                        name = syscall_name(view.event.arg0)
                        if name in keep_syscalls:
                            if name in {"ioctl", "read", "close"} and parse_i64(view.event.arg1) not in input_fds:
                                continue
                            keep.add(view.event.seq)
                            pending_syscalls[view.event.tid] = name
                        continue
                    if view.label == "SysExit":
                        name = syscall_name(view.event.arg0)
                        if pending_syscalls.get(view.event.tid) == name:
                            keep.add(view.event.seq)
                            pending_syscalls.pop(view.event.tid, None)
                        continue
                if parent_tid is not None and view.event.tid == parent_tid and view.label in {"WaitReap", "SignalSend", "SignalHandle"}:
                    keep.add(view.event.seq)
                    if view.label == "SignalHandle" and view.event.arg0 != "0x11":
                        keep.discard(view.event.seq)
            selected_views = [view for view in views if view.event.seq in keep]
            collapsed: list[EventView] = []
            previous_signature: tuple[str, str] | None = None
            for view in selected_views:
                if view.label in {"PollSleep", "PollWake"}:
                    signature = (view.label, view.detail)
                    if signature == previous_signature:
                        continue
                    previous_signature = signature
                    collapsed.append(view)
                    continue
                previous_signature = None
                collapsed.append(view)
            selected_views = collapsed
    if demo.name == "gui":
        helper_tid: int | None = None
        fb_fd: int | None = None
        input_fds: set[int] = set()
        mmap_exit_seq: int | None = None
        page_fault_budget = 8
        for view in reversed(selected_views):
            if view.label == "WaitReap":
                helper_tid = parse_usize(view.event.arg0)
                break
        if helper_tid is not None:
            keep_syscalls = {"openat", "ioctl", "mmap", "read", "munmap", "close"}
            keep_labels = {"FbIoctl", "FbMap", "DisplayFlush", "InputOpen", "InputRead", "InputPollWake", "PageFault", "PollSleep", "PollWake", "WaitReap", "TaskExit", "SignalSend", "SignalHandle"}
            keep: set[int] = set()
            pending_syscalls: dict[int, str] = {}
            parent_tid = next(
                (view.event.tid for view in views if view.label == "WaitReap" and parse_usize(view.event.arg0) == helper_tid),
                None,
            )
            for view in views:
                if view.label == "DisplayFlush":
                    keep.add(view.event.seq)
                    continue
                if view.event.tid == helper_tid:
                    if (
                        view.label == "SysExit"
                        and syscall_name(view.event.arg0) == "openat"
                        and parse_i64(view.event.arg1) >= 0
                    ):
                        fd = parse_i64(view.event.arg1)
                        if fb_fd is None:
                            fb_fd = fd
                        else:
                            input_fds.add(fd)
                    if (
                        view.label == "SysExit"
                        and syscall_name(view.event.arg0) == "mmap"
                        and parse_i64(view.event.arg1) > 0
                        and mmap_exit_seq is None
                    ):
                        mmap_exit_seq = view.event.seq
                    if view.label in keep_labels:
                        if view.label == "PageFault":
                            if mmap_exit_seq is None or view.event.seq <= mmap_exit_seq or page_fault_budget <= 0:
                                continue
                            page_fault_budget -= 1
                        keep.add(view.event.seq)
                        continue
                    if view.label == "SysEnter":
                        name = syscall_name(view.event.arg0)
                        if name in keep_syscalls:
                            fd_arg = parse_i64(view.event.arg1)
                            if name in {"ioctl", "close"}:
                                if fd_arg not in ({fb_fd} if fb_fd is not None else set()) | input_fds:
                                    continue
                            if name == "read" and fd_arg not in input_fds:
                                continue
                            keep.add(view.event.seq)
                            pending_syscalls[view.event.tid] = name
                        continue
                    if view.label == "SysExit":
                        name = syscall_name(view.event.arg0)
                        if pending_syscalls.get(view.event.tid) == name:
                            keep.add(view.event.seq)
                            pending_syscalls.pop(view.event.tid, None)
                        continue
                if parent_tid is not None and view.event.tid == parent_tid and view.label in {"WaitReap", "SignalSend", "SignalHandle"}:
                    keep.add(view.event.seq)
                    if view.label == "SignalHandle" and view.event.arg0 != "0x11":
                        keep.discard(view.event.seq)
            selected_views = [view for view in views if view.event.seq in keep]
            collapsed: list[EventView] = []
            previous_signature: tuple[str, str] | None = None
            for view in selected_views:
                if view.label in {"PollSleep", "PollWake"}:
                    signature = (view.label, view.detail)
                    if signature == previous_signature:
                        continue
                    previous_signature = signature
                    collapsed.append(view)
                    continue
                previous_signature = None
                collapsed.append(view)
            selected_views = collapsed
    if demo.name == "snake":
        helper_tid: int | None = None
        fb_fd: int | None = None
        key_fd: int | None = None
        mmap_exit_seq: int | None = None
        page_fault_budget = 8
        for view in reversed(selected_views):
            if view.label == "WaitReap":
                helper_tid = parse_usize(view.event.arg0)
                break
        if helper_tid is not None:
            keep_syscalls = {"openat", "ioctl", "mmap", "read", "munmap", "close"}
            keep_labels = {"FbIoctl", "FbMap", "DisplayFlush", "InputOpen", "InputRead", "InputPollWake", "PageFault", "PollSleep", "PollWake", "WaitReap", "TaskExit", "SignalSend", "SignalHandle"}
            keep: set[int] = set()
            pending_syscalls: dict[int, str] = {}
            parent_tid = next(
                (view.event.tid for view in views if view.label == "WaitReap" and parse_usize(view.event.arg0) == helper_tid),
                None,
            )
            for view in views:
                if view.label == "DisplayFlush":
                    keep.add(view.event.seq)
                    continue
                if view.event.tid == helper_tid:
                    if (
                        view.label == "SysExit"
                        and syscall_name(view.event.arg0) == "openat"
                        and parse_i64(view.event.arg1) >= 0
                    ):
                        fd = parse_i64(view.event.arg1)
                        if fb_fd is None:
                            fb_fd = fd
                        elif key_fd is None:
                            key_fd = fd
                    if (
                        view.label == "SysExit"
                        and syscall_name(view.event.arg0) == "mmap"
                        and parse_i64(view.event.arg1) > 0
                        and mmap_exit_seq is None
                    ):
                        mmap_exit_seq = view.event.seq
                    if view.label in keep_labels:
                        if view.label == "PageFault":
                            if mmap_exit_seq is None or view.event.seq <= mmap_exit_seq or page_fault_budget <= 0:
                                continue
                            page_fault_budget -= 1
                        keep.add(view.event.seq)
                        continue
                    if view.label == "SysEnter":
                        name = syscall_name(view.event.arg0)
                        if name in keep_syscalls:
                            fd_arg = parse_i64(view.event.arg1)
                            if name in {"ioctl", "close"} and fd_arg not in {fb_fd, key_fd}:
                                continue
                            if name == "read" and fd_arg != key_fd:
                                continue
                            keep.add(view.event.seq)
                            pending_syscalls[view.event.tid] = name
                        continue
                    if view.label == "SysExit":
                        name = syscall_name(view.event.arg0)
                        if pending_syscalls.get(view.event.tid) == name:
                            keep.add(view.event.seq)
                            pending_syscalls.pop(view.event.tid, None)
                        continue
                if parent_tid is not None and view.event.tid == parent_tid and view.label in {"WaitReap", "SignalSend", "SignalHandle"}:
                    keep.add(view.event.seq)
                    if view.label == "SignalHandle" and view.event.arg0 != "0x11":
                        keep.discard(view.event.seq)
            selected_views = [view for view in views if view.event.seq in keep]
            collapsed: list[EventView] = []
            previous_signature: tuple[str, str] | None = None
            for view in selected_views:
                if view.label in {"PollSleep", "PollWake"}:
                    signature = (view.label, view.detail)
                    if signature == previous_signature:
                        continue
                    previous_signature = signature
                    collapsed.append(view)
                    continue
                previous_signature = None
                collapsed.append(view)
            selected_views = collapsed
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

    if phase_name == "phase-4-jobctl":
        keep_labels = {
            "PtyOpen",
            "SessionCreate",
            "TtyCtl",
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
        focus_syscalls = {"read", "write", "wait4", "ioctl", "close"}
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

    if phase_name in {"phase-5a-sigttou", "phase-5b-sigttin"}:
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
        focus_syscalls = {"read", "write", "wait4", "ioctl", "close"}
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

    if phase_name == "phase-4-jobctl":
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
        lines = [
            "this phase isolates real SSH job control: Ctrl-Z to stop the foreground job, `fg` to resume it, and Ctrl-C to terminate it from the remote pty.",
        ]
        if sigtstp is not None:
            lines.append("the host-side Ctrl-Z keystroke reached the remote pty and generated SIGTSTP for the foreground job.")
        if wait_stop is not None:
            lines.append(f"the shell reported the stop through {wait_stop.detail}.")
        if sigcont is not None or wait_continue is not None:
            detail = wait_continue.detail if wait_continue is not None else "a SIGCONT-driven foreground resume"
            lines.append(f"`fg` resumed the job, and the continue path showed up as {detail}.")
        if sigint is not None:
            lines.append("the host-side Ctrl-C keystroke generated SIGINT for the resumed foreground job.")
        if wait_reap is not None:
            lines.append(f"the shell's final collection path completed through {wait_reap.detail}.")
        if transcript.strip():
            lines.append("the remote transcript printed `sshd-jobctl-lab`, so the SSH-backed shell really returned control after the Ctrl-Z/fg/Ctrl-C cycle.")
        return tuple(lines)

    if phase_name == "phase-5a-sigttou":
        wait_stop = next((view for view in key_views if view.label == "WaitStop"), None)
        wait_continue = next((view for view in key_views if view.label == "WaitContinue"), None)
        wait_reap = next((view for view in key_views if view.label == "WaitReap"), None)
        sigttou = next(
            (view for view in key_views if view.label == "SignalHandle" and view.detail.startswith("handle SIGTTOU")),
            None,
        )
        lines = [
            "this phase isolates background tty output over a real SSH pty: a background writer runs with `TOSTOP` enabled and should stop on SIGTTOU until foregrounded.",
        ]
        if sigttou is not None:
            lines.append("the background writer hit `TOSTOP` semantics and received SIGTTOU before being foregrounded.")
        if wait_stop is not None:
            lines.append(f"the shell surfaced the resulting stop state through {wait_stop.detail}.")
        if wait_continue is not None:
            lines.append(f"foreground resume activity showed up as {wait_continue.detail}.")
        if wait_reap is not None:
            lines.append(f"the shell eventually reaped the background tty worker through {wait_reap.detail}.")
        if transcript.strip():
            lines.append("the remote transcript included `sshd-sigttou-lab`, so the writer-side tty-stop path completed end to end.")
        return tuple(lines)

    if phase_name == "phase-5b-sigttin":
        wait_stop = next((view for view in key_views if view.label == "WaitStop"), None)
        wait_continue = next((view for view in key_views if view.label == "WaitContinue"), None)
        wait_reap = next((view for view in key_views if view.label == "WaitReap"), None)
        sigttin = next(
            (view for view in key_views if view.label == "SignalHandle" and view.detail.startswith("handle SIGTTIN")),
            None,
        )
        lines = [
            "this phase isolates background tty input over a real SSH pty: a background reader attempts to consume terminal input and should stop on SIGTTIN until foregrounded.",
        ]
        if sigttin is not None:
            lines.append("the background reader attempted to consume tty input and received SIGTTIN until it was foregrounded.")
        if wait_stop is not None:
            lines.append(f"the shell surfaced the resulting stop state through {wait_stop.detail}.")
        if wait_continue is not None:
            lines.append(f"foreground resume activity showed up as {wait_continue.detail}.")
        if wait_reap is not None:
            lines.append(f"the shell eventually reaped the background tty worker through {wait_reap.detail}.")
        if transcript.strip():
            lines.append("the remote transcript included `sigttin:ttin-input` and `sshd-sigttin-lab`, so the reader-side tty-stop path completed end to end.")
        return tuple(lines)

    return ()


def select_waitctl_phase_views(phase_name: str, views: list[EventView]) -> list[EventView]:
    if phase_name == "phase-1-stop":
        keep_labels = {"SignalSend", "SignalHandle", "WaitStop", "WaitReap", "TaskExit"}
    elif phase_name == "phase-2-continue":
        keep_labels = {"SignalSend", "SignalHandle", "WaitStop", "WaitContinue", "WaitReap", "TaskExit"}
    elif phase_name == "phase-3-reap":
        keep_labels = {"SignalSend", "SignalHandle", "WaitReap", "TaskExit"}
    else:
        return views

    focus_syscalls = {"wait4", "kill", "close"}
    keep: set[int] = {view.event.seq for view in views if view.label in keep_labels}
    pending_syscalls: dict[int, str] = {}
    for view in views:
        if view.label == "SysEnter":
            name = syscall_name(view.event.arg0)
            if name in focus_syscalls:
                keep.add(view.event.seq)
                pending_syscalls[view.event.tid] = name
            continue
        if view.label == "SysExit":
            name = syscall_name(view.event.arg0)
            if pending_syscalls.get(view.event.tid) == name:
                keep.add(view.event.seq)
                pending_syscalls.pop(view.event.tid, None)
    return [view for view in views if view.event.seq in keep]


def select_x11_phase_views(phase_name: str, views: list[EventView]) -> list[EventView]:
    helper_wait = next((view for view in views if view.label == "WaitReap"), None)
    helper_tid = parse_usize(helper_wait.event.arg0) if helper_wait is not None else None
    shell_tid = helper_wait.event.tid if helper_wait is not None else None

    if phase_name == "phase-1-fb":
        keep_labels = {"FbIoctl", "FbMap", "DisplayFlush", "PageFault", "WaitReap", "TaskExit"}
        focus_syscalls = {"openat", "mmap", "munmap", "close"}
    elif phase_name == "phase-2-input":
        keep_labels = {"InputOpen", "InputRead", "InputPollWake", "PollSleep", "PollWake", "WaitReap", "TaskExit"}
        focus_syscalls = {"openat", "ioctl", "read", "close"}
    elif phase_name == "phase-3-x11":
        keep_labels = {"PollSleep", "PollWake", "WaitReap", "TaskExit", "SignalSend", "SignalHandle"}
        focus_syscalls = {"socket", "connect", "openat", "read", "write", "close"}
    elif phase_name == "phase-4-xinput":
        keep_labels = {"WaitReap", "TaskExit", "SignalSend", "SignalHandle"}
        focus_syscalls = ()
    else:
        return views

    keep: set[int] = set()
    for view in views:
        if view.label not in keep_labels:
            continue
        if phase_name in {"phase-1-fb", "phase-2-input"}:
            if view.label == "DisplayFlush":
                keep.add(view.event.seq)
                continue
            if view.label == "WaitReap" and shell_tid is not None and view.event.tid == shell_tid:
                keep.add(view.event.seq)
                continue
            if helper_tid is not None and view.event.tid == helper_tid:
                keep.add(view.event.seq)
            continue
        keep.add(view.event.seq)

    pending_syscalls: dict[int, str] = {}
    for view in views:
        if view.label == "SysEnter":
            name = syscall_name(view.event.arg0)
            if name in focus_syscalls:
                if phase_name in {"phase-1-fb", "phase-2-input"} and helper_tid is not None and view.event.tid != helper_tid:
                    continue
                if name in {"read", "write"} and parse_i64(view.event.arg1) in {0, 1, 2}:
                    continue
                keep.add(view.event.seq)
                pending_syscalls[view.event.tid] = name
            continue
        if view.label == "SysExit":
            name = syscall_name(view.event.arg0)
            if pending_syscalls.get(view.event.tid) == name:
                if phase_name in {"phase-1-fb", "phase-2-input"} and helper_tid is not None and view.event.tid != helper_tid:
                    pending_syscalls.pop(view.event.tid, None)
                    continue
                if name in {"read", "write"} and abs(parse_i64(view.event.arg1)) == 1:
                    pending_syscalls.pop(view.event.tid, None)
                    continue
                keep.add(view.event.seq)
                pending_syscalls.pop(view.event.tid, None)
    selected = [view for view in views if view.event.seq in keep]
    collapsed: list[EventView] = []
    previous_signature: tuple[str, str] | None = None
    for view in selected:
        if view.label in {"PollSleep", "PollWake"}:
            signature = (view.label, view.detail)
            if signature == previous_signature:
                continue
            previous_signature = signature
            collapsed.append(view)
            continue
        previous_signature = None
        collapsed.append(view)
    return collapsed


def build_x11_phase_walkthrough(
    phase_name: str,
    key_views: list[EventView],
    transcript: str,
    notes: tuple[str, ...] = (),
) -> tuple[str, ...]:
    if phase_name == "phase-1-fb":
        lines = [
            "this phase isolates the raw framebuffer layer underneath X11 by running a tiny fbdev helper directly on `/dev/fb0`: it opens the node, queries fixed and variable metadata, maps the framebuffer, and draws one deterministic scene.",
        ]
        fb_ioctls = [view for view in key_views if view.label == "FbIoctl"]
        if fb_ioctls:
            lines.append(f"framebuffer metadata flowed through {', '.join(view.detail for view in fb_ioctls[:2])}.")
        fb_map = next((view for view in key_views if view.label == "FbMap"), None)
        if fb_map is not None:
            lines.append(f"userspace gained direct pixel access through {fb_map.detail}.")
        if any(view.label == "PageFault" for view in key_views):
            lines.append("framebuffer-backed pages faulted into the helper while it populated the first frame.")
        if any(view.label == "DisplayFlush" for view in key_views):
            lines.append("the first framebuffer flush reached the display backend, so the raw fbdev scene was no longer only dirty userspace memory.")
        lines.extend(notes)
        return tuple(lines)

    if phase_name == "phase-2-input":
        lines = [
            "this phase isolates the raw evdev layer underneath X11 by running a tiny helper directly on `/dev/input/event0` and `/dev/input/mice`: it opens the nodes, blocks in poll(), and drains deterministic keyboard and mouse activity injected through QEMU.",
        ]
        input_opens = [view for view in key_views if view.label == "InputOpen"]
        if input_opens:
            lines.append(f"the input path opened {', '.join(view.detail for view in input_opens[:2])}.")
        if any(view.label == "InputPollWake" for view in key_views):
            rendered = ", ".join(view.detail for view in key_views if view.label == "InputPollWake")
            lines.append(f"readiness first surfaced as {rendered}.")
        if any(view.label == "InputRead" for view in key_views):
            rendered = ", ".join(view.detail for view in key_views if view.label == "InputRead")
            lines.append(f"userspace then drained actual input records through {rendered}.")
        if any(view.label in {"PollSleep", "PollWake"} for view in key_views):
            lines.append("the server's input loop visibly blocked in poll() and woke again as events arrived.")
        lines.extend(notes)
        return tuple(lines)

    if phase_name == "phase-3-x11":
        lines = [
            "this phase isolates the first Starry Lab X11 client after the raw fbdev and evdev layers are already proven separately: a fresh `X -retro` instance comes up, the teaching calculator connects to it, draws one window, and stays alive long enough for the runner to capture a framebuffer screenshot.",
        ]
        if any(view.label in {"PollSleep", "PollWake"} for view in key_views):
            lines.append("client/server interaction stayed visible through poll wakeups while the X connection became active.")
        if X11_CLIENT_TOKEN in transcript:
            lines.append("the guest printed `x11-lab`, so the teaching calculator stayed alive long enough to prove the GUI client path succeeded.")
        lines.extend(notes)
        return tuple(lines)

    if phase_name == "phase-4-xinput":
        lines = [
            "this phase keeps the X server and the visible teaching calculator window alive, clears the client's input log, then injects deterministic mouse movement and a click so the final step proves that host mouse input reaches a real mapped teaching client while the lab helper bridges `/dev/input/mice` into visible window-local motion and clicks.",
        ]
        if any(view.label == "InputOpen" for view in key_views):
            lines.append("the live graphical stack reopened or kept using input nodes while the mapped client window stayed on screen.")
        if any(view.label == "InputPollWake" for view in key_views):
            rendered = ", ".join(view.detail for view in key_views if view.label == "InputPollWake")
            lines.append(f"mouse readiness then surfaced as {rendered}.")
        if any(view.label == "InputRead" for view in key_views):
            rendered = ", ".join(view.detail for view in key_views if view.label == "InputRead")
            lines.append(f"the X input stack drained actual evdev records through {rendered}.")
        if X11_INPUT_TOKEN in transcript:
            lines.append("the guest printed `x11-input-lab`, so the visible teaching calculator client stayed alive while the runner injected mouse movement and clicks.")
        lines.extend(notes)
        return tuple(lines)

    return ()


def build_waitctl_phase_walkthrough(
    phase_name: str,
    key_views: list[EventView],
    transcript: str,
) -> tuple[str, ...]:
    wait_stop = next((view for view in key_views if view.label == "WaitStop"), None)
    wait_continue = next((view for view in key_views if view.label == "WaitContinue"), None)
    wait_reap = next((view for view in key_views if view.label == "WaitReap"), None)

    if phase_name == "phase-1-stop":
        lines = [
            "this phase isolates the stopped wait4 state: the helper sends SIGTSTP to its child and waits with WUNTRACED.",
        ]
        if wait_stop is not None:
            lines.append(f"`wait4(..., WUNTRACED)` surfaced the stop through {wait_stop.detail}.")
        if wait_reap is not None:
            lines.append(f"after the stop report, the helper cleaned the child up through {wait_reap.detail}.")
        if WAITCTL_STOP_TOKEN in transcript:
            lines.append("the helper printed `waitctl-stop-lab`, so the stop-reporting phase completed end to end.")
        return tuple(lines)

    if phase_name == "phase-2-continue":
        lines = [
            "this phase isolates the continued wait4 state: the helper stops its child, resumes it with SIGCONT, and waits with WCONTINUED.",
        ]
        if wait_stop is not None:
            lines.append(f"the setup stop remained visible as {wait_stop.detail}.")
        if wait_continue is not None:
            lines.append(f"`wait4(..., WCONTINUED)` surfaced the resume through {wait_continue.detail}.")
        if wait_reap is not None:
            lines.append(f"cleanup after the continue phase completed through {wait_reap.detail}.")
        if WAITCTL_CONTINUE_TOKEN in transcript:
            lines.append("the helper printed `waitctl-continue-lab`, so the continue-reporting phase completed end to end.")
        return tuple(lines)

    if phase_name == "phase-3-reap":
        lines = [
            "this phase isolates the final reap path: the helper terminates its child with SIGINT and waits for the terminal status.",
        ]
        if wait_reap is not None:
            lines.append(f"the blocking wait reaped the child through {wait_reap.detail}.")
        if WAITCTL_REAP_TOKEN in transcript:
            lines.append("the helper printed `waitctl-reap-lab`, so the reap-reporting phase completed end to end.")
        return tuple(lines)

    return ()


def render_waitctl_phase_artifacts(
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
    key_views = select_waitctl_phase_views(phase_name, event_views)
    write_text(phase_dir / "key_trace.txt", render_event_table(key_views))
    walkthrough = build_waitctl_phase_walkthrough(phase_name, key_views, transcript)
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


def render_x11_phase_artifacts(
    phase_dir: pathlib.Path,
    phase_name: str,
    title: str,
    events: list[TraceEvent],
    stats_text: str,
    last_fault_text: str,
    input_stream: tuple[str, ...],
    transcript: str,
    notes: tuple[str, ...],
    raw: bool,
) -> PhaseResult:
    phase_dir.mkdir(parents=True, exist_ok=True)
    event_views = build_event_views(events)
    key_views = select_x11_phase_views(phase_name, event_views)
    write_text(phase_dir / "key_trace.txt", render_event_table(key_views))
    walkthrough = build_x11_phase_walkthrough(phase_name, key_views, transcript, notes)
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


def render_x11_key_trace(path: pathlib.Path, phase_results: tuple[PhaseResult, ...]) -> list[EventView]:
    sections: list[str] = []
    combined: list[EventView] = []
    for phase in phase_results:
        sections.append(f"== {phase.name}: {phase.title} ==")
        sections.append(render_event_table(phase.key_views))
        sections.append("")
        combined.extend(phase.key_views)
    write_text(path, "\n".join(sections).rstrip() + "\n")
    return combined


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


def digest_file(path: pathlib.Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()[:16]


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


def qmp_read_message(handle: "socket.SocketIO") -> dict[str, object]:
    while True:
        line = handle.readline()
        if not line:
            raise RuntimeError("qmp connection closed unexpectedly")
        rendered = line.decode("utf-8", errors="replace").strip()
        if not rendered:
            continue
        return json.loads(rendered)


def qmp_execute(handle: "socket.SocketIO", execute: str, arguments: dict[str, object] | None = None) -> dict[str, object]:
    payload: dict[str, object] = {"execute": execute}
    if arguments is not None:
        payload["arguments"] = arguments
    handle.write((json.dumps(payload) + "\r\n").encode("utf-8"))
    handle.flush()
    while True:
        message = qmp_read_message(handle)
        if "return" in message:
            return message
        if "error" in message:
            raise RuntimeError(f"qmp {execute} failed: {message['error']}")


def wait_for_unix_socket(path: pathlib.Path, timeout: float) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if path.exists():
            return
        time.sleep(0.1)
    raise TimeoutError(f"timed out waiting for unix socket: {path}")


def qmp_screendump(path: pathlib.Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    resolved = path.resolve()
    wait_for_unix_socket(QMP_SOCKET, timeout=10.0)
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
        sock.settimeout(10)
        sock.connect(str(QMP_SOCKET))
        handle = sock.makefile("rwb")
        qmp_read_message(handle)
        qmp_execute(handle, "qmp_capabilities")
        qmp_execute(handle, "screendump", {"filename": str(resolved)})


def qmp_send_input_batches(
    batches: tuple[tuple[dict[str, object], ...], ...],
    delay_s: float = 0.08,
) -> None:
    wait_for_unix_socket(QMP_SOCKET, timeout=10.0)
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
        sock.settimeout(10)
        sock.connect(str(QMP_SOCKET))
        handle = sock.makefile("rwb")
        qmp_read_message(handle)
        qmp_execute(handle, "qmp_capabilities")
        for events in batches:
            qmp_execute(handle, "input-send-event", {"events": list(events)})
            time.sleep(delay_s)


def inject_x11_input_sequence() -> str:
    qmp_send_input_batches(
        (
            (
                {"type": "rel", "data": {"axis": "x", "value": 9}},
                {"type": "rel", "data": {"axis": "y", "value": -5}},
            ),
            (
                {"type": "rel", "data": {"axis": "x", "value": -6}},
                {"type": "rel", "data": {"axis": "y", "value": 11}},
            ),
            (
                {"type": "btn", "data": {"down": True, "button": "left"}},
            ),
            (
                {"type": "btn", "data": {"down": False, "button": "left"}},
            ),
        )
    )
    return "the runner injected two mouse moves `(9,-5)` then `(-6,11)` and one left-button click while the visible teaching calculator client was logging input."


def start_input_peer() -> PeerController:
    results: "queue.Queue[PeerResult]" = queue.Queue()

    def worker() -> None:
        try:
            wait_for_unix_socket(QMP_SOCKET, timeout=10.0)
            time.sleep(1.0)
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
                sock.settimeout(10)
                sock.connect(str(QMP_SOCKET))
                handle = sock.makefile("rwb")
                qmp_read_message(handle)
                qmp_execute(handle, "qmp_capabilities")
                qmp_execute(
                    handle,
                    "input-send-event",
                    {
                        "events": [
                            {"type": "key", "data": {"down": True, "key": {"type": "qcode", "data": "a"}}},
                            {"type": "key", "data": {"down": False, "key": {"type": "qcode", "data": "a"}}},
                        ]
                    },
                )
                time.sleep(0.1)
                qmp_execute(
                    handle,
                    "input-send-event",
                    {
                        "events": [
                            {"type": "rel", "data": {"axis": "x", "value": 12}},
                            {"type": "rel", "data": {"axis": "y", "value": -7}},
                        ]
                    },
                )
                time.sleep(0.1)
                qmp_execute(
                    handle,
                    "input-send-event",
                    {"events": [{"type": "btn", "data": {"down": True, "button": "left"}}]},
                )
                time.sleep(0.05)
                qmp_execute(
                    handle,
                    "input-send-event",
                    {"events": [{"type": "btn", "data": {"down": False, "button": "left"}}]},
                )
            results.put(
                PeerResult(
                    notes=(
                        "runner QMP peer injected keyboard `A` press/release, mouse relative move `(12,-7)`, and a left-button click.",
                    )
                )
            )
        except Exception as exc:
            results.put(PeerResult(notes=(f"runner input peer error: {exc}",)))

    thread = threading.Thread(target=worker, daemon=True)
    thread.start()
    return PeerController(thread=thread, results=results)


def start_gui_peer() -> PeerController:
    results: "queue.Queue[PeerResult]" = queue.Queue()

    def worker() -> None:
        try:
            wait_for_unix_socket(QMP_SOCKET, timeout=10.0)
            time.sleep(1.0)
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
                sock.settimeout(10)
                sock.connect(str(QMP_SOCKET))
                handle = sock.makefile("rwb")
                qmp_read_message(handle)
                qmp_execute(handle, "qmp_capabilities")
                qmp_execute(
                    handle,
                    "input-send-event",
                    {
                        "events": [
                            {"type": "key", "data": {"down": True, "key": {"type": "qcode", "data": "d"}}},
                            {"type": "key", "data": {"down": False, "key": {"type": "qcode", "data": "d"}}},
                        ]
                    },
                )
                time.sleep(0.08)
                qmp_execute(
                    handle,
                    "input-send-event",
                    {
                        "events": [
                            {"type": "key", "data": {"down": True, "key": {"type": "qcode", "data": "s"}}},
                            {"type": "key", "data": {"down": False, "key": {"type": "qcode", "data": "s"}}},
                        ]
                    },
                )
                time.sleep(0.08)
                qmp_execute(
                    handle,
                    "input-send-event",
                    {
                        "events": [
                            {"type": "rel", "data": {"axis": "x", "value": 14}},
                            {"type": "rel", "data": {"axis": "y", "value": -9}},
                        ]
                    },
                )
                time.sleep(0.08)
                qmp_execute(
                    handle,
                    "input-send-event",
                    {"events": [{"type": "btn", "data": {"down": True, "button": "left"}}]},
                )
                time.sleep(0.04)
                qmp_execute(
                    handle,
                    "input-send-event",
                    {"events": [{"type": "btn", "data": {"down": False, "button": "left"}}]},
                )
            results.put(
                PeerResult(
                    notes=(
                        "runner QMP peer injected keyboard `D`/`S`, mouse relative move `(14,-9)`, and a left-button click to drive the mini GUI.",
                    )
                )
            )
        except Exception as exc:
            results.put(PeerResult(notes=(f"runner gui peer error: {exc}",)))

    thread = threading.Thread(target=worker, daemon=True)
    thread.start()
    return PeerController(thread=thread, results=results)


def start_snake_peer() -> PeerController:
    results: "queue.Queue[PeerResult]" = queue.Queue()

    def worker() -> None:
        try:
            wait_for_unix_socket(QMP_SOCKET, timeout=10.0)
            time.sleep(1.0)
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
                sock.settimeout(10)
                sock.connect(str(QMP_SOCKET))
                handle = sock.makefile("rwb")
                qmp_read_message(handle)
                qmp_execute(handle, "qmp_capabilities")
                for key in ("d", "d", "s", "s", "a", "q"):
                    qmp_execute(
                        handle,
                        "input-send-event",
                        {
                            "events": [
                                {"type": "key", "data": {"down": True, "key": {"type": "qcode", "data": key}}},
                                {"type": "key", "data": {"down": False, "key": {"type": "qcode", "data": key}}},
                            ]
                        },
                    )
                    time.sleep(0.08)
            results.put(
                PeerResult(
                    notes=(
                        "runner QMP peer injected keyboard `D D S S A Q` to drive the scripted snake path: eat three foods, turn twice, then quit cleanly.",
                    )
                )
            )
        except Exception as exc:
            results.put(PeerResult(notes=(f"runner snake peer error: {exc}",)))

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
    line_index = 0
    char_index = 0
    next_send_at = time.monotonic() + 1.0
    delay_between_chars = 0.01
    delay_between_lines = 0.2
    deadline = time.monotonic() + timeout

    try:
        while time.monotonic() < deadline:
            now = time.monotonic()
            while line_index < len(input_lines) and now >= next_send_at:
                line = input_lines[line_index]
                if line.startswith("__LAB_DELAY__:"):
                    next_send_at = now + float(line.split(":", 1)[1])
                    line_index += 1
                    continue
                payload = line if len(line) == 1 and ord(line) < 0x20 else line + "\r"
                os.write(master_fd, payload[char_index].encode("utf-8"))
                char_index += 1
                if char_index == len(payload):
                    line_index += 1
                    char_index = 0
                    next_send_at = now + delay_between_lines
                else:
                    next_send_at = now + delay_between_chars
                break

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

            if proc.poll() is not None and line_index >= len(input_lines):
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
    if demo.name == "ev":
        return start_input_peer()
    if demo.name == "gui":
        return start_gui_peer()
    if demo.name == "snake":
        return start_snake_peer()
    if demo.name == "ssh-poll":
        return start_shell_peer(SSH_POLL_PORT, "ssh-poll")
    if demo.name == "ssh-select":
        return start_shell_peer(SSH_SELECT_PORT, "ssh-select")
    return None


def x11_install_command() -> str:
    return f"sh -c 'rm -f {X11_APK_LOG_GUEST}; {X11_HELPER_GUEST} install >{X11_APK_LOG_GUEST} 2>&1'"


def x11_server_start_command() -> str:
    return f"{X11_HELPER_GUEST} server"


def x11_client_command() -> str:
    return f"{X11_HELPER_GUEST} client"


def x11_input_command() -> str:
    return f"{X11_HELPER_GUEST} input"


def x11_input_capture_command() -> str:
    return (
        "sh -c '"
        "sleep 1; "
        f"offset=$(cat {X11_INPUT_OFFSET_GUEST} 2>/dev/null || echo 0); "
        f"dd if={X11_INPUT_LOG_GUEST} bs=1 skip=$offset 2>/dev/null || true; "
        f"rm -f {X11_INPUT_PID_GUEST} {X11_INPUT_OFFSET_GUEST}'"
    )


def x11_wait_server_ready_command() -> str:
    return (
        "sh -c '"
        "for i in $(seq 1 40); do "
        f"  [ -S /tmp/.X11-unix/X0 ] && {{ printf \"{X11_SERVER_TOKEN}\\n\"; exit 0; }}; "
        f"  pid=$(cat {X11_SERVER_PID_GUEST} 2>/dev/null || true); "
        "  if [ -n \"$pid\" ] && ! kill -0 \"$pid\" 2>/dev/null; then "
        f"    cat {X11_SERVER_LOG_GUEST} 2>/dev/null || true; "
        "    exit 1; "
        "  fi; "
        "  sleep 0.05; "
        "done; "
        f"cat {X11_SERVER_LOG_GUEST} 2>/dev/null || true; "
        "exit 1'"
    )


def x11_cleanup_command() -> str:
    return f"{X11_HELPER_GUEST} stop"


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
    artifact_dir: pathlib.Path,
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
    if demo.name == "cow":
        mmap_exit = find_syscall_view(event_views, syscall="mmap", label="SysExit")
        protect_enter = find_syscall_view(event_views, syscall="mprotect", label="SysEnter")
        clone_exit = find_syscall_view(event_views, syscall="clone", label="SysExit")
        wait_reap = next((view for view in key_views if view.label == "WaitReap"), None)
        page_faults = [view for view in key_views if view.label == "PageFault"]
        task_exit = next((view for view in task_exits if view.event.arg0 == "0x0"), None)
        helper_parent_tid = wait_reap.event.tid if wait_reap is not None else None
        helper_child_tid = parse_usize(wait_reap.event.arg0) if wait_reap is not None else None
        lines = [
            "the helper mapped two anonymous private pages, touched them, flipped one page read-only and back to writable, then forked to force copy-on-write on the first private page.",
        ]
        if mmap_exit is not None:
            lines.append(f"the anonymous region was created through {mmap_exit.detail}.")
        if protect_enter is not None:
            lines.append(
                "the second page went through mprotect(PROT_READ) and then mprotect(PROT_READ|PROT_WRITE) before the fork."
            )
        if clone_exit is not None and parse_i64(clone_exit.event.arg1) > 0:
            lines.append(
                f"helper task tid={helper_parent_tid or clone_exit.event.tid} forked child tid={helper_child_tid or parse_i64(clone_exit.event.arg1)} so parent and child temporarily shared the first page as a COW mapping."
            )
        if page_faults:
            lines.append(
                f"page-fault activity stayed visible ({len(page_faults)} event(s)), including the child-side write fault that materialized a private copy."
            )
        if wait_reap is not None:
            lines.append(f"the parent validated its original bytes and then completed child collection through {wait_reap.detail}.")
        if "cow-lab" in artifact_outputs.get("demo-step-1.txt", ""):
            lines.append(
                "the helper printed `cow-lab`, which means the parent still saw `parent-page` after the child wrote `child-copy`, so anonymous copy-on-write held end to end."
            )
        if task_exit is not None:
            lines.append(f"the workload closed out cleanly with {task_exit.detail}.")
        return lines
    if demo.name == "filemap":
        helper_reap = next((view for view in key_views if view.label == "WaitReap"), None)
        helper_tid = parse_usize(helper_reap.event.arg0) if helper_reap is not None else None
        helper_views = [view for view in key_views if helper_tid is None or view.event.tid == helper_tid]
        mmap_exits = [
            view for view in helper_views if view.label == "SysExit" and syscall_name(view.event.arg0) == "mmap"
        ]
        shared_fault = next((view for view in helper_views if view.label == "PageFault" and view.event.arg0 == "0x1000"), None)
        private_fault = next((view for view in helper_views if view.label == "PageFault" and view.event.arg0 == "0x1000"), None)
        write_fault = next((view for view in helper_views if view.label == "PageFault" and view.event.arg0 == "0x1005"), None)
        task_exit = next((view for view in helper_views if view.label == "TaskExit"), None)
        lines = [
            "the helper created a two-page file, mapped page 0 as MAP_SHARED and page 1 as MAP_PRIVATE, then checked coherence in both directions.",
        ]
        if len(mmap_exits) >= 2:
            lines.append(
                f"the shared and private mappings were established through {mmap_exits[0].detail} and {mmap_exits[1].detail}."
            )
        if shared_fault is not None:
            lines.append("the initial shared/private touches faulted the mapped file pages into memory through the page cache.")
        if write_fault is not None:
            lines.append("a later write fault on the private mapping stayed visible, which is the per-process MAP_PRIVATE copy path instead of a file-wide shared write.")
        lines.append("writing through the shared mapping was observed back through pread(), and then pwrite() into the file became visible through the still-mapped shared page.")
        lines.append("writing through the private mapping did not change the backing file bytes, so reopening the file still showed `private-base` on page 1.")
        if helper_reap is not None:
            lines.append(f"the shell-side cleanup finished through {helper_reap.detail}.")
        if "filemap-lab" in artifact_outputs.get("demo-step-1.txt", ""):
            lines.append(
                "the helper printed `filemap-lab`, which means shared-map coherence and private-map isolation both held end to end."
            )
        if task_exit is not None:
            lines.append(f"the helper itself exited cleanly with {task_exit.detail}.")
        return lines
    if demo.name == "shm":
        shmat_exit = find_syscall_view(event_views, syscall="shmat", label="SysExit")
        clone_exit = find_syscall_view(event_views, syscall="clone", label="SysExit")
        wait_reap = next((view for view in key_views if view.label == "WaitReap"), None)
        page_faults = [view for view in key_views if view.label == "PageFault"]
        task_exit = next((view for view in task_exits if view.event.arg0 == "0x0"), None)
        helper_parent_tid = wait_reap.event.tid if wait_reap is not None else None
        helper_child_tid = parse_usize(wait_reap.event.arg0) if wait_reap is not None else None
        lines = [
            "the helper created one SysV shared-memory segment, attached it in the parent, forked a child that inherited the attachment, and then exercised child detach plus parent-side IPC_RMID cleanup.",
        ]
        if shmat_exit is not None:
            lines.append(f"the initial attach succeeded through {shmat_exit.detail}.")
        if clone_exit is not None and parse_i64(clone_exit.event.arg1) > 0:
            lines.append(
                f"helper task tid={helper_parent_tid or clone_exit.event.tid} forked child tid={helper_child_tid or parse_i64(clone_exit.event.arg1)}, so the shared segment had to stay visible across process inheritance."
            )
        if page_faults:
            lines.append(
                f"page-fault activity stayed visible ({len(page_faults)} event(s)), showing the shared segment being faulted into both parent and child address spaces."
            )
        lines.append("the child wrote through the inherited shared pointer and detached with shmdt(), then the parent observed the new bytes before issuing IPC_RMID and the final detach.")
        if wait_reap is not None:
            lines.append(f"the parent's wait path completed through {wait_reap.detail}.")
        if "shm-lab" in artifact_outputs.get("demo-step-1.txt", ""):
            lines.append(
                "the helper printed `shm-lab`, which means shared bytes crossed the fork boundary, child-side shmdt succeeded, and the segment stopped being attachable after IPC_RMID plus the last detach."
            )
        if task_exit is not None:
            lines.append(f"the workload closed out cleanly with {task_exit.detail}.")
        return lines
    if demo.name == "fb":
        helper_reap = next((view for view in key_views if view.label == "WaitReap"), None)
        helper_tid = parse_usize(helper_reap.event.arg0) if helper_reap is not None else None
        helper_views = [view for view in key_views if helper_tid is None or view.event.tid == helper_tid]
        fb_ioctls = [view for view in helper_views if view.label == "FbIoctl"]
        fb_map = next((view for view in helper_views if view.label == "FbMap"), None)
        display_flush = next((view for view in helper_views if view.label == "DisplayFlush"), None)
        page_faults = [view for view in helper_views if view.label == "PageFault"]
        task_exit = next((view for view in helper_views if view.label == "TaskExit"), None)
        transcript = artifact_outputs.get("demo-step-1.txt", "")
        lines = [
            "the helper opened `/dev/fb0`, queried both fixed and variable framebuffer metadata, mapped the backing memory, and drew a small teaching scene directly into the framebuffer.",
        ]
        if len(fb_ioctls) >= 2:
            lines.append(
                f"framebuffer metadata flowed through {fb_ioctls[0].detail} and {fb_ioctls[1].detail} before drawing began."
            )
        elif fb_ioctls:
            lines.append(f"framebuffer metadata flowed through {fb_ioctls[0].detail}.")
        if fb_map is not None:
            lines.append(f"pixel memory became writable through {fb_map.detail}.")
        if page_faults:
            lines.append(
                f"the first drawing touches faulted framebuffer pages into the process view ({len(page_faults)} visible page-fault event(s) kept in the teaching trace)."
            )
        if display_flush is not None:
            lines.append("the first framebuffer flush reached the display backend, so the scene was no longer only dirty userspace memory.")
        if "fb-lab" in transcript:
            lines.append(
                "the helper printed `fb-lab ... checksum=...`, which means the color bands, boxed center panel, and simple glyphs were all written through the mapped framebuffer."
            )
        screenshot = artifact_dir / "screen.ppm"
        if screenshot.exists():
            lines.append(f"the runner also captured `{screenshot}` so the teaching artifact includes the actual framebuffer image, not only the checksum.")
        if helper_reap is not None:
            lines.append(f"the shell-side cleanup finished through {helper_reap.detail}.")
        if task_exit is not None:
            lines.append(f"the helper itself exited cleanly with {task_exit.detail}.")
        return lines
    if demo.name == "ev":
        helper_reap = next((view for view in key_views if view.label == "WaitReap"), None)
        helper_tid = parse_usize(helper_reap.event.arg0) if helper_reap is not None else None
        helper_views = [view for view in key_views if helper_tid is None or view.event.tid == helper_tid]
        input_opens = [view for view in helper_views if view.label == "InputOpen"]
        input_reads = [view for view in helper_views if view.label == "InputRead"]
        input_wakes = [view for view in helper_views if view.label == "InputPollWake"]
        ioctl_exits = [view for view in helper_views if view.label == "SysExit" and syscall_name(view.event.arg0) == "ioctl"]
        poll_events = [view for view in helper_views if view.label in {"PollSleep", "PollWake"}]
        task_exit = next((view for view in helper_views if view.label == "TaskExit"), None)
        transcript = artifact_outputs.get("demo-step-1.txt", "")
        lines = [
            "the helper opened the keyboard and mouse evdev nodes, queried their metadata, then blocked in poll() until the runner injected deterministic keyboard and mouse activity through QEMU.",
        ]
        if len(input_opens) >= 2:
            lines.append(f"the input nodes opened successfully through {input_opens[0].detail} and {input_opens[1].detail}.")
        if ioctl_exits:
            lines.append(
                f"device metadata flowed through {len(ioctl_exits)} successful ioctl call(s) before the event loop started."
            )
        if input_wakes:
            lines.append(f"readiness first surfaced as {', '.join(view.detail for view in input_wakes[:2])}.")
        if poll_events:
            lines.append(
                f"the helper's poll path slept {sum(1 for view in poll_events if view.label == 'PollSleep')} time(s) and woke {sum(1 for view in poll_events if view.label == 'PollWake')} time(s) as events arrived."
            )
        if input_reads:
            lines.append(f"event delivery then showed up as {', '.join(view.detail for view in input_reads[:3])}.")
        if "ev-lab" in transcript:
            lines.append(
                "the helper printed `ev-lab ...`, confirming that EV_KEY for keyboard input and EV_REL plus button activity for the mouse were both observed from userspace."
            )
        lines.extend(peer_notes)
        if helper_reap is not None:
            lines.append(f"the shell-side cleanup finished through {helper_reap.detail}.")
        if task_exit is not None:
            lines.append(f"the helper itself exited cleanly with {task_exit.detail}.")
        return lines
    if demo.name == "gui":
        helper_reap = next((view for view in key_views if view.label == "WaitReap"), None)
        helper_tid = parse_usize(helper_reap.event.arg0) if helper_reap is not None else None
        helper_views = [view for view in key_views if helper_tid is None or view.event.tid == helper_tid]
        input_opens = [view for view in helper_views if view.label == "InputOpen"]
        input_reads = [view for view in helper_views if view.label == "InputRead"]
        input_wakes = [view for view in helper_views if view.label == "InputPollWake"]
        fb_ioctls = [view for view in helper_views if view.label == "FbIoctl"]
        fb_map = next((view for view in helper_views if view.label == "FbMap"), None)
        display_flush = next((view for view in helper_views if view.label == "DisplayFlush"), None)
        poll_events = [view for view in helper_views if view.label in {"PollSleep", "PollWake"}]
        page_faults = [view for view in helper_views if view.label == "PageFault"]
        task_exit = next((view for view in helper_views if view.label == "TaskExit"), None)
        transcript = artifact_outputs.get("demo-step-1.txt", "")
        lines = [
            "the helper opened `/dev/fb0` plus the keyboard and mouse evdev nodes, mapped the framebuffer, and then redrew a tiny full-screen scene while consuming injected input.",
        ]
        if fb_ioctls:
            lines.append(f"framebuffer metadata flowed through {', '.join(view.detail for view in fb_ioctls[:2])}.")
        if fb_map is not None:
            lines.append(f"the framebuffer became writable through {fb_map.detail}.")
        if len(input_opens) >= 2:
            lines.append(f"the input side opened {input_opens[0].detail} and {input_opens[1].detail}.")
        if page_faults:
            lines.append(
                f"the first redraws faulted framebuffer-backed pages into userspace ({len(page_faults)} visible page-fault event(s) kept in the teaching trace)."
            )
        if display_flush is not None:
            lines.append("the display backend flush became visible, so the drawn scene was actually scanned out.")
        if input_wakes:
            lines.append(f"input readiness surfaced as {', '.join(view.detail for view in input_wakes[:2])}.")
        if poll_events:
            lines.append(
                f"the combined input loop slept {sum(1 for view in poll_events if view.label == 'PollSleep')} time(s) and woke {sum(1 for view in poll_events if view.label == 'PollWake')} time(s) while waiting for keyboard and mouse events."
            )
        if input_reads:
            lines.append(f"input delivery then showed up as {', '.join(view.detail for view in input_reads[:3])}.")
        if "gui-lab" in transcript:
            lines.append(
                "the helper printed `gui-lab ...`, which means the box moved via keyboard input, the cursor moved via relative mouse input, and the left-button click flipped the box color before the final checksum was computed."
            )
        screenshot = artifact_dir / "screen.ppm"
        if screenshot.exists():
            lines.append(f"the runner also captured `{screenshot}` so the final interactive scene is saved alongside the trace.")
        lines.extend(peer_notes)
        if helper_reap is not None:
            lines.append(f"the shell-side cleanup finished through {helper_reap.detail}.")
        if task_exit is not None:
            lines.append(f"the helper itself exited cleanly with {task_exit.detail}.")
        return lines
    if demo.name == "snake":
        helper_reap = next((view for view in key_views if view.label == "WaitReap"), None)
        helper_tid = parse_usize(helper_reap.event.arg0) if helper_reap is not None else None
        helper_views = [view for view in key_views if helper_tid is None or view.event.tid == helper_tid]
        input_opens = [view for view in helper_views if view.label == "InputOpen"]
        input_reads = [view for view in helper_views if view.label == "InputRead"]
        input_wakes = [view for view in helper_views if view.label == "InputPollWake"]
        fb_ioctls = [view for view in helper_views if view.label == "FbIoctl"]
        fb_map = next((view for view in helper_views if view.label == "FbMap"), None)
        display_flush = next((view for view in helper_views if view.label == "DisplayFlush"), None)
        poll_events = [view for view in helper_views if view.label in {"PollSleep", "PollWake"}]
        page_faults = [view for view in helper_views if view.label == "PageFault"]
        task_exit = next((view for view in helper_views if view.label == "TaskExit"), None)
        transcript = artifact_outputs.get("demo-step-1.txt", "")
        lines = [
            "the helper opened `/dev/fb0` plus the keyboard evdev node, mapped the framebuffer, and ran a small snake game directly on fbdev + evdev without any window system.",
        ]
        if fb_ioctls:
            lines.append(f"framebuffer metadata flowed through {', '.join(view.detail for view in fb_ioctls[:2])} before the game loop started.")
        if fb_map is not None:
            lines.append(f"the framebuffer became writable through {fb_map.detail}.")
        if input_opens:
            lines.append(f"keyboard input opened through {input_opens[0].detail}.")
        if page_faults:
            lines.append(
                f"the first redraws faulted framebuffer-backed pages into userspace ({len(page_faults)} visible page-fault event(s) kept in the teaching trace)."
            )
        if display_flush is not None:
            lines.append("the display backend flush became visible, so the snake board was actually scanned out rather than only updated in the mapping.")
        if input_wakes:
            lines.append(f"keyboard readiness surfaced as {', '.join(view.detail for view in input_wakes[:2])}.")
        if poll_events:
            lines.append(
                f"the input loop slept {sum(1 for view in poll_events if view.label == 'PollSleep')} time(s) and woke {sum(1 for view in poll_events if view.label == 'PollWake')} time(s) while waiting for keyboard turns."
            )
        if input_reads:
            lines.append(f"keyboard delivery then showed up as {', '.join(view.detail for view in input_reads[:3])}.")
        if "snake-lab" in transcript:
            lines.append(
                "the helper printed `snake-lab ...`, which means the scripted run ate food, changed direction through evdev key input, rendered the updated board through fbdev, and quit cleanly with a deterministic final checksum."
            )
        screenshot = artifact_dir / "screen.ppm"
        if screenshot.exists():
            lines.append(f"the runner also captured `{screenshot}` so the final snake frame is saved alongside the trace.")
        lines.extend(peer_notes)
        if helper_reap is not None:
            lines.append(f"the shell-side cleanup finished through {helper_reap.detail}.")
        if task_exit is not None:
            lines.append(f"the helper itself exited cleanly with {task_exit.detail}.")
        return lines
    if demo.name == "x11":
        if phase_results:
            phase_map = {phase.name: phase for phase in phase_results}
            fb_phase = phase_map.get("phase-1-fb")
            input_phase = phase_map.get("phase-2-input")
            x11_phase = phase_map.get("phase-3-x11")
            xinput_phase = phase_map.get("phase-4-xinput")
            lines = [
                "the X11-lite demo is split into focused phases so the graphics stack stays teachable end to end: raw framebuffer first, raw evdev second, the first teaching calculator client third, and X-side mouse delivery last.",
            ]
            if fb_phase is not None:
                lines.append("phase 1 isolated raw framebuffer bring-up on `/dev/fb0` before X11 entered the picture.")
                lines.extend(f"(phase 1) {line}" for line in fb_phase.walkthrough[:4])
            if input_phase is not None:
                lines.append("phase 2 isolated raw evdev input on `/dev/input/*` before X11 entered the picture.")
                lines.extend(f"(phase 2) {line}" for line in input_phase.walkthrough[:4])
            if x11_phase is not None:
                lines.append("phase 3 isolated the first Starry Lab X11 client, the teaching calculator, after the lower graphics layers were already proven independently.")
                lines.extend(f"(phase 3) {line}" for line in x11_phase.walkthrough[:4])
                screenshot = x11_phase.out_dir / "screen.ppm"
                if screenshot.exists():
                    lines.append(f"the runner also captured one framebuffer screenshot at `{screenshot}` as proof that the X client actually drew on screen.")
            if xinput_phase is not None:
                lines.append("phase 4 kept the graphical session alive and proved that mouse motion/button events reached the teaching calculator client.")
                lines.extend(f"(phase 4) {line}" for line in xinput_phase.walkthrough[:4])
            transcript = artifact_outputs.get("demo-step-1.txt", "")
            if X11_CLIENT_TOKEN in transcript:
                lines.append(
                    "the combined transcript printed `x11-lab`, so the X server stayed up and the first GUI client remained alive long enough to draw."
                )
            if X11_INPUT_TOKEN in transcript:
                lines.append(
                    "the combined transcript also printed `x11-input-lab`, so the follow-up X-side probe stayed alive while injected mouse events reached the visible X client."
                )
            lines.extend(peer_notes)
            return lines
        return [
            "the X11-lite demo brings up `X -retro` over fbdev+evdev, then launches the Starry Lab teaching calculator as the first client.",
        ]
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
        if phase_results:
            phase_map = {phase.name: phase for phase in phase_results}
            stop_phase = phase_map.get("phase-1-stop")
            continue_phase = phase_map.get("phase-2-continue")
            reap_phase = phase_map.get("phase-3-reap")
            lines = [
                "the helper is split into three focused wait4 phases so stopped, continued, and reaped states each stay visible without getting buried under unrelated trace noise.",
            ]
            if stop_phase is not None:
                lines.append("phase 1 isolates the WUNTRACED stop report.")
                lines.extend(f"(phase 1) {line}" for line in stop_phase.walkthrough[:3])
            if continue_phase is not None:
                lines.append("phase 2 isolates the WCONTINUED resume report.")
                lines.extend(f"(phase 2) {line}" for line in continue_phase.walkthrough[:3])
            if reap_phase is not None:
                lines.append("phase 3 isolates the final reap path after SIGINT.")
                lines.extend(f"(phase 3) {line}" for line in reap_phase.walkthrough[:3])
            transcript = artifact_outputs.get("demo-step-1.txt", "")
            if WAITCTL_STOP_TOKEN in transcript and WAITCTL_CONTINUE_TOKEN in transcript and WAITCTL_REAP_TOKEN in transcript:
                lines.append(
                    "the combined transcript printed `waitctl-stop-lab`, `waitctl-continue-lab`, and `waitctl-reap-lab`, so all three wait-status phases completed end to end."
                )
            return lines
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
        if (
            WAITCTL_STOP_TOKEN in artifact_outputs.get("demo-step-1.txt", "")
            and WAITCTL_CONTINUE_TOKEN in artifact_outputs.get("demo-step-1.txt", "")
            and WAITCTL_REAP_TOKEN in artifact_outputs.get("demo-step-1.txt", "")
        ):
            lines.append(
                "the helper printed `waitctl-stop-lab`, `waitctl-continue-lab`, and `waitctl-reap-lab`, so all three wait-status phases completed end to end."
            )
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
        jobctl_phase = phase_map.get("phase-4-jobctl")
        sigttou_phase = phase_map.get("phase-5a-sigttou")
        sigttin_phase = phase_map.get("phase-5b-sigttin")
        lines: list[str] = [
            f"the guest ran a real Dropbear SSH server on port {SSHD_PORT}, and the host OpenSSH client logged in over QEMU user-net forwarding through focused trace windows for connect, pty bootstrap, shell wait semantics, interactive job control, and background tty stop signals.",
        ]
        if connect_phase is not None:
            lines.append("phase 1 isolated socket accept/authentication, so the network half of SSH is visible without later pty noise.")
        if pty_phase is not None:
            lines.append("phase 2 isolated pty/session/job-control bootstrap, so the shell login path reads like a standalone terminal bring-up.")
            lines.extend(f"(phase 2) {line}" for line in pty_phase.walkthrough[:3])
        if shell_phase is not None:
            lines.append("phase 3 isolated the interactive shell workload, including the background child, SIGCHLD, wait4, and session teardown.")
            lines.extend(f"(phase 3) {line}" for line in shell_phase.walkthrough[:4])
        if jobctl_phase is not None:
            lines.append("phase 4 isolated real remote job control, including Ctrl-Z, `fg`, Ctrl-C, and the shell's stop/reap handling.")
            lines.extend(f"(phase 4) {line}" for line in jobctl_phase.walkthrough[:5])
        if sigttou_phase is not None:
            lines.append("phase 5 isolated background tty output over SSH, focusing on SIGTTOU for a background writer with `TOSTOP` set.")
            lines.extend(f"(phase 5a) {line}" for line in sigttou_phase.walkthrough[:5])
        if sigttin_phase is not None:
            lines.append("phase 6 isolated background tty input over SSH, focusing on SIGTTIN for a background reader.")
            lines.extend(f"(phase 5b) {line}" for line in sigttin_phase.walkthrough[:5])
        if transcript:
            lines.append(
                "the real SSH transcripts printed `sshd-lab`, `sshd-jobctl-lab`, `sshd-sigttou-lab`, and `sshd-sigttin-lab`, which confirms the path guest sshd -> pty -> shell -> pty -> encrypted socket -> host ssh client end to end for ordinary commands, job-control keystrokes, and both background tty-stop cases."
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
    walkthrough = build_walkthrough(demo, event_views, key_views, artifact_dir, artifact_outputs, peer_notes, phase_results)
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
        f"- graphic: {demo.graphic}",
        f"- input: {demo.input}",
        f"- headless_graphic: {'y' if demo.graphic == 'y' else 'n'}",
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
        lines.append(f"{demo.name} phases:")
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
    parser.add_argument("--stage-only", action="store_true")
    return parser.parse_args()

def execute_run(
    demo: Demo,
    arch: str,
    out_dir: pathlib.Path,
    boot_timeout: float,
    command_timeout: float,
    raw: bool,
) -> RunResult:
    if demo.name == "x11":
        base_img = prepare_x11_base(arch, boot_timeout, command_timeout)
    else:
        base_img = ensure_working_disk(arch)
    run_disk = create_lab_disk(base_img, demo)
    ensure_guest_helpers(demo, arch, run_disk)
    proc = spawn_qemu(
        arch,
        demo.net,
        demo.graphic,
        demo.input,
        run_disk,
        hostfwd="y" if demo.name == "sshd" else "n",
    )
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
        if demo.name == "waitctl":
            waitctl_phase_specs = (
                ("phase-1-stop", "wait4 WUNTRACED stop", f"{WAITCTL_HELPER_GUEST} stop"),
                ("phase-2-continue", "wait4 WCONTINUED continue", f"{WAITCTL_HELPER_GUEST} continue"),
                ("phase-3-reap", "wait4 terminal reap", f"{WAITCTL_HELPER_GUEST} reap"),
            )
            phase_results_list: list[PhaseResult] = []
            phase_transcripts: list[str] = []
            for phase_name, phase_title, phase_command in waitctl_phase_specs:
                reset_command = "echo 1 > /proc/starry/reset"
                off_command = "echo 1 > /proc/starry/off"
                input_stream.append(f"{reset_command} [{phase_name}]")
                session.run_command(reset_command, command_timeout)
                input_stream.append(f"{phase_command} [{phase_name}]")
                transcript = clean_capture(session.run_command(phase_command, command_timeout), phase_command)
                phase_transcripts.append(transcript)
                input_stream.append(f"{off_command} [{phase_name}]")
                session.run_command(off_command, command_timeout)
                phase_outputs = collect_trace_artifacts(session, command_timeout)
                phase_events = parse_trace(phase_outputs["starry_trace.txt"])
                phase_results_list.append(
                    render_waitctl_phase_artifacts(
                        out_dir / phase_name,
                        phase_name,
                        phase_title,
                        phase_events,
                        phase_outputs["starry_stats.txt"],
                        phase_outputs["starry_last_fault.txt"],
                        (phase_command,),
                        transcript,
                        raw,
                    )
                )
            phase_results = tuple(phase_results_list)
            cleaned_output = normalize_demo_output(demo, "\n".join(t for t in phase_transcripts if t))
            step_path = out_dir / "demo-step-1.txt"
            write_text(step_path, cleaned_output)
            demo_outputs.append((step_path, cleaned_output))
        elif demo.name == "x11":
            phase_results_list: list[PhaseResult] = []
            x11_peer_notes: list[str] = []
            try:
                phase_reset = "echo 1 > /proc/starry/reset"
                phase_off = "echo 1 > /proc/starry/off"
                server_start = x11_server_start_command()
                wait_ready = x11_wait_server_ready_command()
                cleanup_command = x11_cleanup_command()

                # Phase 1: isolate raw framebuffer bring-up before X.
                input_stream.append(f"{phase_reset} [phase-1-fb]")
                session.run_command(phase_reset, command_timeout)
                phase1_command = FBDRAW_HELPER_GUEST
                input_stream.append(f"{phase1_command} [phase-1-fb]")
                phase1_transcript = clean_capture(
                    session.run_command(phase1_command, max(command_timeout, 60.0)),
                    phase1_command,
                )
                phase1_screenshot = out_dir / "phase-1-fb" / "screen.ppm"
                phase1_screenshot.parent.mkdir(parents=True, exist_ok=True)
                qmp_screendump(phase1_screenshot)
                phase1_notes = (
                    f"the runner captured one QMP screendump at `{phase1_screenshot}` after the raw framebuffer helper finished drawing.",
                )
                x11_peer_notes.append(f"phase-1-fb: {phase1_notes[0]}")
                input_stream.append(f"{phase_off} [phase-1-fb]")
                session.run_command(phase_off, command_timeout)
                phase1_outputs = collect_trace_artifacts(session, command_timeout)
                phase1_events = parse_trace(phase1_outputs["starry_trace.txt"])
                phase_results_list.append(
                    render_x11_phase_artifacts(
                        out_dir / "phase-1-fb",
                        "phase-1-fb",
                        "Raw framebuffer on /dev/fb0",
                        phase1_events,
                        phase1_outputs["starry_stats.txt"],
                        phase1_outputs["starry_last_fault.txt"],
                        (phase1_command,),
                        phase1_transcript,
                        phase1_notes,
                        raw,
                    )
                )

                # Phase 2: isolate raw evdev open/poll/read before X.
                input_stream.append(f"{phase_reset} [phase-2-input]")
                session.run_command(phase_reset, command_timeout)
                phase2_command = EVWATCH_HELPER_GUEST
                phase2_peer = start_input_peer()
                input_stream.append(f"{phase2_command} [phase-2-input]")
                phase2_transcript = clean_capture(
                    session.run_command(phase2_command, max(command_timeout, 60.0)),
                    phase2_command,
                )
                phase2_peer_result = phase2_peer.finish(max(command_timeout, 20.0))
                phase2_notes = phase2_peer_result.notes
                input_stream.append("HOST:QMP inject deterministic raw input [phase-2-input]")
                input_stream.append(f"{phase_off} [phase-2-input]")
                session.run_command(phase_off, command_timeout)
                phase2_outputs = collect_trace_artifacts(session, command_timeout)
                phase2_events = parse_trace(phase2_outputs["starry_trace.txt"])
                phase_results_list.append(
                    render_x11_phase_artifacts(
                        out_dir / "phase-2-input",
                        "phase-2-input",
                        "Raw input on /dev/input/*",
                        phase2_events,
                        phase2_outputs["starry_stats.txt"],
                        phase2_outputs["starry_last_fault.txt"],
                        (phase2_command, "HOST:QMP inject deterministic raw input"),
                        phase2_transcript,
                        phase2_notes,
                        raw,
                    )
                )
                x11_peer_notes.extend(f"phase-2-input: {note}" for note in phase2_notes)

                # Phase 3: bring X up after the raw layers are already proven, then isolate the first client.
                install_command = x11_install_command()
                input_stream.append(f"{install_command} [phase-3-x11 prep]")
                session.run_command(install_command, max(command_timeout, 120.0))
                input_stream.append(f"{server_start} [phase-3-x11 prep]")
                session.run_command(server_start, max(command_timeout, 60.0))
                input_stream.append(f"{wait_ready} [phase-3-x11 prep]")
                session.run_command(wait_ready, max(command_timeout, 60.0))
                server_screenshot_path = out_dir / "phase-3-x11" / "server.ppm"
                server_screenshot_path.parent.mkdir(parents=True, exist_ok=True)
                qmp_screendump(server_screenshot_path)
                input_stream.append(f"{phase_reset} [phase-3-x11]")
                session.run_command(phase_reset, command_timeout)
                client_command = x11_client_command()
                input_stream.append(f"{client_command} [phase-3-x11]")
                phase3_transcript = clean_capture(
                    session.run_command(client_command, max(command_timeout, 60.0)),
                    client_command,
                )
                if X11_CLIENT_TOKEN not in phase3_transcript:
                    raise RuntimeError("x11 client helper did not report a mapped teaching calculator window")
                screenshot_path = out_dir / "phase-3-x11" / "screen.ppm"
                screenshot_path.parent.mkdir(parents=True, exist_ok=True)
                qmp_screendump(screenshot_path)
                server_hash = digest_file(server_screenshot_path)
                client_hash = digest_file(screenshot_path)
                if client_hash == server_hash:
                    raise RuntimeError(
                        "x11 client did not change the framebuffer; the teaching calculator was still not visibly mapped"
                    )
                phase3_notes = (
                    f"the runner captured `{server_screenshot_path}` before launching the client and `{screenshot_path}` after it started; the framebuffer hash changed from `{server_hash}` to `{client_hash}`, so the X client really drew on screen.",
                )
                x11_peer_notes.append(f"phase-3-x11: {phase3_notes[0]}")
                input_stream.append(f"{phase_off} [phase-3-x11]")
                session.run_command(phase_off, command_timeout)
                phase3_outputs = collect_trace_artifacts(session, command_timeout)
                phase3_events = parse_trace(phase3_outputs["starry_trace.txt"])
                phase_results_list.append(
                    render_x11_phase_artifacts(
                        out_dir / "phase-3-x11",
                        "phase-3-x11",
                        "First X11 client (teaching calculator)",
                        phase3_events,
                        phase3_outputs["starry_stats.txt"],
                        phase3_outputs["starry_last_fault.txt"],
                        (client_command,),
                        phase3_transcript,
                        phase3_notes,
                        raw,
                    )
                )

                # Phase 4: keep X alive and prove mouse input reaches the teaching calculator client.
                input_probe_command = x11_input_command()
                input_stream.append(f"{input_probe_command} [phase-4-xinput prep]")
                phase4_probe_transcript = clean_capture(
                    session.run_command(input_probe_command, max(command_timeout, 30.0)),
                    input_probe_command,
                )
                if X11_INPUT_TOKEN not in phase4_probe_transcript:
                    raise RuntimeError("x11 input helper did not report a live visible-client probe")
                input_stream.append(f"{phase_reset} [phase-4-xinput]")
                session.run_command(phase_reset, command_timeout)
                phase4_note = inject_x11_input_sequence()
                input_stream.append("HOST:QMP inject deterministic X mouse input [phase-4-xinput]")
                capture_command = x11_input_capture_command()
                input_stream.append(f"{capture_command} [phase-4-xinput]")
                phase4_transcript = clean_capture(
                    session.run_command(capture_command, max(command_timeout, 30.0)),
                    capture_command,
                )
                if "MotionNotify" not in phase4_transcript or "ButtonPress" not in phase4_transcript:
                    raise RuntimeError("x11 input probe did not observe mouse motion/button events inside the visible teaching calculator window")
                phase4_notes = (phase4_note,)
                x11_peer_notes.append(f"phase-4-xinput: {phase4_notes[0]}")
                input_stream.append(f"{phase_off} [phase-4-xinput]")
                session.run_command(phase_off, command_timeout)
                phase4_outputs = collect_trace_artifacts(session, command_timeout)
                phase4_events = parse_trace(phase4_outputs["starry_trace.txt"])
                phase_results_list.append(
                    render_x11_phase_artifacts(
                        out_dir / "phase-4-xinput",
                        "phase-4-xinput",
                        "Mouse delivery inside X11",
                        phase4_events,
                        phase4_outputs["starry_stats.txt"],
                        phase4_outputs["starry_last_fault.txt"],
                        ("HOST:QMP inject deterministic X mouse input", capture_command),
                        phase4_transcript,
                        phase4_notes,
                        raw,
                    )
                )
                input_stream.append(f"{cleanup_command} [phase-4-xinput]")
                session.run_command(cleanup_command, command_timeout)
            except Exception as exc:
                apk_log = clean_capture(
                    session.run_command(f"cat {X11_APK_LOG_GUEST} 2>/dev/null || true", command_timeout),
                    f"cat {X11_APK_LOG_GUEST} 2>/dev/null || true",
                )
                x_log = clean_capture(
                    session.run_command(f"cat {X11_SERVER_LOG_GUEST} 2>/dev/null || true", command_timeout),
                    f"cat {X11_SERVER_LOG_GUEST} 2>/dev/null || true",
                )
                xcalc_log = clean_capture(
                    session.run_command(f"cat {X11_CLIENT_LOG_GUEST} 2>/dev/null || true", command_timeout),
                    f"cat {X11_CLIENT_LOG_GUEST} 2>/dev/null || true",
                )
                raise RuntimeError(
                    f"{exc}\napk log:\n{apk_log}\nX log:\n{x_log}\nxcalc log:\n{xcalc_log}"
                ) from exc
            finally:
                input_stream.append(cleanup_command)
                session.run_command(cleanup_command, command_timeout)
            phase_results = tuple(phase_results_list)
            peer_notes = tuple(x11_peer_notes)
            cleaned_output = "\n".join(
                token
                for token in (phase3_transcript, phase4_transcript)
                if token.strip()
            )
            step_path = out_dir / "demo-step-1.txt"
            write_text(step_path, cleaned_output)
            demo_outputs.append((step_path, cleaned_output))
        elif demo.name == "sshd":
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
                (
                    "phase-4-jobctl",
                    "SSH interactive job control",
                    ("echo 1 > /proc/starry/reset",),
                    f"HOST:ssh -tt -p {SSHD_PORT} -i {private_key} root@127.0.0.1 [phase-4]",
                    "echo 1 > /proc/starry/off",
                    lambda: run_host_ssh_demo(
                        private_key,
                        command_timeout,
                        SSHD_PHASE4_LINES,
                        SSHD_PHASE4_TOKEN,
                    ),
                ),
                (
                    "phase-5a-sigttou",
                    "SSH background tty output stop (SIGTTOU)",
                    ("echo 1 > /proc/starry/reset",),
                    f"HOST:ssh -tt -p {SSHD_PORT} -i {private_key} root@127.0.0.1 [phase-5a]",
                    "echo 1 > /proc/starry/off",
                    lambda: run_host_ssh_demo(
                        private_key,
                        command_timeout,
                        SSHD_PHASE5A_LINES,
                        SSHD_PHASE5A_TOKEN,
                    ),
                ),
                (
                    "phase-5b-sigttin",
                    "SSH background tty input stop (SIGTTIN)",
                    ("echo 1 > /proc/starry/reset",),
                    f"HOST:ssh -tt -p {SSHD_PORT} -i {private_key} root@127.0.0.1 [phase-5b]",
                    "echo 1 > /proc/starry/off",
                    lambda: run_host_ssh_demo(
                        private_key,
                        command_timeout,
                        SSHD_PHASE5B_LINES,
                        SSHD_PHASE5B_TOKEN,
                    ),
                ),
            )
            phase_results_list: list[PhaseResult] = []
            ssh_peer_notes: list[str] = []
            phase3_peer_result: PeerResult | None = None
            phase4_peer_result: PeerResult | None = None
            phase5a_peer_result: PeerResult | None = None
            phase5b_peer_result: PeerResult | None = None
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
                    if phase_name == "phase-4-jobctl":
                        phase4_peer_result = phase_peer_result
                    if phase_name == "phase-5a-sigttou":
                        phase5a_peer_result = phase_peer_result
                    if phase_name == "phase-5b-sigttin":
                        phase5b_peer_result = phase_peer_result
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
                "\n".join(
                    transcript
                    for transcript in (
                        None if phase3_peer_result is None else phase3_peer_result.transcript,
                        None if phase4_peer_result is None else phase4_peer_result.transcript,
                        None if phase5a_peer_result is None else phase5a_peer_result.transcript,
                        None if phase5b_peer_result is None else phase5b_peer_result.transcript,
                    )
                    if transcript
                ),
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
            peer_note_list = list(peer_result.notes)
            if demo.name in {"fb", "gui", "snake"}:
                screenshot_path = out_dir / "screen.ppm"
                qmp_screendump(screenshot_path)
                peer_note_list.append(f"the runner captured one QMP screendump at `{screenshot_path}` after the helper finished drawing.")
            peer_notes = tuple(peer_note_list)
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
        if phase_results:
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
            if demo.name == "sshd":
                key_views = render_sshd_key_trace(out_dir / "key_trace.txt", phase_results)
            elif demo.name == "x11":
                key_views = render_x11_key_trace(out_dir / "key_trace.txt", phase_results)
            else:
                key_views = []
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
        if raw and demo.name == "x11":
            for filename, guest_path in (
                ("lab_x11_apk.log", X11_APK_LOG_GUEST),
                ("lab_x11.log", X11_SERVER_LOG_GUEST),
                ("lab_xcalc.log", X11_CLIENT_LOG_GUEST),
                ("lab_xev.log", X11_INPUT_LOG_GUEST),
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
        run_disk.unlink(missing_ok=True)


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
        f"- graphic: {demo.graphic}",
        f"- input: {demo.input}",
        f"- headless_graphic: {'y' if demo.graphic == 'y' else 'n'}",
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
    if args.stage_only and args.repeat != 1:
        raise SystemExit("--stage-only cannot be combined with --repeat")

    if not args.skip_build:
        run_build(args.arch)

    if args.stage_only:
        if demo.name == "x11":
            print(prepare_x11_base(args.arch, args.boot_timeout, args.command_timeout).resolve())
            return 0
        base_img = ensure_working_disk(args.arch)
        ensure_guest_helpers(demo, args.arch, base_img)
        print(base_img.resolve())
        return 0

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
