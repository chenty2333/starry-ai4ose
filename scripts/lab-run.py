#!/usr/bin/env python3

import argparse
import collections
import datetime as dt
import errno
import hashlib
import pathlib
import re
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


@dataclass(frozen=True)
class Demo:
    name: str
    goal: str
    commands: tuple[str, ...]
    expected_events: tuple[str, ...]
    focus_events: tuple[str, ...]
    focus_page_fault_arg0: str | None = None
    focus_signal_arg0: str | None = None


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


DEMOS: dict[str, Demo] = {
    "pipe": Demo(
        name="pipe",
        goal="Show how a tiny shell pipeline drives fork/exec, pipe usage, and wakeups.",
        commands=("echo hi | cat",),
        expected_events=("SysEnter", "SysExit", "FdOpen", "FdClose", "PollSleep", "PollWake"),
        focus_events=("FdOpen", "FdClose", "PollSleep", "PollWake", "TaskExit"),
        focus_page_fault_arg0=None,
        focus_signal_arg0=None,
    ),
    "wait": Demo(
        name="wait",
        goal="Show child execution, blocking, and wait-based completion.",
        commands=("sleep 1 & wait",),
        expected_events=("SysEnter", "SysExit", "TaskExit", "PollSleep", "PollWake"),
        focus_events=("PollSleep", "PollWake", "TaskExit", "SignalSend", "SignalHandle"),
        focus_page_fault_arg0=None,
        focus_signal_arg0=None,
    ),
    "fd": Demo(
        name="fd",
        goal="Show the current process fd view and the Starry Lab fd snapshot side by side.",
        commands=("ls -l /proc/self/fd", "cat /proc/starry/fd"),
        expected_events=("SysEnter", "SysExit", "FdOpen", "FdClose"),
        focus_events=("FdOpen", "FdClose"),
        focus_page_fault_arg0=None,
        focus_signal_arg0=None,
    ),
    "fault": Demo(
        name="fault",
        goal="Show a deliberate fault path through page-fault recording, SIGSEGV delivery, and task exit.",
        commands=("sh -c 'echo 1 > /proc/starry/fault_demo' || true",),
        expected_events=("PageFault", "SignalSend", "SignalHandle", "TaskExit"),
        focus_events=("PageFault", "SignalSend", "SignalHandle", "TaskExit"),
        focus_page_fault_arg0="0xdeadbeef",
        focus_signal_arg0="0xb",
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
        wrapped = f"{command}; printf '\\n{marker} %s\\n' $? \n"
        start = len(self.log)
        self.sock.sendall(wrapped.encode("utf-8"))
        self.recv_until(marker, timeout, start)
        self.wait_for_prompt(timeout, start)
        return self.log[start:]


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


def run_build(arch: str) -> None:
    subprocess.run(
        ["make", f"ARCH={arch}", f"APP_FEATURES={BASELINE_APP_FEATURES}", "build"],
        check=True,
    )


def spawn_qemu(arch: str) -> subprocess.Popen[str]:
    return subprocess.Popen(
        [
            "make",
            f"ARCH={arch}",
            f"APP_FEATURES={BASELINE_APP_FEATURES}",
            f"NET={BASELINE_NET}",
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


def clean_capture(text: str) -> str:
    text = ANSI_RE.sub("", text).replace("\r", "")
    lines = text.splitlines()
    cleaned: list[str] = []
    for index, line in enumerate(lines):
        if index == 0 and "; printf " in line:
            continue
        if "__LAB_DONE__" in line:
            continue
        if line.strip() == PROMPT:
            continue
        if line.strip() == "$?":
            continue
        cleaned.append(line)

    while cleaned and not cleaned[0].strip():
        cleaned.pop(0)
    while cleaned and not cleaned[-1].strip():
        cleaned.pop()
    return "\n".join(cleaned) + ("\n" if cleaned else "")


def parse_trace(text: str) -> list[TraceEvent]:
    events: list[TraceEvent] = []
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    if not lines:
        return events
    for line in lines[1:]:
        parts = line.split("\t")
        if len(parts) != 6:
            continue
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
    keep = {event.seq for event in selected}
    return [view for view in views if view.event.seq in keep]


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


def build_walkthrough(demo: Demo, key_views: list[EventView], artifact_outputs: dict[str, str]) -> list[str]:
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
        lines = [
            f"the wait path blocked {counts['PollSleep']} time(s) before wakeup {counts['PollWake']} time(s).",
        ]
        if task_exits:
            exits = ", ".join(view.detail for view in task_exits[:3])
            lines.append(f"task exit observation(s): {exits}.")
        if signal_events:
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
    return [view.detail for view in key_views[:5]]


def create_summary(
    path: pathlib.Path,
    demo: Demo,
    artifact_dir: pathlib.Path,
    events: list[TraceEvent],
    key_views: list[EventView],
    stats_text: str,
    last_fault_text: str,
    input_stream: tuple[str, ...],
    artifact_outputs: dict[str, str],
) -> None:
    counts = collections.Counter(event.kind for event in events)
    present = [kind for kind in demo.expected_events if counts[kind] > 0]
    missing = [kind for kind in demo.expected_events if counts[kind] == 0]
    stats = parse_tab_values(stats_text)
    walkthrough = build_walkthrough(demo, key_views, artifact_outputs)
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
        f"- net: {BASELINE_NET}",
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
    proc = spawn_qemu(arch)
    try:
        wait_for_qemu_start(proc, boot_timeout)
        sock = socket.create_connection(("localhost", SERIAL_PORT), timeout=boot_timeout)
        session = Session(sock)
        session.wait_for_prompt(boot_timeout)
        input_stream = ["echo 1 > /proc/starry/reset"]
        session.run_command(input_stream[0], command_timeout)

        for index, command in enumerate(demo.commands, start=1):
            input_stream.append(command)
            output = session.run_command(command, command_timeout)
            write_text(out_dir / f"demo-step-{index}.txt", clean_capture(output))

        input_stream.append("echo 1 > /proc/starry/off")
        session.run_command(input_stream[-1], command_timeout)

        artifact_outputs: dict[str, str] = {}
        for name, command in ARTIFACT_COMMANDS:
            output = session.run_command(command, command_timeout)
            artifact_outputs[name] = clean_capture(output)
            if raw:
                write_text(out_dir / name, artifact_outputs[name])

        trace_text = artifact_outputs["starry_trace.txt"]
        stats_text = artifact_outputs["starry_stats.txt"]
        last_fault_text = artifact_outputs["starry_last_fault.txt"]
        events = parse_trace(trace_text)
        event_views = build_event_views(events)
        key_views = render_key_trace(out_dir / "key_trace.txt", demo, event_views)
        key_events = [view.event for view in key_views]
        if raw:
            write_text(out_dir / "session.log", session.log)
        create_summary(
            out_dir / "summary.txt",
            demo,
            out_dir,
            events,
            key_views,
            stats_text,
            last_fault_text,
            tuple(input_stream),
            artifact_outputs,
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
        f"- net: {BASELINE_NET}",
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
