#!/usr/bin/env python3

import argparse
import collections
import datetime as dt
import pathlib
import re
import socket
import subprocess
import sys
import threading
import time
from dataclasses import dataclass


PROMPT = "starry:~#"
SERIAL_PORT = 4444
ANSI_RE = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]")


@dataclass(frozen=True)
class Demo:
    name: str
    goal: str
    commands: tuple[str, ...]
    expected_events: tuple[str, ...]
    focus_events: tuple[str, ...]
    focus_page_fault_arg0: str | None = None


@dataclass(frozen=True)
class TraceEvent:
    seq: int
    time_ns: int
    tid: int
    kind: str
    arg0: str
    arg1: str


DEMOS: dict[str, Demo] = {
    "pipe": Demo(
        name="pipe",
        goal="Show how a tiny shell pipeline drives fork/exec, pipe usage, and wakeups.",
        commands=("echo hi | cat",),
        expected_events=("SysEnter", "SysExit", "FdOpen", "FdClose", "PollSleep", "PollWake"),
        focus_events=("FdOpen", "FdClose", "PollSleep", "PollWake", "TaskExit"),
        focus_page_fault_arg0=None,
    ),
    "wait": Demo(
        name="wait",
        goal="Show child execution, blocking, and wait-based completion.",
        commands=("sleep 1 & wait",),
        expected_events=("SysEnter", "SysExit", "TaskExit", "PollSleep", "PollWake"),
        focus_events=("PollSleep", "PollWake", "TaskExit", "SignalSend", "SignalHandle"),
        focus_page_fault_arg0=None,
    ),
    "fd": Demo(
        name="fd",
        goal="Show the current process fd view and the Starry Lab fd snapshot side by side.",
        commands=("ls -l /proc/self/fd", "cat /proc/starry/fd"),
        expected_events=("SysEnter", "SysExit", "FdOpen", "FdClose"),
        focus_events=("FdOpen", "FdClose"),
        focus_page_fault_arg0=None,
    ),
    "fault": Demo(
        name="fault",
        goal="Show a deliberate fault path through page-fault recording, SIGSEGV delivery, and task exit.",
        commands=("sh -c 'echo 1 > /proc/starry/fault_demo' || true",),
        expected_events=("PageFault", "SignalSend", "SignalHandle", "TaskExit"),
        focus_events=("PageFault", "SignalSend", "SignalHandle", "TaskExit"),
        focus_page_fault_arg0="0xdeadbeef",
    ),
}

ARTIFACT_COMMANDS: tuple[tuple[str, str], ...] = (
    ("starry_stats.txt", "cat /proc/starry/stats"),
    ("starry_trace.txt", "cat /proc/starry/trace"),
    ("starry_last_fault.txt", "cat /proc/starry/last_fault"),
    ("starry_fd.txt", "cat /proc/starry/fd"),
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
        ["make", f"ARCH={arch}", "APP_FEATURES=qemu,lab", "build"],
        check=True,
    )


def spawn_qemu(arch: str) -> subprocess.Popen[str]:
    return subprocess.Popen(
        [
            "make",
            f"ARCH={arch}",
            "APP_FEATURES=qemu,lab",
            "NET=n",
            "ACCEL=n",
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


def render_key_trace(path: pathlib.Path, demo: Demo, events: list[TraceEvent]) -> None:
    interesting = demo.focus_events
    selected = [event for event in events if event.kind in interesting]
    if demo.focus_page_fault_arg0 is not None:
        keep = {
            event.seq
            for event in selected
            if event.kind != "PageFault" or event.arg0 == demo.focus_page_fault_arg0
        }
        selected = [
            event for event in selected if event.seq in keep
        ]
    else:
        page_faults = [event for event in selected if event.kind == "PageFault"]
        if len(page_faults) > 8:
            keep = {event.seq for event in page_faults[-8:]}
            selected = [
                event for event in selected if event.kind != "PageFault" or event.seq in keep
            ]
    lines = ["seq\ttid\tkind\targ0\targ1"]
    lines.extend(
        f"{event.seq}\t{event.tid}\t{event.kind}\t{event.arg0}\t{event.arg1}" for event in selected
    )
    write_text(path, "\n".join(lines) + "\n")


def parse_tab_values(text: str) -> dict[str, str]:
    result: dict[str, str] = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or "\t" not in line:
            continue
        key, value = line.split("\t", 1)
        result[key] = value
    return result


def create_summary(
    path: pathlib.Path,
    demo: Demo,
    artifact_dir: pathlib.Path,
    events: list[TraceEvent],
    stats_text: str,
    last_fault_text: str,
) -> None:
    counts = collections.Counter(event.kind for event in events)
    present = [kind for kind in demo.expected_events if counts[kind] > 0]
    missing = [kind for kind in demo.expected_events if counts[kind] == 0]
    stats = parse_tab_values(stats_text)
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
        "commands:",
    ]
    lines.extend(f"- {cmd}" for cmd in demo.commands)
    lines.append("")
    lines.append("expected events:")
    lines.extend(f"- {kind}" for kind in demo.expected_events)
    lines.append("")
    lines.append("focus events:")
    lines.extend(f"- {kind}" for kind in demo.focus_events)
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
    parser.add_argument("--skip-build", action="store_true")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    demo = DEMOS[args.demo]

    if not args.skip_build:
        run_build(args.arch)

    stamp = dt.datetime.now().strftime("%Y%m%d-%H%M%S")
    out_dir = pathlib.Path(args.out_dir) / f"{demo.name}-{stamp}"
    out_dir.mkdir(parents=True, exist_ok=True)

    proc = spawn_qemu(args.arch)
    try:
        wait_for_qemu_start(proc, args.boot_timeout)
        sock = socket.create_connection(("localhost", SERIAL_PORT), timeout=args.boot_timeout)
        session = Session(sock)
        session.wait_for_prompt(args.boot_timeout)
        session.run_command("echo 1 > /proc/starry/reset", args.command_timeout)

        for index, command in enumerate(demo.commands, start=1):
            output = session.run_command(command, args.command_timeout)
            write_text(out_dir / f"demo-step-{index}.txt", clean_capture(output))

        session.run_command("echo 1 > /proc/starry/off", args.command_timeout)

        artifact_outputs: dict[str, str] = {}
        for name, command in ARTIFACT_COMMANDS:
            output = session.run_command(command, args.command_timeout)
            artifact_outputs[name] = clean_capture(output)
            if args.raw:
                write_text(out_dir / name, artifact_outputs[name])

        trace_text = artifact_outputs["starry_trace.txt"]
        stats_text = artifact_outputs["starry_stats.txt"]
        last_fault_text = artifact_outputs["starry_last_fault.txt"]
        events = parse_trace(trace_text)
        render_key_trace(out_dir / "key_trace.txt", demo, events)
        if args.raw:
            write_text(out_dir / "session.log", session.log)
        create_summary(
            out_dir / "summary.txt",
            demo,
            out_dir,
            events,
            stats_text,
            last_fault_text,
        )

        sock.sendall(b"exit\r\n")
        print(out_dir)
        return 0
    finally:
        try:
            proc.wait(timeout=1)
        except subprocess.TimeoutExpired:
            proc.terminate()
            proc.wait()


if __name__ == "__main__":
    raise SystemExit(main())
