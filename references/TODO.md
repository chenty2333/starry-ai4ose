# Starry Lab TODO

This file tracks the first implementation backlog for `Starry Lab v1`.

## M0: Baseline

- [x] Freeze the initial target as `riscv64 + qemu + single core`.
- [x] Document the exact boot command used for lab runs.
- [x] Confirm the initial shell prompt and serial interaction path remain stable.
- [x] List the minimum rootfs commands required by the first four demos.

Exit condition:
The same baseline can repeatedly boot to shell and accept scripted input.

## M1: Lab Subsystem

- [x] Add a `lab` feature gate in [`kernel/Cargo.toml`](/home/dia/starry-ai4ose/kernel/Cargo.toml).
- [x] Add a new `kernel/src/lab/` module tree.
- [x] Define the initial event enum and record format.
- [x] Implement a fixed-size in-memory ring buffer.
- [x] Add simple counters for event totals and drops.
- [x] Add a `last_fault` snapshot structure.
- [x] Provide a small `emit()` API or macro that is cheap to call from hot paths.

Exit condition:
Kernel code can record events without needing `/proc` or host tooling yet.

## M2: First Trace Points

- [x] Instrument syscall enter in [`kernel/src/syscall/mod.rs`](/home/dia/starry-ai4ose/kernel/src/syscall/mod.rs).
- [x] Instrument syscall exit in [`kernel/src/syscall/mod.rs`](/home/dia/starry-ai4ose/kernel/src/syscall/mod.rs).
- [x] Instrument page faults in [`kernel/src/task/user.rs`](/home/dia/starry-ai4ose/kernel/src/task/user.rs).
- [x] Instrument fatal signal send/handle paths near [`kernel/src/task/user.rs`](/home/dia/starry-ai4ose/kernel/src/task/user.rs).
- [x] Instrument fd add/remove in [`kernel/src/file/mod.rs`](/home/dia/starry-ai4ose/kernel/src/file/mod.rs).
- [x] Instrument poll sleep/wake in [`kernel/src/syscall/io_mpx/poll.rs`](/home/dia/starry-ai4ose/kernel/src/syscall/io_mpx/poll.rs).
- [x] Instrument task exit in the task exit path.

Exit condition:
At least one shell command produces a non-empty kernel trace that includes syscall and fd events.

## M3: `/proc/starry`

- [x] Extend [`kernel/src/pseudofs/proc.rs`](/home/dia/starry-ai4ose/kernel/src/pseudofs/proc.rs) with a `/proc/starry` directory.
- [x] Add `/proc/starry/trace` for recent event dump.
- [x] Add `/proc/starry/stats` for aggregate counts and drop counters.
- [x] Add `/proc/starry/last_fault` for the latest page-fault snapshot.
- [x] Add `/proc/starry/fd` for a readable view of current fd state.
- [x] Make file output line-oriented and script-friendly.

Exit condition:
All observability data needed by the first four demos is available from `/proc/starry/*`.

## M4: Host Runner

- [x] Add `scripts/lab-run.py`.
- [x] Reuse the current serial/TCP QEMU interaction pattern from [`scripts/ci-test.py`](/home/dia/starry-ai4ose/scripts/ci-test.py).
- [x] Support running one named demo at a time.
- [x] Capture command output and `/proc/starry/*` artifacts.
- [x] Save raw artifacts under a stable output directory.
- [x] Render one compact summary or timeline per run.

Exit condition:
A single command can boot the kernel, run one lab demo, and save a readable trace report.

## M5: Teaching Demos

- [x] Add a demo for `echo hi | cat`.
- [x] Add a demo for `sleep 1 & wait`.
- [x] Add a demo for bad-pointer fault handling.
- [x] Add a demo for `/proc/self/fd`.
- [x] For each demo, write down the teaching goal and the key expected events.

Exit condition:
All four demos run through the host runner and produce explainable traces.

## M6: Cheap Deterministic Mode

- [x] Fix the lab baseline to one architecture and one scheduler configuration.
- [x] Introduce a stable seed for lab runs where randomness exists.
- [x] Audit obvious wall-clock uses and replace or wrap them where needed for repeatability.
- [x] Record demo input streams.
- [x] Compare traces from repeated runs and measure drift.

Exit condition:
Running the same demo twice produces traces that are close enough to compare meaningfully.

## M7: TCP Cleanup and SSH Prep

- [x] Make the TCP echo demo print the echoed line from guest stdout.
- [x] Trim the TCP teaching trace down to the stream main path: `connect -> write -> read -> EOF`.
- [x] Audit the `pty/tty` path needed for interactive remote shells.
- [x] Audit `session/process group` and job-control gaps on the SSH path.
- [x] Audit `SIGCHLD/wait4` behavior under interactive shell workloads.
- [x] Validate `poll/select` across socket and tty objects in one combined scenario.

Exit condition:
The TCP stream demo is clean enough to teach, and the next SSH-oriented backlog is explicit.

## M8: Real SSH Bring-up

- [x] Stage a guest-runnable SSH server binary in the lab rootfs.
- [x] Log in from the host with key-based auth over QEMU user-net forwarding.
- [x] Route the SSH login into a real pty-backed interactive shell.
- [x] Capture the SSH teaching path in `summary.txt` and `key_trace.txt`.
- [x] Check repeatability for the first real SSH demo.

Exit condition:
`make lab-sshd` produces one real SSH login trace and `make lab-repeat-sshd` can compare repeated runs meaningfully.

## M9: SSH Teaching Trace Refinement

- [x] Split the real SSH demo into phase-focused trace windows for connect, pty bootstrap, and interactive shell work.
- [x] Add phase-specific `summary.txt` and `key_trace.txt` artifacts under the SSH demo output.
- [x] Rewrite the top-level SSH summary as a teaching walkthrough over `accept -> pty -> setsid -> TIOCSCTTY/TIOCSPGRP -> SIGCHLD -> wait4 -> close`.
- [x] Tighten the interactive SSH workload so `wait4` reaps a clean `status=0` child and `demo-step-1.txt` stays readable.
- [x] Re-check repeatability for the refined SSH teaching path.

Exit condition:
`make lab-sshd` produces clean phase artifacts that explain the SSH path without raw-trace spelunking, and `make lab-repeat-sshd` still matches exactly.

## M10: SSH Semantics Hardening

- [x] Surface socket peer shutdown as readable hangup in `poll/select` so plain EOF waiters wake reliably.
- [x] Wake late PTY pollers immediately once EOF/HUP has already been observed.
- [x] Make `TIOCSCTTY` idempotent for the owning session and reject cross-session controlling-tty rebinding cleanly.
- [x] Make `TIOCNOTTY` detach quietly when the tty is not actually owned by the caller session.
- [x] Stop reporting a fake `WaitReap` event for `WNOWAIT`.
- [x] Reject `WUNTRACED/WCONTINUED` until stop/continue reporting is implemented instead of silently lying.

Exit condition:
`make lab-repeat-tcp`, `make lab-repeat-pty`, and `make lab-repeat-sshd` all stay green after the semantic tightening pass.

## M11: Interactive Job Control and Wait Semantics

- [x] Add a dedicated `jobctl` workload that drives `Ctrl-Z`, `fg`, and `Ctrl-C` through a real pty-backed shell.
- [x] Add a dedicated `waitctl` helper that exercises `wait4(..., WUNTRACED)`, `wait4(..., WCONTINUED)`, and final reap semantics explicitly.
- [x] Teach the tty line discipline to emit `SIGTSTP` on `Ctrl-Z`.
- [x] Surface stopped tasks as `T` in `/proc/[pid]/stat`.
- [x] Record process stop/continue state so `wait4` can report `WaitStop` and `WaitContinue`.
- [x] Block stopped tasks in the user loop until a later `SIGCONT` resumes them.
- [x] Add `WaitStop` and `WaitContinue` to the lab event vocabulary and teaching output.
- [x] Add `make lab-jobctl`, `make lab-waitctl`, `make lab-repeat-jobctl`, and `make lab-repeat-waitctl`.

Exit condition:
`make lab-repeat-jobctl` and `make lab-repeat-waitctl` both stay green, with stop semantics visible in the pty job-control demo and continued/reap semantics visible in the explicit wait helper demo.

## M12: Real SSH Job Control Edges

- [x] Observe `Ctrl-Z`, `fg`, and `Ctrl-C` through a real `sshd` session instead of only the local pty helper.
- [x] Split the `waitctl` teaching output into phase-focused stop/continue/reap reports so all three wait4 states stay visible.
- [x] Observe `SIGTTOU` for background tty output over a real SSH-backed controlling terminal.
- [x] Observe `SIGTTIN` for background tty input over a real SSH-backed controlling terminal.
- [x] Re-check repeatability for the extended `waitctl` and `sshd` teaching paths.

Exit condition:
`make lab-repeat-waitctl` stays exact-match green, and `make lab-sshd` clearly shows `Ctrl-Z/Ctrl-C`, `SIGTTOU`, and `SIGTTIN` in its phase summaries and SSH transcript.

## M13: MM + FS Stage 1, Anonymous Memory and COW

- [x] Add a dedicated `cow` helper workload that exercises anonymous `mmap`, `mprotect`, `fork`, COW write faults, `wait4`, and `munmap`.
- [x] Stage the helper into the lab rootfs and expose `make lab-cow` / `make lab-repeat-cow`.
- [x] Teach the runner to summarize anonymous private mapping bring-up, permission flips, and parent/child divergence after the COW write.
- [x] Re-check repeatability for the new anonymous-memory workload.

Exit condition:
`make lab-repeat-cow` stays exact-match green, and the output makes it obvious that the parent kept `parent-page` while the child successfully wrote its private `child-copy`.

## M14: MM + FS Stage 2, File Mappings and Page Cache

- [x] Add a dedicated `filemap` helper workload that exercises `open/ftruncate`, `MAP_SHARED`, `MAP_PRIVATE`, `pread/pwrite`, and `munmap`.
- [x] Stage the helper into the lab rootfs and expose `make lab-filemap` / `make lab-repeat-filemap`.
- [x] Teach the runner to explain shared-map coherence and private-map isolation in one readable summary.
- [x] Re-check repeatability for the file-backed mapping workload.

Exit condition:
`make lab-repeat-filemap` stays exact-match green, and the output makes it obvious that shared-map writes round-trip through file I/O while private-map writes stay isolated from the backing file.

## M15: MM + FS Stage 3, SysV Shared Memory

- [x] Add a dedicated `shm` helper workload that exercises `shmget`, `shmat`, fork inheritance, child-side `shmdt`, `IPC_RMID`, and final detach/removal.
- [x] Stage the helper into the lab rootfs and expose `make lab-shm` / `make lab-repeat-shm`.
- [x] Fix fork-time SysV shm bookkeeping so inherited attachments can detach and clean up correctly from the child process.
- [x] Make `shmat` fail cleanly instead of panicking when a removed segment is no longer present.
- [x] Re-check repeatability for the SysV shm workload.

Exit condition:
`make lab-repeat-shm` stays exact-match green, and the output makes it obvious that the child inherited the segment, detached successfully, and the segment stopped being attachable after `IPC_RMID` plus the last detach.

## Deferred by Default

- [ ] Broad syscall-count expansion
- [ ] LTP-driven work
- [ ] SMP work
- [ ] Multi-architecture polishing
- [ ] Full X11/SSH enablement
- [ ] New native ABI design

Rule:
Do not pull deferred items into the active backlog unless they directly improve a current lab demo or observability surface.
