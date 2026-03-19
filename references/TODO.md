# Starry Lab TODO

This file tracks the first implementation backlog for `Starry Lab v1`.

## M0: Baseline

- [ ] Freeze the initial target as `riscv64 + qemu + single core`.
- [ ] Document the exact boot command used for lab runs.
- [ ] Confirm the initial shell prompt and serial interaction path remain stable.
- [ ] List the minimum rootfs commands required by the first four demos.

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
- [ ] Instrument fatal signal send/handle paths near [`kernel/src/task/user.rs`](/home/dia/starry-ai4ose/kernel/src/task/user.rs).
- [x] Instrument fd add/remove in [`kernel/src/file/mod.rs`](/home/dia/starry-ai4ose/kernel/src/file/mod.rs).
- [ ] Instrument poll sleep/wake in [`kernel/src/syscall/io_mpx/poll.rs`](/home/dia/starry-ai4ose/kernel/src/syscall/io_mpx/poll.rs).
- [ ] Instrument task exit in the task exit path.

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

- [ ] Add `scripts/lab-run.py`.
- [ ] Reuse the current serial/TCP QEMU interaction pattern from [`scripts/ci-test.py`](/home/dia/starry-ai4ose/scripts/ci-test.py).
- [ ] Support running one named demo at a time.
- [ ] Capture command output and `/proc/starry/*` artifacts.
- [ ] Save raw artifacts under a stable output directory.
- [ ] Render one compact summary or timeline per run.

Exit condition:
A single command can boot the kernel, run one lab demo, and save a readable trace report.

## M5: Teaching Demos

- [ ] Add a demo for `echo hi | cat`.
- [ ] Add a demo for `sleep 1 & wait`.
- [ ] Add a demo for bad-pointer fault handling.
- [ ] Add a demo for `/proc/self/fd`.
- [ ] For each demo, write down the teaching goal and the key expected events.

Exit condition:
All four demos run through the host runner and produce explainable traces.

## M6: Cheap Deterministic Mode

- [ ] Fix the lab baseline to one architecture and one scheduler configuration.
- [ ] Introduce a stable seed for lab runs where randomness exists.
- [ ] Audit obvious wall-clock uses and replace or wrap them where needed for repeatability.
- [ ] Record demo input streams.
- [ ] Compare traces from repeated runs and measure drift.

Exit condition:
Running the same demo twice produces traces that are close enough to compare meaningfully.

## Deferred by Default

- [ ] Broad syscall-count expansion
- [ ] LTP-driven work
- [ ] SMP work
- [ ] Multi-architecture polishing
- [ ] Full X11/SSH enablement
- [ ] New native ABI design

Rule:
Do not pull deferred items into the active backlog unless they directly improve a current lab demo or observability surface.
