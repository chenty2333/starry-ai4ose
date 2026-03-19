# Starry Lab v1

## Positioning

`Starry Lab` is not a full Linux clone.

It is a demo-friendly teaching and experimentation kernel built on the current `StarryOS` mainline:

- enough Linux ABI to run representative user-space demos
- strong observability for core kernel mechanisms
- one focused experimental feature after the observability base is in place

The first release goal is:

> Make one small user-space scenario explain the kernel clearly, instead of making the kernel imitate Linux broadly.

## Product Definition

`Starry Lab = small Linux ABI surface + strong observability + one experimental feature`

### Small Linux ABI Surface

Keep the kernel capable of supporting:

- shell startup
- `fork/exec/wait`
- `pipe/dup/close`
- `poll/select` on the basic objects we care about
- tty interaction
- one simple network demo later
- one simple graphics demo later

### Strong Observability

Treat the following as first-class visible objects:

- syscall enter/exit
- page faults
- signal delivery and handling
- task block/wake/exit
- file descriptor lifecycle
- poll sleep/wake

### One Experimental Feature

Do not start with a new native API.

The first experimental direction after observability should be a cheap deterministic mode:

- single architecture
- single platform
- single-core first
- repeatable demo execution
- event trace stability across reruns

## Design Principles

1. Demo-first, not syscall-first.
2. Observe before optimizing.
3. One platform first: `riscv64 + qemu + single core`.
4. Reuse current `StarryOS` structure instead of large refactors.
5. Prefer a narrow, well-explained feature over a broad but shallow feature set.

## v1 Scope

### Kernel Surfaces

Add a small `lab` subsystem that provides:

- a shared event type
- a fixed-size ring buffer
- simple counters and snapshots
- a lightweight `emit` interface for trace points

### Trace Export

Expose the first observability surface through `/proc/starry`:

- `/proc/starry/trace`
- `/proc/starry/stats`
- `/proc/starry/last_fault`
- `/proc/starry/fd`

The `/proc/starry/*` files are teaching surfaces first, Linux compatibility surfaces second.

### Host Tooling

Add one host-side runner:

- `scripts/lab-run.py`

Responsibilities:

- boot QEMU
- send demo commands over the existing serial/TCP path
- collect `/proc/starry/*`
- save raw traces
- render a small human-readable timeline or summary

### Teaching Demos

Start with four demos only:

1. `echo hi | cat`
2. `sleep 1 & wait`
3. a deliberate bad-pointer program
4. `/proc/self/fd` inspection

Each demo should answer one teaching question:

- how do processes and pipes interact?
- how do block and wake paths work?
- how does user memory failure become `EFAULT` or `SIGSEGV`?
- how are kernel objects turned into file descriptors?

## Initial Event Set

The first trace format should stay small:

- `SysEnter`
- `SysExit`
- `PageFault`
- `SignalSend`
- `SignalHandle`
- `FdOpen`
- `FdClose`
- `PollSleep`
- `PollWake`
- `TaskExit`

This list is intentionally incomplete.
Add events only when they help explain an existing demo.

## Suggested Hook Points

- syscall entry/exit: `kernel/src/syscall/mod.rs`
- page fault and signal loop: `kernel/src/task/user.rs`
- fd lifecycle: `kernel/src/file/mod.rs`
- poll blocking path: `kernel/src/syscall/io_mpx/poll.rs`
- proc export surface: `kernel/src/pseudofs/proc.rs`

## Non-Goals for v1

The following are explicitly out of scope for the first phase:

- full Linux compatibility
- large syscall-count chasing
- LTP completeness
- SMP
- multi-architecture parity
- full SSH/X11 ecosystem support
- a new native syscall ABI
- aggressive performance work

## Milestones

### M0: Freeze the teaching baseline

- only target `riscv64 + qemu + single core`
- keep the current shell boot path working
- define the initial demos and expected outputs

### M1: Observability substrate

- add `lab` feature
- add ring buffer and event definitions
- add kernel-side counters and snapshots

### M2: First trace points

- instrument syscall enter/exit
- instrument page faults and signal handling
- instrument fd open/close
- instrument poll sleep/wake

### M3: `/proc/starry`

- export trace, stats, last fault, and fd state
- make outputs stable and readable

### M4: Host runner and demos

- implement `lab-run.py`
- add the four teaching demos
- save artifacts for later comparison

### M5: Cheap deterministic mode

- fixed seed
- fixed clock policy where feasible
- fixed demo input stream
- trace stability checks across reruns

## Acceptance Criteria for v1

`Starry Lab v1` is successful if all of the following are true:

- the system still boots to shell on the frozen baseline
- the four teaching demos run end-to-end
- each demo can export a readable trace from `/proc/starry/*`
- the trace is good enough to explain the kernel path in a short walkthrough
- the implementation remains smaller and simpler than a broad Linux-compat push

## Decision Rule

When a feature request appears, ask:

1. Does it make an existing demo clearer?
2. Does it improve observability?
3. Does it unblock the deterministic mode roadmap?

If the answer to all three is no, it probably does not belong in `Starry Lab v1`.
