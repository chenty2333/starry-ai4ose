# Starry Lab Baseline

This file freezes the first deterministic teaching baseline for `Starry Lab`.

## Platform

- architecture: `riscv64`
- machine: `qemu`
- cpu count: `1`
- acceleration: `off`
- network device: `off`
- QEMU icount: `on`
- app features: `qemu,lab`

The host runner enforces this baseline through:

- `ARCH=riscv64`
- `APP_FEATURES=qemu,lab`
- `ACCEL=n`
- `NET=n`
- `ICOUNT=y`
- `SMP=1`
- `QEMU_ARGS=-snapshot -monitor none -serial tcp::4444,server=on`

## Stable Sources

- `/dev/random` and `/dev/urandom` use a fixed seed:
  - `0123456789abcdef0123456789abcdef`
- Repeatability compares normalized kernel traces:
  - drop `seq`
  - drop `time_ns`
  - remap concrete tids into stable `T0`, `T1`, ... labels

This means the lab tooling compares kernel behavior, not wall-clock timestamps.

## Shell Prompt

- expected prompt: `starry:~#`
- serial path: `tcp::4444`

## First Four Demos

### `pipe`

- command: `echo hi | cat`
- required commands:
  - `sh`
  - `echo`
  - `cat`

### `wait`

- command: `sleep 1 & wait`
- required commands:
  - `sh`
  - `sleep`
  - `wait`

### `fd`

- commands:
  - `ls -l /proc/self/fd`
  - `cat /proc/starry/fd`
- required commands:
  - `ls`
  - `cat`

### `fault`

- command: `sh -c 'echo 1 > /proc/starry/fault_demo' || true`
- required commands:
  - `sh`
  - shell redirection and `||`

## Decision Rule

If a run is outside this baseline, it is allowed for exploration, but it should
not be used as a repeatability reference run.
