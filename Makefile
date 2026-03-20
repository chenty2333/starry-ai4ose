# Build Options
export ARCH := riscv64
export LOG := warn
export DWARF := y
export MEMTRACK := n

# QEMU Options
export BLK := y
export NET := y
export VSOCK := n
export MEM := 1G
export ICOUNT := n

# Generated Options
export A := $(PWD)
export NO_AXSTD := y
export AX_LIB := axfeat
export APP_FEATURES := qemu

ifeq ($(MEMTRACK), y)
	APP_FEATURES += starry-api/memtrack
endif

default: build

ROOTFS_URL = https://github.com/Starry-OS/rootfs/releases/download/20260214
ROOTFS_IMG = rootfs-$(ARCH).img

rootfs:
	@if [ ! -f $(ROOTFS_IMG) ]; then \
		echo "Image not found, downloading..."; \
		curl -f -L $(ROOTFS_URL)/$(ROOTFS_IMG).xz -O; \
		xz -d $(ROOTFS_IMG).xz; \
	fi
	@cp $(ROOTFS_IMG) make/disk.img

img:
	@echo -e "\033[33mWARN: The 'img' target is deprecated. Please use 'rootfs' instead.\033[0m"
	@$(MAKE) --no-print-directory rootfs

defconfig justrun clean:
	@$(MAKE) -C make $@

build run debug disasm: defconfig
	@$(MAKE) -C make $@

ci-test:
	./scripts/ci-test.py $(ARCH)

LAB_DEMO ?= pipe
LAB_RAW ?= n
LAB_REPEAT ?= 1
DEMO ?= $(LAB_DEMO)
REPEAT ?= $(LAB_REPEAT)

ifeq ($(filter y yes 1,$(LAB_RAW)),)
LAB_RAW_FLAG :=
else
LAB_RAW_FLAG := --raw
endif

ifeq ($(REPEAT),1)
LAB_REPEAT_FLAG :=
else
LAB_REPEAT_FLAG := --repeat $(REPEAT)
endif

ifeq ($(REPEAT),1)
LAB_REPEAT_DEFAULT_FLAG := --repeat 2
else
LAB_REPEAT_DEFAULT_FLAG := --repeat $(REPEAT)
endif

lab:
	python3 ./scripts/lab-run.py $(DEMO) $(LAB_RAW_FLAG)

lab-stage:
	python3 ./scripts/lab-run.py $(DEMO) --stage-only

lab-run:
	python3 ./scripts/lab-run.py $(DEMO) $(LAB_RAW_FLAG) $(LAB_REPEAT_FLAG)

lab-pipe:
	$(MAKE) --no-print-directory lab DEMO=pipe LAB_RAW=$(LAB_RAW)

lab-wait:
	$(MAKE) --no-print-directory lab DEMO=wait LAB_RAW=$(LAB_RAW)

lab-cow:
	$(MAKE) --no-print-directory lab DEMO=cow LAB_RAW=$(LAB_RAW)

lab-filemap:
	$(MAKE) --no-print-directory lab DEMO=filemap LAB_RAW=$(LAB_RAW)

lab-shm:
	$(MAKE) --no-print-directory lab DEMO=shm LAB_RAW=$(LAB_RAW)

lab-fb:
	$(MAKE) --no-print-directory lab DEMO=fb LAB_RAW=$(LAB_RAW)

lab-ev:
	$(MAKE) --no-print-directory lab DEMO=ev LAB_RAW=$(LAB_RAW)

lab-gui:
	$(MAKE) --no-print-directory lab DEMO=gui LAB_RAW=$(LAB_RAW)

lab-snake:
	$(MAKE) --no-print-directory lab DEMO=snake LAB_RAW=$(LAB_RAW)

lab-stage-snake:
	$(MAKE) --no-print-directory lab-stage DEMO=snake

lab-fd:
	$(MAKE) --no-print-directory lab DEMO=fd LAB_RAW=$(LAB_RAW)

lab-fault:
	$(MAKE) --no-print-directory lab DEMO=fault LAB_RAW=$(LAB_RAW)

lab-udp:
	$(MAKE) --no-print-directory lab DEMO=udp LAB_RAW=$(LAB_RAW)

lab-tcp:
	$(MAKE) --no-print-directory lab DEMO=tcp LAB_RAW=$(LAB_RAW)

lab-http:
	$(MAKE) --no-print-directory lab DEMO=http LAB_RAW=$(LAB_RAW)

lab-pty:
	$(MAKE) --no-print-directory lab DEMO=pty LAB_RAW=$(LAB_RAW)

lab-jobctl:
	$(MAKE) --no-print-directory lab DEMO=jobctl LAB_RAW=$(LAB_RAW)

lab-waitctl:
	$(MAKE) --no-print-directory lab DEMO=waitctl LAB_RAW=$(LAB_RAW)

lab-ssh-poll:
	$(MAKE) --no-print-directory lab DEMO=ssh-poll LAB_RAW=$(LAB_RAW)

lab-ssh-select:
	$(MAKE) --no-print-directory lab DEMO=ssh-select LAB_RAW=$(LAB_RAW)

lab-sshd:
	$(MAKE) --no-print-directory lab DEMO=sshd LAB_RAW=$(LAB_RAW)

lab-repeat:
	python3 ./scripts/lab-run.py $(DEMO) $(LAB_RAW_FLAG) $(LAB_REPEAT_DEFAULT_FLAG)

lab-repeat-pipe:
	$(MAKE) --no-print-directory lab-repeat DEMO=pipe REPEAT=2 LAB_RAW=$(LAB_RAW)

lab-repeat-wait:
	$(MAKE) --no-print-directory lab-repeat DEMO=wait REPEAT=2 LAB_RAW=$(LAB_RAW)

lab-repeat-cow:
	$(MAKE) --no-print-directory lab-repeat DEMO=cow REPEAT=2 LAB_RAW=$(LAB_RAW)

lab-repeat-filemap:
	$(MAKE) --no-print-directory lab-repeat DEMO=filemap REPEAT=2 LAB_RAW=$(LAB_RAW)

lab-repeat-shm:
	$(MAKE) --no-print-directory lab-repeat DEMO=shm REPEAT=2 LAB_RAW=$(LAB_RAW)

lab-repeat-fb:
	$(MAKE) --no-print-directory lab-repeat DEMO=fb REPEAT=2 LAB_RAW=$(LAB_RAW)

lab-repeat-ev:
	$(MAKE) --no-print-directory lab-repeat DEMO=ev REPEAT=2 LAB_RAW=$(LAB_RAW)

lab-repeat-gui:
	$(MAKE) --no-print-directory lab-repeat DEMO=gui REPEAT=2 LAB_RAW=$(LAB_RAW)

lab-repeat-snake:
	$(MAKE) --no-print-directory lab-repeat DEMO=snake REPEAT=2 LAB_RAW=$(LAB_RAW)

lab-repeat-fd:
	$(MAKE) --no-print-directory lab-repeat DEMO=fd REPEAT=2 LAB_RAW=$(LAB_RAW)

lab-repeat-fault:
	$(MAKE) --no-print-directory lab-repeat DEMO=fault REPEAT=2 LAB_RAW=$(LAB_RAW)

lab-repeat-udp:
	$(MAKE) --no-print-directory lab-repeat DEMO=udp REPEAT=2 LAB_RAW=$(LAB_RAW)

lab-repeat-tcp:
	$(MAKE) --no-print-directory lab-repeat DEMO=tcp REPEAT=2 LAB_RAW=$(LAB_RAW)

lab-repeat-http:
	$(MAKE) --no-print-directory lab-repeat DEMO=http REPEAT=2 LAB_RAW=$(LAB_RAW)

lab-repeat-pty:
	$(MAKE) --no-print-directory lab-repeat DEMO=pty REPEAT=2 LAB_RAW=$(LAB_RAW)

lab-repeat-jobctl:
	$(MAKE) --no-print-directory lab-repeat DEMO=jobctl REPEAT=2 LAB_RAW=$(LAB_RAW)

lab-repeat-waitctl:
	$(MAKE) --no-print-directory lab-repeat DEMO=waitctl REPEAT=2 LAB_RAW=$(LAB_RAW)

lab-repeat-ssh-poll:
	$(MAKE) --no-print-directory lab-repeat DEMO=ssh-poll REPEAT=2 LAB_RAW=$(LAB_RAW)

lab-repeat-ssh-select:
	$(MAKE) --no-print-directory lab-repeat DEMO=ssh-select REPEAT=2 LAB_RAW=$(LAB_RAW)

lab-repeat-sshd:
	$(MAKE) --no-print-directory lab-repeat DEMO=sshd REPEAT=2 LAB_RAW=$(LAB_RAW)

# Aliases
rv:
	$(MAKE) ARCH=riscv64 run

la:
	$(MAKE) ARCH=loongarch64 run

vf2:
	$(MAKE) ARCH=riscv64 APP_FEATURES=vf2 MYPLAT=axplat-riscv64-visionfive2 BUS=mmio build

.PHONY: build run justrun debug disasm clean lab lab-stage lab-run lab-pipe lab-wait lab-cow lab-filemap lab-shm lab-fb lab-ev lab-gui lab-snake lab-stage-snake lab-fd lab-fault lab-udp lab-tcp lab-http lab-pty lab-jobctl lab-waitctl lab-ssh-poll lab-ssh-select lab-sshd lab-repeat lab-repeat-pipe lab-repeat-wait lab-repeat-cow lab-repeat-filemap lab-repeat-shm lab-repeat-fb lab-repeat-ev lab-repeat-gui lab-repeat-snake lab-repeat-fd lab-repeat-fault lab-repeat-udp lab-repeat-tcp lab-repeat-http lab-repeat-pty lab-repeat-jobctl lab-repeat-waitctl lab-repeat-ssh-poll lab-repeat-ssh-select lab-repeat-sshd
