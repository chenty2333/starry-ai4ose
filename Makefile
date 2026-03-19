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

ifeq ($(filter y yes 1,$(LAB_RAW)),)
LAB_RAW_FLAG :=
else
LAB_RAW_FLAG := --raw
endif

ifeq ($(LAB_REPEAT),1)
LAB_REPEAT_FLAG :=
else
LAB_REPEAT_FLAG := --repeat $(LAB_REPEAT)
endif

lab-run:
	python3 ./scripts/lab-run.py $(LAB_DEMO) $(LAB_RAW_FLAG) $(LAB_REPEAT_FLAG)

lab-pipe:
	python3 ./scripts/lab-run.py pipe $(LAB_RAW_FLAG)

lab-wait:
	python3 ./scripts/lab-run.py wait $(LAB_RAW_FLAG)

lab-fd:
	python3 ./scripts/lab-run.py fd $(LAB_RAW_FLAG)

lab-fault:
	python3 ./scripts/lab-run.py fault $(LAB_RAW_FLAG)

lab-repeat:
	python3 ./scripts/lab-run.py $(LAB_DEMO) $(LAB_RAW_FLAG) --repeat 2

lab-repeat-pipe:
	python3 ./scripts/lab-run.py pipe $(LAB_RAW_FLAG) --repeat 2

lab-repeat-wait:
	python3 ./scripts/lab-run.py wait $(LAB_RAW_FLAG) --repeat 2

lab-repeat-fd:
	python3 ./scripts/lab-run.py fd $(LAB_RAW_FLAG) --repeat 2

lab-repeat-fault:
	python3 ./scripts/lab-run.py fault $(LAB_RAW_FLAG) --repeat 2

# Aliases
rv:
	$(MAKE) ARCH=riscv64 run

la:
	$(MAKE) ARCH=loongarch64 run

vf2:
	$(MAKE) ARCH=riscv64 APP_FEATURES=vf2 MYPLAT=axplat-riscv64-visionfive2 BUS=mmio build

.PHONY: build run justrun debug disasm clean lab-run lab-pipe lab-wait lab-fd lab-fault lab-repeat lab-repeat-pipe lab-repeat-wait lab-repeat-fd lab-repeat-fault
