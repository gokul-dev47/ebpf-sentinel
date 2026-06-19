# SPDX-License-Identifier: GPL-2.0
CLANG      ?= clang
LLC        ?= llc
STRIP      ?= llvm-strip
BPFTOOL    ?= bpftool
ARCH       := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')
KERNEL_HDR ?= /usr/include
LIBBPF_HDR ?= /usr/include/bpf
OUTPUT_DIR ?= ../../build/bpf

BPF_CFLAGS := \
    -target bpf -g -O2 -Wall \
    -Wno-unused-value -Wno-pointer-sign \
    -Wno-compare-distinct-pointer-types \
    -D__KERNEL__ -D__TARGET_ARCH_$(ARCH) \
    -I$(KERNEL_HDR) -I$(LIBBPF_HDR) -I../common -I. -mcpu=v3

SRCS := syscall_monitor.bpf.c process_scanner.bpf.c file_monitor.bpf.c \
        network_monitor.bpf.c ebpf_audit.bpf.c memory_scanner.bpf.c

OBJS := $(patsubst %.bpf.c,$(OUTPUT_DIR)/%.bpf.o,$(SRCS))

.PHONY: all clean

all: $(OUTPUT_DIR) $(OBJS)

$(OUTPUT_DIR):
	mkdir -p $(OUTPUT_DIR)

$(OUTPUT_DIR)/%.bpf.o: %.bpf.c
	@echo "  BPF  $<"
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@
	$(STRIP) -g $@

clean:
	rm -rf $(OUTPUT_DIR)/*.bpf.o
