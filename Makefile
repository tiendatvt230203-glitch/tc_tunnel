CLANG ?= clang
CC ?= gcc

ARCH := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')

CFLAGS := -g -O2 -Wall
BPF_CFLAGS := -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH)

.PHONY: all clean

all: tc_encap.bpf.o tc_decap.bpf.o loader

tc_encap.bpf.o: tc_encap.bpf.c tc_common.h
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

tc_decap.bpf.o: tc_decap.bpf.c tc_common.h
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

loader: loader.c tc_common.h
	$(CC) $(CFLAGS) $< -o $@ -lbpf -lelf -lz

clean:
	rm -f tc_encap.bpf.o tc_decap.bpf.o loader
