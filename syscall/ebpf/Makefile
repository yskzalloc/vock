BPFTOOL ?= /usr/sbin/bpftool
CLANG   ?= clang

.PHONY: all clean generate

all: generate

generate: vmlinux.h trace.skel.h

vmlinux.h:
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $@

trace.bpf.o: trace.bpf.c vmlinux.h
	$(CLANG) -g -O2 -target bpf -I. -c $< -o $@

trace.skel.h: trace.bpf.o
	$(BPFTOOL) gen skeleton $< > $@

clean:
	rm -f vmlinux.h trace.bpf.o trace.skel.h
