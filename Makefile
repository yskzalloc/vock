CC ?= clang
CFLAGS += -Wall -O2
LDFLAGS += -lm

DEBUG_INFO_BTF ?= $(shell [ -e /sys/kernel/btf/vmlinux ] && echo 1 || echo 0)

ifeq ($(DEBUG_INFO_BTF),1)
  CFLAGS += -DDEBUG_INFO_BTF=1
endif

TOOL_NAME = vock
TARGET_EXE = vock
TARGET_LIB = mode/kcov.so
LIB_SOURCE = mode/kcov.c

EXE_OBJS = vock.o mode/hw.o mode/intel_pt.o mode/pt_decode.o mode/amd_lbr.o \
            syscall/ptrace/ptrace.o syscall/sud/sud.o syscall/ebpf/ebpf.o \
            syscall/decode.o syzlang/syzlang.o \
            fuzz/fuzz.o fuzz/covset.o fuzz/signal.o fuzz/mutate.o fuzz/state.o \
            prog2c/prog2c.o execprog/execprog.o

ARCH := $(shell uname -m)
ifeq ($(ARCH),aarch64)
  EXE_OBJS += syscall/aarch64/sys.o syscall/aarch64/decode.o
else
  EXE_OBJS += syscall/x86_64/sys.o syscall/x86_64/decode.o
endif

.PHONY: all
all: $(TARGET_EXE) $(TARGET_LIB) sud-libs btf-test

$(TARGET_EXE): $(EXE_OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

$(TARGET_LIB): $(LIB_SOURCE)
	$(CC) $(CFLAGS) -shared -fPIC -o $@ $<

.PHONY: sud-libs
sud-libs:
	$(MAKE) -C syscall/sud CC=$(CC) || echo "[warn] SUD build failed (--syscall sud unavailable)"

.PHONY: btf-test
btf-test: btf/btf_test
btf/btf_test: btf/btf_test.c btf/btf.c btf/btf.h
	$(CC) $(CFLAGS) -o $@ btf/btf_test.c btf/btf.c

.PHONY: mutate-test
mutate-test: btf/mutate_test
btf/mutate_test: btf/mutate_test.c btf/mutate.c btf/mutate.h btf/btf.c btf/btf.h
	$(CC) $(CFLAGS) -o $@ btf/mutate_test.c btf/mutate.c btf/btf.c

.PHONY: signal-test
signal-test: fuzz/signal_edge_test
fuzz/signal_edge_test: fuzz/signal_edge_test.c fuzz/signal_edge.c fuzz/signal_edge.h
	$(CC) $(CFLAGS) -o $@ fuzz/signal_edge_test.c fuzz/signal_edge.c

.PHONY: types-test
types-test: syzlang/types_test
syzlang/types_test: syzlang/types_test.c syzlang/types.c syzlang/types.h btf/btf.c btf/btf.h
	$(CC) $(CFLAGS) -o $@ syzlang/types_test.c syzlang/types.c btf/btf.c

.PHONY: clean
clean:
	rm -f $(TARGET_EXE) $(TARGET_LIB) $(EXE_OBJS) syscall/x86_64/*.o syscall/aarch64/*.o btf/btf_test btf/mutate_test syzlang/types_test fuzz/signal_edge_test
	$(MAKE) -C syscall/sud clean 2>/dev/null || true
