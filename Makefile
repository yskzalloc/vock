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
all: $(TARGET_EXE) $(TARGET_LIB) sud-libs

$(TARGET_EXE): $(EXE_OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

$(TARGET_LIB): $(LIB_SOURCE)
	$(CC) $(CFLAGS) -shared -fPIC -o $@ $<

.PHONY: sud-libs
sud-libs:
	$(MAKE) -C syscall/sud CC=$(CC) || echo "[warn] SUD build failed (--syscall sud unavailable)"

