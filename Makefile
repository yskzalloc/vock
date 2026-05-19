CC ?= clang
CFLAGS += -Wall -O2
LDFLAGS += -lm

DEBUG_INFO_BTF ?= $(shell [ -e /sys/kernel/btf/vmlinux ] && echo 1 || echo 0)
EBPF ?= 0

ifeq ($(EBPF),1)
  CFLAGS += -DVOCK_EBPF_ENABLED=1
  LDFLAGS += -lbpf -lelf -lz
endif

TOOL_NAME = vock
TARGET_EXE = vock
EXE_SOURCES = vock.c mode/hw.c mode/pt_decode.c mode/amd_lbr.c syscall/ptrace/ptrace.c syscall/sud/sud.c syscall/ebpf/ebpf.c syscall/decode.c syzlang/syzlang.c fuzz/fuzz.c fuzz/covset.c fuzz/signal.c fuzz/mutate.c fuzz/state.c prog2c/prog2c.c execprog/execprog.c
EXE_OBJS = vock.o mode/hw.o mode/pt_decode.o mode/amd_lbr.o syscall/ptrace/ptrace.o syscall/sud/sud.o syscall/ebpf/ebpf.o syscall/decode.o syzlang/syzlang.o fuzz/fuzz.o fuzz/covset.o fuzz/signal.o fuzz/mutate.o fuzz/state.o prog2c/prog2c.o execprog/execprog.o

ARCH := $(shell uname -m)
ifeq ($(ARCH),aarch64)
  EXE_SOURCES += syscall/aarch64/sys.c syscall/aarch64/decode.c
  EXE_OBJS += syscall/aarch64/sys.o syscall/aarch64/decode.o
else
  EXE_SOURCES += syscall/x86_64/sys.c syscall/x86_64/decode.c
  EXE_OBJS += syscall/x86_64/sys.o syscall/x86_64/decode.o
endif
TARGET_LIB = mode/kcov.so
LIB_SOURCE = mode/kcov.c
BPF_SRC = syscall.bpf.c
BPF_OBJ = syscall.bpf.o
INSTALL_DIR = /usr/local/lib/$(TOOL_NAME)
BIN_DIR = /usr/local/bin

ifeq ($(DEBUG_INFO_BTF),1)
  CFLAGS += -DDEBUG_INFO_BTF=1
  BUILD_BPF := 1
else
  BUILD_BPF := 0
endif

.PHONY: all
all: $(TARGET_EXE) $(TARGET_LIB) $(if $(filter 1,$(BUILD_BPF)),$(BPF_OBJ)) sud-libs $(if $(filter 1,$(EBPF)),ebpf-gen)

.PHONY: sud-libs
sud-libs:
	$(MAKE) -C syscall/sud CC=$(CC)

.PHONY: ebpf-gen
ebpf-gen:
	$(MAKE) -C syscall/ebpf generate

$(TARGET_EXE): $(EXE_OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

$(TARGET_LIB): $(LIB_SOURCE)
	$(CC) $(CFLAGS) -shared -fPIC -o $@ $<

ifeq ($(BUILD_BPF),1)
$(BPF_OBJ): $(BPF_SRC) vmlinux.h
	clang -O2 -g -target bpf -c $< -o $@

vmlinux.h:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > $@
endif

.PHONY: install
install: all
	@echo "Installing $(TOOL_NAME)..."
	sudo mkdir -p $(INSTALL_DIR)
	sudo cp $(TARGET_EXE) $(TARGET_LIB) output.py mode/ $(INSTALL_DIR)/
	sudo cp -r report/ $(INSTALL_DIR)/
ifneq ($(BUILD_BPF),0)
	sudo cp $(BPF_OBJ) $(INSTALL_DIR)/
endif
	sudo ln -sf $(INSTALL_DIR)/$(TARGET_EXE) $(BIN_DIR)/$(TOOL_NAME)
	@echo "Installed."

.PHONY: uninstall
uninstall:
	sudo rm -f $(BIN_DIR)/$(TOOL_NAME)
	sudo rm -rf $(INSTALL_DIR)

.PHONY: clean
clean:
	rm -f $(TARGET_EXE) $(TARGET_LIB) $(EXE_OBJS) $(BPF_OBJ) vmlinux.h
	$(MAKE) -C syscall/sud clean
