CC      := clang
CFLAGS  := -std=gnu11 -Wall -O3 -fPIC -march=native -D_GNU_SOURCE -I.
ASFLAGS := $(CFLAGS) -x assembler-with-cpp
SETUP_CFLAGS := -std=gnu11 -Wall -O3 -fPIC -march=native -D_GNU_SOURCE -I. \
                -ffreestanding -nostdlib -nodefaultlibs \
                -mno-sse -mno-avx -mno-mmx -msoft-float

.PHONY: all clean

all: liblazypoline.so libbootstrap.so

# lazypoline shared library
LAZYPOLINE_OBJS = sud_core.o zpoline.o lazypoline.o syscall_names.o \
                  virtualize_signals.o asm_syscall_hook.o \
                  restore_selector_trampoline.o setup_new_thread.o

liblazypoline.so: $(LAZYPOLINE_OBJS)
	$(CC) -shared -O3 -o $@ $^ -lpthread

libbootstrap.so: bootstrap.o
	$(CC) -shared -O3 -o $@ $^ -ldl

# Object rules
sud_core.o: sud_core.c
	$(CC) $(CFLAGS) -c -o $@ $<

zpoline.o: zpoline.c
	$(CC) $(CFLAGS) -c -o $@ $<

lazypoline.o: lazypoline.c
	$(CC) $(CFLAGS) -c -o $@ $<

syscall_names.o: syscall_names.c
	$(CC) $(CFLAGS) -c -o $@ $<

virtualize_signals.o: virtualize_signals.c
	$(CC) $(CFLAGS) -c -o $@ $<

setup_new_thread.o: setup_new_thread.c
	$(CC) $(SETUP_CFLAGS) -c -o $@ $<

bootstrap.o: bootstrap.c
	$(CC) $(CFLAGS) -c -o $@ $<

asm_syscall_hook.o: asm_syscall_hook.S
	$(CC) $(ASFLAGS) -c -o $@ $<

restore_selector_trampoline.o: restore_selector_trampoline.S
	$(CC) $(ASFLAGS) -c -o $@ $<

clean:
	rm -f *.o *.so
