# vock
A lightweight, wrapper-based kernel coverage viewer for any command, powered by kcov and LD_PRELOAD.
You need root privileges to access `/sys/kernel/debug/kcov` and use the kernel's code coverage feature. You can find more information at the linux kernel document: [KCOV: code coverage for fuzzing](https://docs.kernel.org/dev-tools/kcov.html)
```
 $ make
 # make install
 # vock [--kernel-src PATH (default: $HOME/linux)] \
        [--vmlinux FILE (default: $HOME/linux/vmlinux] \
        [--filter Keyword (File paths by keyword)] \
        <target program>
```
I am using `vock` with [virtme-ng](https://github.com/arighi/virtme-ng) on a linux kernel that has CONFIG_KCOV and CONFIG_DEBUG_INFO enabled. This setup is the same as the one in the demo below.

![vock](https://github.com/user-attachments/assets/69531851-8776-42ed-82f9-dac937f089de)
