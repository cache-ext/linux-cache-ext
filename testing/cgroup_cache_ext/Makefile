# Define the compiler and the flags
CLANG ?= clang
BPFTOOL ?= bpftool
CFLAGS = -O2 -target bpf -c -g
USERSPACE_CFLAGS = -O2
USERSPACE_LINKER_FLAGS = -L/usr/local/lib64 -lbpf

# Userspace programs
USERSPACE_SRC = cgroup_cache_ext.c
USERSPACE_BIN = $(USERSPACE_SRC:.c=.out)
# Define the BPF program source and the output object file
BPF_SRC = basic.bpf.c
BPF_OBJ = $(BPF_SRC:.c=.o)
BPF_SKEL = $(BPF_SRC:bpf.c=skel.h)

VMLINUX_H = vmlinux.h

# Get Clang's default includes on this system. We'll explicitly add these dirs
# to the includes list when compiling with `-target bpf` because otherwise some
# architecture-specific dirs will be "missing" on some architectures/distros -
# headers such as asm/types.h, asm/byteorder.h, asm/socket.h, asm/sockios.h,
# sys/cdefs.h etc. might be missing.
#
# Use '-idirafter': Don't interfere with include mechanics except where the
# build would have failed anyways.
CLANG_BPF_SYS_INCLUDES ?= $(shell $(CLANG) -v -E - </dev/null 2>&1 \
	| sed -n '/<...> search starts here:/,/End of search list./{ s| \(/.*\)|-idirafter \1|p }')


all: $(BPF_OBJ) $(BPF_SKEL) $(USERSPACE_BIN)

$(VMLINUX_H):
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $(VMLINUX_H)

$(BPF_OBJ): $(BPF_SRC) $(VMLINUX_H)
	$(CLANG) $(CFLAGS) $(CLANG_BPF_SYS_INCLUDES) $(BPF_SRC) -o $(BPF_OBJ)

$(BPF_SKEL): $(BPF_OBJ)
	$(BPFTOOL) gen skeleton $(BPF_OBJ) > $(BPF_SKEL)

$(USERSPACE_BIN): $(USERSPACE_SRC) $(BPF_SKEL)
	$(CLANG) $(USERSPACE_CFLAGS) $(USERSPACE_SRC) -o $(USERSPACE_BIN) $(USERSPACE_LINKER_FLAGS)


clean:
	rm -f $(BPF_OBJ) $(USERSPACE_BIN) $(BPF_SKEL) $(VMLINUX_H)

.PHONY: all clean
