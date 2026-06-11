CC	= gcc
CLANG	= clang

LIBBPF_CFLAGS  = $(shell pkg-config --cflags libbpf 2>/dev/null || echo "-I/usr/include/bpf")
LIBBPF_LDFLAGS = $(shell pkg-config --libs   libbpf 2>/dev/null || echo "-lbpf")

BPF_CFLAGS = \
    -target bpf \
    -O2 \
    -g \
    -Wall \
    -Wextra \
    -Wno-unused-parameter \
    -I/usr/include \
    -I/usr/include/x86_64-linux-gnu \
    $(LIBBPF_CFLAGS)

USER_CFLAGS  = -O2 -Wall -Wextra -Wno-unused-parameter $(LIBBPF_CFLAGS)
USER_LDFLAGS = $(LIBBPF_LDFLAGS) -lelf -lz

BPF_SRC  = e5_kern.bpf.c
BPF_OBJ  = e5_kern.bpf.o
USER_SRC = e5_user.c
USER_BIN = e5_user

.PHONY: all clean

all: $(BPF_OBJ) $(USER_BIN)
	@echo ""
	@echo "Build successful!"
	@echo "Run: sudo ./e5_user <interface>"

$(BPF_OBJ): $(BPF_SRC) common.h
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

$(USER_BIN): $(USER_SRC) common.h
	$(CC) $(USER_CFLAGS) $< -o $@ $(USER_LDFLAGS)

clean:
	rm -f $(BPF_OBJ) $(USER_BIN)
	@echo "Cleaned."
