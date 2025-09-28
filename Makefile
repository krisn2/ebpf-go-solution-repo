BPF_DIR=bpf
BIN_DIR=bin
GO_CMD=go
CLANG=clang
BPF_CFLAGS=-O2 -target bpf -g 

.PHONY: all build-bpf build-go clean

all: build-bpf build-go

build-bpf:
	$(CLANG) $(BPF_CFLAGS) -c $(BPF_DIR)/drop_port.c -o $(BPF_DIR)/drop_port.o
	$(CLANG) $(BPF_CFLAGS) -c $(BPF_DIR)/cgroup_allow_port.c -o $(BPF_DIR)/cgroup_allow_port.o

build-go:
	$(GO_CMD) build -o $(BIN_DIR)/xdp-loader ./cmd/xdp-loader
	$(GO_CMD) build -o $(BIN_DIR)/cgroup-loader ./cmd/cgroup-loader

clean:
	rm -f $(BPF_DIR)/*.o
	rm -rf $(BIN_DIR)

