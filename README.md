# eBPF Go Solution Repo

This repository demonstrates how to use **eBPF with Go** to enforce network policies:

- **XDP program** (`drop_port.c`)  
  Drops TCP packets destined to a specific port using eXpress Data Path (XDP).
- **cgroup program** (`cgroup_allow_port.c`)  
  Restricts processes in a given cgroup to only bind/connect to a specific port.

Both examples use the [`cilium/ebpf`](https://github.com/cilium/ebpf) Go library.

---

## 📦 Requirements

### System

- Linux kernel **>= 5.8** (with eBPF, XDP, and cgroup v2 support)
- `clang` and `llvm` for compiling BPF programs
- `libbpf-dev` (optional, depending on distro)
- `make`, `gcc`, `pkg-config`

### Install on Ubuntu/Debian

```bash
sudo apt update
sudo apt install -y clang llvm libbpf-dev gcc make pkg-config
```

### Go

Go >= 1.25 (module system enabled)

Install Go:

```bash
wget https://go.dev/dl/go1.25.1.linux-amd64.tar.gz
sudo tar -C /usr/local -xzf go1.25.1.linux-amd64.tar.gz
export PATH=$PATH:/usr/local/go/bin
```

---

## 🔧 Build Instructions

Clone the repo:

```bash
git clone https://github.com/krisn2/ebpf-go-solution-repo.git
cd ebpf-go-solution-repo
```

Build everything:

```bash
make all
```

This will:

- Compile BPF programs (.c → .o)
- Build Go loaders into `bin/`:
  - `bin/xdp-loader`
  - `bin/cgroup-loader`

Clean build artifacts:

```bash
make clean
```

---

## 🚀 Usage

### 1. XDP Loader (Drop Port)

Attach an XDP program to an interface and drop packets to a given port.

```bash
cd bin
sudo ./xdp-loader -iface eth0 -port 8080
```

- Drops all TCP traffic on `eth0` going to port `8080`.
- Default port is `4040`.
- Detach by pressing `CTRL+C`.

### 2. Cgroup Loader (Allow Port)

Restrict processes in a cgroup so they can only bind/connect to one port.

**Create a cgroup:**

```bash
cd scripts
sudo ./create_cgroup.sh /sys/fs/cgroup/mygroup sleep 300
```

**Attach loader:**

```bash
cd bin
sudo ./cgroup-loader -cgroup /sys/fs/cgroup/mygroup -port 4040
```

- Processes inside `/sys/fs/cgroup/mygroup` can only use TCP port `4040`.
- Bind/connect to any other port will be denied.
- Detach with `CTRL+C`.

### 3. Test Script

Run the automated tests:

```bash
cd scripts
sudo ./test_cgroup.sh
```

It will check:

- Binding inside cgroup (allowed vs denied ports)
- Connecting inside cgroup (allowed vs denied ports)

---

## 🛠 Repository Structure

```
.
├── bpf/                # eBPF C programs
│   ├── cgroup_allow_port.c
│   └── drop_port.c
├── cmd/                # Go loaders
│   ├── cgroup-loader/
│   └── xdp-loader/
├── scripts/            # Helpers and test scripts
│   ├── create_cgroup.sh
│   └── test_cgroup.sh
├── Makefile            # Build automation
├── go.mod
└── go.sum
```

---

## 📖 Notes

- Requires root privileges to run loaders.
- You can check logs via:

```bash
sudo cat /sys/kernel/debug/tracing/trace_pipe
```

- If your kernel doesn't support cgroup v2, ensure it's mounted:

```bash
sudo mount -t cgroup2 none /sys/fs/cgroup
```

---

## ✅ Example

```bash
# Drop TCP traffic to 8080 on eth0
sudo ./bin/xdp-loader -iface eth0 -port 8080

#------OR-----

sudo ./bin/xdp-loader -iface lb -port 8080


# Restrict cgroup processes to port 4040
sudo ./bin/cgroup-loader -cgroup /sys/fs/cgroup/mygroup -port 4040
```