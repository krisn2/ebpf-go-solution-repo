package main

import (
"flag"
"fmt"
"log"
"os"
"os/signal"
"path/filepath"
"syscall"


"github.com/cilium/ebpf"
"github.com/cilium/ebpf/link"
)


func main() {
cgroupPath := flag.String("cgroup", "", "path to cgroup v2 or cgroup v1 net_cls cgroup")
port := flag.Uint("port", 4040, "allowed TCP port for processes in the cgroup")
obj := flag.String("obj", filepath.Join("..", "bpf", "cgroup_allow_port.o"), "path to bpf object")
flag.Parse()


if *cgroupPath == "" {
log.Fatal("must provide -cgroup path")
}


spec, err := ebpf.LoadCollectionSpec(*obj)
if err != nil {
log.Fatalf("failed to load bpf spec: %v", err)
}


coll, err := ebpf.NewCollection(spec)
if err != nil {
log.Fatalf("failed to create collection: %v", err)
}
defer coll.Close()


m, ok := coll.Maps["allowed_port"]
if !ok {
log.Fatalf("map allowed_port not found in object")
}


var key uint32 = 0
var p uint16 = uint16(*port)
if err := m.Put(key, p); err != nil {
log.Fatalf("failed to set allowed port: %v", err)
}


prog, ok := coll.Programs["allow_only_port"]
if !ok {
log.Fatalf("program allow_only_port not found")
}


lnk, err := link.AttachCgroup(link.CgroupOptions{Path: *cgroupPath, Program: prog})
if err != nil {
log.Fatalf("failed to attach cgroup program: %v", err)
}
defer lnk.Close()


fmt.Printf("cgroup filter attached to %s allowing port %d\n", *cgroupPath, *port)


sig := make(chan os.Signal, 1)
signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
<-sig
fmt.Println("detaching...")
}
