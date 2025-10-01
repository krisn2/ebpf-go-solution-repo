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

	// 1. Set the allowed port in the map
	m, ok := coll.Maps["allowed_port"]
	if !ok {
		log.Fatalf("map allowed_port not found in object")
	}

	var key uint32 = 0
	var p uint16 = uint16(*port)
	if err := m.Put(key, p); err != nil {
		log.Fatalf("failed to set allowed port: %v", err)
	}

	// 2. Attach cgroup/connect4 program (for OUTGOING traffic)
	progV4, ok := coll.Programs["cgroup_allow_port_v4"]
	if !ok {
		log.Fatalf("program cgroup_allow_port_v4 not found")
	}

	lnk4, err := link.AttachCgroup(link.CgroupOptions{
		Path:    *cgroupPath,
		Program: progV4,
		Attach:  ebpf.AttachCGroupInet4Connect,
	})
	if err != nil {
		log.Fatalf("failed to attach cgroup/connect4 program: %v", err)
	}
	defer lnk4.Close()

	// 3. Attach cgroup/bind4 program (for INCOMING/SERVER traffic)
	progBind4, ok := coll.Programs["cgroup_allow_port_bind4"]
	if !ok {
		log.Fatalf("program cgroup_allow_port_bind4 not found")
	}

	lnkBind4, err := link.AttachCgroup(link.CgroupOptions{
		Path:    *cgroupPath,
		Program: progBind4,
		Attach:  ebpf.AttachCGroupInet4Bind,
	})
	if err != nil {
		log.Fatalf("failed to attach cgroup/bind4 program: %v", err)
	}
	defer lnkBind4.Close()

	fmt.Printf("cgroup filters attached to %s allowing TCP port %d\n", *cgroupPath, *port)
	fmt.Printf("Attached: connect4 (outgoing client) and bind4 (incoming server)\n")

	// Keep the program running until interrupted
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
	fmt.Println("detaching...")
}
