package main

import (
    "flag"
    "fmt"
    "log"
    "net"
    "os"
    "os/signal"
    "path/filepath"
    "syscall"

    "github.com/cilium/ebpf"
    "github.com/cilium/ebpf/link"
)



func main() {
iface := flag.String("iface", "eth0", "network interface to attach XDP program")
port := flag.Uint("port", 4040, "destination TCP port to drop")
obj := flag.String("obj", filepath.Join("..", "bpf", "drop_port.o"), "path to bpf object")
flag.Parse()


spec, err := ebpf.LoadCollectionSpec(*obj)
if err != nil {
log.Fatalf("failed to load bpf spec: %v", err)
}


coll, err := ebpf.NewCollection(spec)
if err != nil {
log.Fatalf("failed to create collection: %v", err)
}
defer coll.Close()


m, ok := coll.Maps["blocked_port"]
if !ok {
log.Fatalf("map blocked_port not found in object")
}


var key uint32 = 0
// store in host byte order (map value is u16 host order expected in loader)
var p uint16 = uint16(*port)
if err := m.Put(key, p); err != nil {
log.Fatalf("failed to set port: %v", err)
}


prog, ok := coll.Programs["xdp_drop_port"]
if !ok {
log.Fatalf("program xdp_drop_port not found")
}


ifaceObj, err := net.InterfaceByName(*iface)
if err != nil {
    log.Fatalf("could not find iface %s: %v", *iface, err)
}

lnk, err := link.AttachXDP(link.XDPOptions{
    Program:   prog,
    Interface: ifaceObj.Index, // <-- use the index, not *iface
})
if err != nil {
    log.Fatalf("failed to attach xdp: %v", err)
}
defer lnk.Close()



fmt.Printf("XDP drop attached on interface %s dropping tcp dest port %d\n", *iface, *port)


sig := make(chan os.Signal, 1)
signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
<-sig
fmt.Println("detaching...")
}
