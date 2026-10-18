package syscalls

import (
	"encoding/binary"
	"fmt"
	"net"
	"syscall"
	"testing"
	"time"

	"golinux/internal/consts"
	"golinux/internal/fds"
)

type socketTestProc struct {
	Proc
	fdTable *fds.Table
	memory  []byte
}

func (p *socketTestProc) Fds() *fds.Table { return p.fdTable }

func (p *socketTestProc) MemRead(addr uint64, size int) ([]byte, error) {
	if size < 0 || addr > uint64(len(p.memory)) || uint64(size) > uint64(len(p.memory))-addr {
		return nil, fmt.Errorf("invalid guest read")
	}
	out := make([]byte, size)
	copy(out, p.memory[int(addr):int(addr)+size])
	return out, nil
}

func (p *socketTestProc) MemWrite(addr uint64, data []byte) error {
	if addr > uint64(len(p.memory)) || uint64(len(data)) > uint64(len(p.memory))-addr {
		return fmt.Errorf("invalid guest write")
	}
	copy(p.memory[int(addr):int(addr)+len(data)], data)
	return nil
}

func TestRecvfromForwardsFlagsAndSourceAddress(t *testing.T) {
	server, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	server.SetReadDeadline(time.Now().Add(3 * time.Second))

	proc := &socketTestProc{fdTable: fds.NewTable(), memory: make([]byte, 1024)}
	defer proc.fdTable.CloseAll()
	fd, err := sysSocket(proc, consts.AF_INET, consts.SOCK_DGRAM, 0, 0, 0, 0)
	if err != nil || fd < 0 {
		t.Fatalf("socket() = %d, %v", fd, err)
	}
	guestFD := int(fd)
	defer proc.fdTable.Close(guestFD)

	dest := make([]byte, 16)
	binary.LittleEndian.PutUint16(dest[0:2], consts.AF_INET)
	binary.BigEndian.PutUint16(dest[2:4], uint16(server.LocalAddr().(*net.UDPAddr).Port))
	copy(dest[4:8], net.IPv4(127, 0, 0, 1).To4())
	if err := proc.MemWrite(0x80, dest); err != nil {
		t.Fatal(err)
	}
	if err := proc.MemWrite(0x40, []byte("query")); err != nil {
		t.Fatal(err)
	}
	if n, err := sysSendto(proc, uint64(guestFD), 0x40, 5, 0, 0x80, uint64(len(dest))); err != nil || n != 5 {
		t.Fatalf("sendto() = %d, %v; want 5, nil", n, err)
	}

	incoming := make([]byte, 64)
	n, peer, err := server.ReadFromUDP(incoming)
	if err != nil {
		t.Fatal(err)
	}
	if got := string(incoming[:n]); got != "query" {
		t.Fatalf("server received %q, want %q", got, "query")
	}
	if _, err := server.WriteToUDP([]byte("response"), peer); err != nil {
		t.Fatal(err)
	}
	if err := syscall.SetsockoptTimeval(proc.fdTable.Get(guestFD).(*GuestSocket).f.fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &syscall.Timeval{Sec: 3}); err != nil {
		t.Fatal(err)
	}

	if err := proc.MemWrite(0x180, make([]byte, 4)); err != nil {
		t.Fatal(err)
	}
	binary.LittleEndian.PutUint32(proc.memory[0x180:0x184], 16)
	got, err := sysRecvfrom(proc, uint64(guestFD), 0x100, 3, uint64(syscall.MSG_TRUNC), 0x140, 0x180)
	if err != nil {
		t.Fatal(err)
	}
	if got != int64(len("response")) {
		t.Fatalf("recvfrom() = %d, want full datagram length %d", got, len("response"))
	}
	if got := string(proc.memory[0x100:0x103]); got != "res" {
		t.Fatalf("guest receive buffer = %q, want %q", got, "res")
	}
	if family := binary.LittleEndian.Uint16(proc.memory[0x140:0x142]); family != consts.AF_INET {
		t.Fatalf("source address family = %d, want AF_INET", family)
	}
	if addrLen := binary.LittleEndian.Uint32(proc.memory[0x180:0x184]); addrLen != 16 {
		t.Fatalf("source address length = %d, want 16", addrLen)
	}
}

func TestRecvfromAllowsZeroLengthBuffer(t *testing.T) {
	server, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()

	proc := &socketTestProc{fdTable: fds.NewTable(), memory: make([]byte, 256)}
	defer proc.fdTable.CloseAll()
	fd, err := sysSocket(proc, consts.AF_INET, consts.SOCK_DGRAM, 0, 0, 0, 0)
	if err != nil || fd < 0 {
		t.Fatalf("socket() = %d, %v", fd, err)
	}
	guestFD := int(fd)
	defer proc.fdTable.Close(guestFD)

	dest := make([]byte, 16)
	binary.LittleEndian.PutUint16(dest[0:2], consts.AF_INET)
	binary.BigEndian.PutUint16(dest[2:4], uint16(server.LocalAddr().(*net.UDPAddr).Port))
	copy(dest[4:8], net.IPv4(127, 0, 0, 1).To4())
	if err := proc.MemWrite(0x40, dest); err != nil {
		t.Fatal(err)
	}
	if n, err := sysSendto(proc, uint64(guestFD), 0, 0, 0, 0x40, uint64(len(dest))); err != nil || n != 0 {
		t.Fatalf("sendto(empty datagram) = %d, %v; want 0, nil", n, err)
	}
	incoming := make([]byte, 1)
	if _, peer, err := server.ReadFromUDP(incoming); err != nil {
		t.Fatal(err)
	} else if _, err := server.WriteToUDP(nil, peer); err != nil {
		t.Fatal(err)
	}
	if err := syscall.SetsockoptTimeval(proc.fdTable.Get(guestFD).(*GuestSocket).f.fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &syscall.Timeval{Sec: 3}); err != nil {
		t.Fatal(err)
	}
	if n, err := sysRecvfrom(proc, uint64(guestFD), 0x80, 0, 0, 0, 0); err != nil || n != 0 {
		t.Fatalf("recvfrom(empty datagram) = %d, %v; want 0, nil", n, err)
	}
}
