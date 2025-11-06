package kernel

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
)

// SSHEvent matches the C struct ssh_event from common.h
// Layout: IP (4) + Port (2) + padding (2) + PID (4) + EventType (1) + padding (3) + Timestamp (8) = 24 bytes
type SSHEvent struct {
	IP        uint32
	Port      uint16
	_         [2]byte // padding to align PID
	PID       uint32
	EventType uint8
	_         [3]byte // padding to align Timestamp
	Timestamp uint64
}

type TCPEvent struct {
	SrcIP     uint32
	DstIP     uint32
	SrcPort   uint16
	DstPort   uint16
	EventType uint8
	_         [3]byte // padding
	Timestamp uint64
}

type Loader struct {
	collection *ebpf.Collection
	links      []link.Link
	sshEvents  *perf.Reader
	tcpEvents  *perf.Reader
}

func NewLoader() (*Loader, error) {
	return &Loader{
		links: []link.Link{},
	}, nil
}

func (l *Loader) LoadCPrograms() error {
	// Try multiple possible locations for the kernel program object file
	paths := []string{
		"/usr/local/lib/secrds/ssh_kprobe.bpf.o",
		filepath.Join("secrds-programs", "ssh_kprobe.bpf.o"),
		filepath.Join("..", "secrds-programs", "ssh_kprobe.bpf.o"),
		filepath.Join("../../secrds-programs", "ssh_kprobe.bpf.o"),
	}

	var spec *ebpf.CollectionSpec
	var err error

	for _, path := range paths {
		if _, err := os.Stat(path); os.IsNotExist(err) {
			continue
		}

		spec, err = ebpf.LoadCollectionSpec(path)
		if err == nil {
			fmt.Printf("Loaded kernel program from: %s\n", path)
			break
		}
	}

	if spec == nil {
		return fmt.Errorf("SSH kernel program object file not found in any expected location")
	}

	// Load the collection
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return fmt.Errorf("failed to load kernel program collection: %w", err)
	}
	l.collection = coll

	// Attach kprobe for inet_csk_accept (incoming connections on server)
	// This is CRITICAL for detecting incoming SSH connections
	acceptAttached := false
	if acceptProg := coll.Programs["ssh_kprobe_accept"]; acceptProg != nil {
		kpAccept, err := link.Kprobe("inet_csk_accept", acceptProg, nil)
		if err != nil {
			fmt.Printf("ERROR: failed to attach kprobe inet_csk_accept: %v\n", err)
			fmt.Printf("WARNING: Incoming SSH connections may not be detected!\n")
			fmt.Printf("This kernel symbol may not be available. Check with: cat /proc/kallsyms | grep inet_csk_accept\n")
			
			// Try alternative: tcp_v4_syn_recv_sock (called when server receives SYN)
			fmt.Printf("Trying alternative: tcp_v4_syn_recv_sock...\n")
			if altProg, altErr := link.Kprobe("tcp_v4_syn_recv_sock", acceptProg, nil); altErr == nil {
				l.links = append(l.links, altProg)
				fmt.Println("Attached kprobe to tcp_v4_syn_recv_sock (alternative for incoming connections)")
				acceptAttached = true
			} else {
				fmt.Printf("Alternative also failed: %v\n", altErr)
				fmt.Printf("CRITICAL: No incoming connection detection available!\n")
			}
		} else {
			l.links = append(l.links, kpAccept)
			fmt.Println("Attached kprobe to inet_csk_accept (incoming connections)")
			acceptAttached = true
		}
	}
	
	if !acceptAttached {
		fmt.Printf("\n")
		fmt.Printf("=================================================================\n")
		fmt.Printf("WARNING: Incoming connection detection is NOT working!\n")
		fmt.Printf("Only outgoing connections will be detected.\n")
		fmt.Printf("To fix this, ensure your kernel exports inet_csk_accept symbol.\n")
		fmt.Printf("Check: cat /proc/kallsyms | grep inet_csk_accept\n")
		fmt.Printf("=================================================================\n")
		fmt.Printf("\n")
	}

	// Attach kprobe for tcp_v4_connect (outgoing connections)
	// Try different possible program names
	progNames := []string{"ssh_kprobe_tcp_connect", "ssh_kprobe_execve", "ssh_tracepoint_write"}
	var kprobeProg *ebpf.Program
	
	for _, name := range progNames {
		if prog := coll.Programs[name]; prog != nil {
			kprobeProg = prog
			fmt.Printf("Found kernel program: %s\n", name)
			break
		}
	}

	if kprobeProg == nil {
		// List available programs for debugging
		fmt.Println("Available kernel programs:")
		for name := range coll.Programs {
			fmt.Printf("  - %s\n", name)
		}
		return fmt.Errorf("no suitable SSH kernel program found")
	}

	kp, err := link.Kprobe("tcp_v4_connect", kprobeProg, nil)
	if err != nil {
		return fmt.Errorf("failed to attach kprobe tcp_v4_connect: %w", err)
	}
	l.links = append(l.links, kp)
	fmt.Println("Attached kprobe to tcp_v4_connect (outgoing connections)")

	// Open perf event array for SSH events
	sshMap := coll.Maps["ssh_events"]
	if sshMap == nil {
		return fmt.Errorf("ssh_events map not found")
	}

	sshReader, err := perf.NewReader(sshMap, 4096)
	if err != nil {
		return fmt.Errorf("failed to create SSH perf reader: %w", err)
	}
	l.sshEvents = sshReader

	fmt.Println("Kernel programs loaded successfully")
	return nil
}

func (l *Loader) GetSSHEvents() *perf.Reader {
	return l.sshEvents
}

func (l *Loader) GetTCPEvents() *perf.Reader {
	return l.tcpEvents
}

func (l *Loader) Close() error {
	for _, lnk := range l.links {
		lnk.Close()
	}
	if l.sshEvents != nil {
		l.sshEvents.Close()
	}
	if l.tcpEvents != nil {
		l.tcpEvents.Close()
	}
	if l.collection != nil {
		l.collection.Close()
	}
	return nil
}

