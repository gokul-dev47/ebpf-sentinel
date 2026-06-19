// Package hiding - network hiding DETECTION utilities.
// Detects when network connection hiding is active. Contains NO hiding logic.
package hiding

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
)

// ConnectionEntry represents a single TCP/UDP connection from procfs.
type ConnectionEntry struct {
	LocalIP    net.IP
	RemoteIP   net.IP
	LocalPort  uint16
	RemotePort uint16
	State      string
	Protocol   string
}

// NetworkHidingIndicator describes evidence of active connection hiding.
type NetworkHidingIndicator struct {
	Technique  string          `json:"technique"`
	Evidence   string          `json:"evidence"`
	Connection ConnectionEntry `json:"connection,omitempty"`
	Confidence float64         `json:"confidence"`
	Timestamp  time.Time       `json:"timestamp"`
}

// NetworkHidingDetector detects network connection hiding techniques.
type NetworkHidingDetector struct{ log *logrus.Logger }

// NewNetworkHidingDetector creates a new detector.
func NewNetworkHidingDetector(log *logrus.Logger) *NetworkHidingDetector {
	return &NetworkHidingDetector{log: log}
}

// DetectListeningPortMismatch checks for ports that accept connections
// but don't appear in /proc/net/tcp.
func (d *NetworkHidingDetector) DetectListeningPortMismatch(portsToCheck []uint16) ([]NetworkHidingIndicator, error) {
	procConns, err := d.readProcNetTCP("/proc/net/tcp")
	if err != nil {
		return nil, fmt.Errorf("reading /proc/net/tcp: %w", err)
	}

	listeningInProc := make(map[uint16]bool)
	for _, c := range procConns {
		if c.State == "0A" { // LISTEN
			listeningInProc[c.LocalPort] = true
		}
	}

	var indicators []NetworkHidingIndicator
	now := time.Now()
	for _, port := range portsToCheck {
		if listeningInProc[port] {
			continue
		}
		conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 100*time.Millisecond)
		if err == nil {
			conn.Close()
			indicators = append(indicators, NetworkHidingIndicator{
				Technique: "listening_port_hidden",
				Evidence: fmt.Sprintf("port %d accepts connections but absent from /proc/net/tcp",
					port),
				Confidence: 0.90,
				Timestamp:  now,
			})
		}
	}
	return indicators, nil
}

// ReadProcNetTCP parses /proc/net/tcp into connection entries.
func (d *NetworkHidingDetector) ReadProcNetTCP(path string) ([]ConnectionEntry, error) {
	return d.readProcNetTCP(path)
}

func (d *NetworkHidingDetector) readProcNetTCP(path string) ([]ConnectionEntry, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var conns []ConnectionEntry
	scanner := bufio.NewScanner(f)
	first := true
	for scanner.Scan() {
		if first {
			first = false
			continue
		}
		conn, err := parseTCPLine(scanner.Text())
		if err != nil {
			continue
		}
		conns = append(conns, conn)
	}
	return conns, scanner.Err()
}

func parseTCPLine(line string) (ConnectionEntry, error) {
	fields := strings.Fields(line)
	if len(fields) < 4 {
		return ConnectionEntry{}, fmt.Errorf("too few fields")
	}
	local, localPort, err := parseAddrPort(fields[1])
	if err != nil {
		return ConnectionEntry{}, err
	}
	remote, remotePort, err := parseAddrPort(fields[2])
	if err != nil {
		return ConnectionEntry{}, err
	}
	return ConnectionEntry{
		LocalIP: local, LocalPort: localPort,
		RemoteIP: remote, RemotePort: remotePort,
		State: fields[3], Protocol: "tcp",
	}, nil
}

func parseAddrPort(s string) (net.IP, uint16, error) {
	parts := strings.SplitN(s, ":", 2)
	if len(parts) != 2 {
		return nil, 0, fmt.Errorf("invalid addr:port %q", s)
	}
	addrBytes, err := hex.DecodeString(parts[0])
	if err != nil {
		return nil, 0, err
	}
	port64, err := strconv.ParseUint(parts[1], 16, 16)
	if err != nil {
		return nil, 0, err
	}
	var ip net.IP
	if len(addrBytes) == 4 {
		ip = net.IP{addrBytes[3], addrBytes[2], addrBytes[1], addrBytes[0]}
	} else {
		ip = net.IP(addrBytes)
	}
	return ip, uint16(port64), nil
}
