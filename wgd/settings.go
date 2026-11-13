package main

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strings"
)

// settings are the daemon's own options, kept in settings.json next to the
// WireGuard configuration.
type settings struct {
	// WebAddr is where the status page listens.
	WebAddr string `json:"webAddr"`
	// ExposeTCP forwards every TCP connection that arrives through the tunnel
	// to the same port on the console (127.0.0.1), unless the port is in
	// BlockedTCPPorts.
	ExposeTCP       bool     `json:"exposeTCP"`
	BlockedTCPPorts []uint16 `json:"blockedTCPPorts"`
	// UDPPorts are relayed from the tunnel to the same port on the console.
	// The default is PS5 Remote Play plus a Sunshine host on the console.
	UDPPorts []uint16 `json:"udpPorts"`
	// AllowFrom limits who may reach the console's services through the
	// tunnel: empty means any address the peers' AllowedIPs let in.
	AllowFrom []string `json:"allowFrom"`
	// Forwards let apps on the console reach hosts behind the tunnel: a
	// listener on the console relays to a target inside the tunnel.
	Forwards []forwardRule `json:"forwards"`
	// DNSServers resolve peer endpoints given as host names. Empty means:
	// a DNS payload on the console, then public resolvers.
	DNSServers []string `json:"dnsServers"`
	// Priority is "low" (default, never competes with games) or "high".
	Priority string `json:"priority"`
	// Verbose adds wireguard-go's own messages to the log.
	Verbose bool `json:"verbose"`
}

type forwardRule struct {
	Proto  string `json:"proto"`  // "tcp" or "udp"
	Listen string `json:"listen"` // e.g. "127.0.0.1:8022"
	Target string `json:"target"` // e.g. "10.8.0.2:22"
}

func defaultSettings() settings {
	return settings{
		WebAddr:         ":8091",
		ExposeTCP:       true,
		BlockedTCPPorts: []uint16{},
		UDPPorts:        []uint16{9295, 9296, 9297, 9302, 47998, 47999, 48000},
		AllowFrom:       []string{},
		Forwards:        []forwardRule{},
		DNSServers:      []string{},
		Priority:        "low",
	}
}

func (s *settings) validate() error {
	if _, _, err := net.SplitHostPort(s.WebAddr); err != nil {
		return fmt.Errorf("webAddr: %v", err)
	}
	for _, f := range s.Forwards {
		if f.Proto != "tcp" && f.Proto != "udp" {
			return fmt.Errorf("forward %s: proto must be tcp or udp", f.Listen)
		}
		if _, _, err := net.SplitHostPort(f.Listen); err != nil {
			return fmt.Errorf("forward listen %q: %v", f.Listen, err)
		}
		if _, _, err := net.SplitHostPort(f.Target); err != nil {
			return fmt.Errorf("forward target %q: %v", f.Target, err)
		}
	}
	for _, a := range s.AllowFrom {
		if _, err := parsePrefix(a); err != nil {
			return fmt.Errorf("allowFrom %q: %v", a, err)
		}
	}
	if s.Priority != "" && s.Priority != "low" && s.Priority != "high" {
		return fmt.Errorf("priority must be low or high")
	}
	return nil
}

func parseSettings(b []byte) (settings, error) {
	s := defaultSettings()
	dec := json.NewDecoder(strings.NewReader(string(b)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&s); err != nil {
		return defaultSettings(), err
	}
	if err := s.validate(); err != nil {
		return defaultSettings(), err
	}
	return s, nil
}

// loadSettings reads the settings file, writing the defaults if there is none.
func loadSettings(path string) (settings, error) {
	b, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		s := defaultSettings()
		return s, saveSettings(path, s)
	}
	if err != nil {
		return defaultSettings(), err
	}
	return parseSettings(b)
}

func saveSettings(path string, s settings) error {
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	return writeFileAtomic(path, append(b, '\n'), 0o644)
}

func writeFileAtomic(path string, b []byte, mode os.FileMode) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, mode); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
