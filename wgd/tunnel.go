package main

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"

	"ps5wireguard/netstack"
)

// tunnel is one running WireGuard device with its userspace network stack.
// The PS5 kernel has no tun device, so the tunnel lives entirely inside this
// process: connections arriving through it are relayed to the console's own
// services on 127.0.0.1, and local forwards let console apps reach hosts
// behind it.
type tunnel struct {
	cfg  *wgConfig
	dev  *device.Device
	tnet *netstack.Net
	logf func(string, ...any)

	opts func() settings // current settings, read per connection

	mu       sync.Mutex
	resolved map[string]netip.AddrPort // endpoint as written -> last address used
}

func startTunnel(cfg *wgConfig, opts func() settings, logf func(string, ...any), verbose bool) (*tunnel, error) {
	var local []netip.Addr
	for _, p := range cfg.Addresses {
		local = append(local, p.Addr())
	}
	tdev, tnet, err := netstack.CreateNetTUN(local, cfg.DNS, cfg.MTU)
	if err != nil {
		return nil, fmt.Errorf("netstack: %w", err)
	}
	lg := &device.Logger{
		Verbosef: func(string, ...any) {},
		Errorf:   func(f string, a ...any) { logf("wg: "+f, a...) },
	}
	if verbose {
		lg.Verbosef = func(f string, a ...any) { logf("wg: "+f, a...) }
	}
	t := &tunnel{cfg: cfg, tnet: tnet, logf: logf, opts: opts, resolved: map[string]netip.AddrPort{}}
	t.dev = device.NewDevice(tdev, conn.NewDefaultBind(), lg)

	uapi, errs := cfg.uapi(t.resolve)
	for _, e := range errs {
		logf("%v (will retry)", e)
	}
	if err := t.dev.IpcSet(uapi); err != nil {
		t.dev.Close()
		return nil, fmt.Errorf("configuring device: %w", err)
	}
	t.installForwarders()
	if err := t.dev.Up(); err != nil {
		t.dev.Close()
		return nil, fmt.Errorf("bringing device up: %w", err)
	}
	return t, nil
}

func (t *tunnel) close() { t.dev.Close() }

func (t *tunnel) resolve(ep string) (netip.AddrPort, error) {
	ap, err := resolveEndpoint(ep)
	if err == nil {
		t.mu.Lock()
		t.resolved[ep] = ap
		t.mu.Unlock()
	}
	return ap, err
}

// refreshEndpoints resolves host-name endpoints again and updates the peers
// whose address changed (DDNS), or that had none yet.
func (t *tunnel) refreshEndpoints() {
	for _, p := range t.cfg.Peers {
		if p.Endpoint == "" {
			continue
		}
		host, _, _ := net.SplitHostPort(p.Endpoint)
		t.mu.Lock()
		old, had := t.resolved[p.Endpoint]
		t.mu.Unlock()
		if _, err := netip.ParseAddr(host); err == nil && had {
			continue
		}
		ap, err := resolveEndpoint(p.Endpoint)
		if err != nil {
			t.logf("endpoint %s: %v", p.Endpoint, err)
			continue
		}
		if had && ap == old {
			continue
		}
		t.logf("endpoint %s -> %s", p.Endpoint, ap)
		set := fmt.Sprintf("public_key=%s\nupdate_only=true\nendpoint=%s\n", hex.EncodeToString(p.PublicKey[:]), ap)
		if err := t.dev.IpcSet(set); err != nil {
			t.logf("updating endpoint: %v", err)
			continue
		}
		t.mu.Lock()
		t.resolved[p.Endpoint] = ap
		t.mu.Unlock()
	}
}

// rebind reopens the UDP socket. On the PS5 sockets die for good when the
// network is reconfigured; wireguard-go's receive loop then stops.
func (t *tunnel) rebind() {
	if err := t.dev.BindUpdate(); err != nil {
		t.logf("rebind: %v", err)
	}
}

// localAddrs are the console's addresses inside the tunnel.
func (t *tunnel) localAddrs() []netip.Addr {
	var out []netip.Addr
	for _, p := range t.cfg.Addresses {
		out = append(out, p.Addr())
	}
	return out
}

// allowed reports whether a connection from src may reach the console.
func (t *tunnel) allowed(src netip.Addr) bool {
	list := t.opts().AllowFrom
	if len(list) == 0 {
		return true
	}
	for _, s := range list {
		if p, err := parsePrefix(s); err == nil && p.Contains(src.Unmap()) {
			return true
		}
	}
	return false
}

// installForwarders hands every TCP connection and every datagram on a
// listed UDP port that arrives for the console through the tunnel to the
// same port on 127.0.0.1.
func (t *tunnel) installForwarders() {
	s := t.tnet.Stack()

	tcpFwd := tcp.NewForwarder(s, 0, 256, func(r *tcp.ForwarderRequest) {
		id := r.ID()
		src := netip.AddrFrom4(id.RemoteAddress.As4())
		if id.RemoteAddress.Len() == 16 {
			src = netip.AddrFrom16(id.RemoteAddress.As16())
		}
		port := id.LocalPort
		o := t.opts()
		if !o.ExposeTCP || slices.Contains(o.BlockedTCPPorts, port) || t.isForwardListenPort("tcp", port) || !t.allowed(src) {
			r.Complete(true)
			return
		}
		// Dial before accepting, so that a closed port is refused properly.
		local, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(int(port))), 2*time.Second)
		if err != nil {
			r.Complete(true)
			return
		}
		var wq waiter.Queue
		ep, terr := r.CreateEndpoint(&wq)
		if terr != nil {
			r.Complete(true)
			local.Close()
			return
		}
		r.Complete(false)
		c := gonet.NewTCPConn(&wq, ep)
		t.logf("tcp %s -> 127.0.0.1:%d", src, port)
		go func() {
			defer c.Close()
			defer local.Close()
			pipe(c, local)
		}()
	})
	s.SetTransportProtocolHandler(tcp.ProtocolNumber, tcpFwd.HandlePacket)

	udpFwd := udp.NewForwarder(s, func(r *udp.ForwarderRequest) bool {
		id := r.ID()
		src := netip.AddrFrom4(id.RemoteAddress.As4())
		if id.RemoteAddress.Len() == 16 {
			src = netip.AddrFrom16(id.RemoteAddress.As16())
		}
		port := id.LocalPort
		o := t.opts()
		if !slices.Contains(o.UDPPorts, port) || t.isForwardListenPort("udp", port) || !t.allowed(src) {
			return false
		}
		var wq waiter.Queue
		ep, terr := r.CreateEndpoint(&wq)
		if terr != nil {
			return true
		}
		c := gonet.NewUDPConn(&wq, ep)
		go relayUDPToLocal(c, port, t.logf)
		return true
	})
	s.SetTransportProtocolHandler(udp.ProtocolNumber, udpFwd.HandlePacket)
}

func (t *tunnel) isForwardListenPort(proto string, port uint16) bool {
	for _, f := range t.opts().Forwards {
		if f.Proto != proto {
			continue
		}
		if _, p, err := net.SplitHostPort(f.Listen); err == nil && p == strconv.Itoa(int(port)) {
			return true
		}
	}
	return false
}

// relayUDPToLocal relays one tunnel client's UDP flow to 127.0.0.1:port until
// it has been idle for udpIdleTimeout.
func relayUDPToLocal(c *gonet.UDPConn, port uint16, logf func(string, ...any)) {
	defer c.Close()
	local, err := net.Dial("udp", net.JoinHostPort("127.0.0.1", strconv.Itoa(int(port))))
	if err != nil {
		logf("udp %d: %v", port, err)
		return
	}
	defer local.Close()
	var last sync.Mutex
	seen := time.Now()
	touch := func() { last.Lock(); seen = time.Now(); last.Unlock() }
	idle := func() bool { last.Lock(); defer last.Unlock(); return time.Since(seen) > udpIdleTimeout }
	done := make(chan struct{}, 2)
	cp := func(dst, src net.Conn) {
		defer func() { done <- struct{}{} }()
		buf := make([]byte, 65535)
		for {
			src.SetReadDeadline(time.Now().Add(udpIdleTimeout / 4))
			n, err := src.Read(buf)
			if err != nil {
				if ne, ok := err.(net.Error); ok && ne.Timeout() && !idle() {
					continue
				}
				return
			}
			touch()
			if _, err := dst.Write(buf[:n]); err != nil {
				return
			}
		}
	}
	go cp(local, c)
	go cp(c, local)
	<-done
}

// peerStatus is what the status page shows for one peer.
type peerStatus struct {
	Name          string   `json:"name"`
	PublicKey     string   `json:"publicKey"`
	Endpoint      string   `json:"endpoint"`
	ConfiguredEP  string   `json:"configuredEndpoint"`
	AllowedIPs    []string `json:"allowedIPs"`
	LastHandshake int64    `json:"lastHandshake"` // unix seconds, 0 = never
	RxBytes       int64    `json:"rxBytes"`
	TxBytes       int64    `json:"txBytes"`
	Keepalive     int      `json:"keepalive"`
}

// peers reads the live peer state from the device.
func (t *tunnel) peers() []peerStatus {
	text, err := t.dev.IpcGet()
	if err != nil {
		return nil
	}
	byKey := map[string]*wgPeer{}
	for i := range t.cfg.Peers {
		byKey[hex.EncodeToString(t.cfg.Peers[i].PublicKey[:])] = &t.cfg.Peers[i]
	}
	var out []peerStatus
	var cur *peerStatus
	sc := bufio.NewScanner(strings.NewReader(text))
	for sc.Scan() {
		k, v, ok := strings.Cut(sc.Text(), "=")
		if !ok {
			continue
		}
		switch k {
		case "public_key":
			out = append(out, peerStatus{})
			cur = &out[len(out)-1]
			if b, err := hex.DecodeString(v); err == nil {
				cur.PublicKey = base64.StdEncoding.EncodeToString(b)
			}
			if p := byKey[v]; p != nil {
				cur.Name, cur.ConfiguredEP, cur.Keepalive = p.Name, p.Endpoint, p.Keepalive
				for _, a := range p.AllowedIPs {
					cur.AllowedIPs = append(cur.AllowedIPs, a.String())
				}
			}
		case "endpoint":
			if cur != nil {
				cur.Endpoint = v
			}
		case "last_handshake_time_sec":
			if cur != nil {
				cur.LastHandshake, _ = strconv.ParseInt(v, 10, 64)
			}
		case "rx_bytes":
			if cur != nil {
				cur.RxBytes, _ = strconv.ParseInt(v, 10, 64)
			}
		case "tx_bytes":
			if cur != nil {
				cur.TxBytes, _ = strconv.ParseInt(v, 10, 64)
			}
		}
	}
	return out
}

// dial opens a connection to a host behind the tunnel.
func (t *tunnel) dial(ctx context.Context, network, addr string) (net.Conn, error) {
	return t.tnet.DialContext(ctx, network, addr)
}
