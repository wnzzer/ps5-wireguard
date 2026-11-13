package main

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// Peer endpoints may be host names (DDNS). The PS5 has no resolv.conf, so
// Go's resolver would only ask 127.0.0.1:53, which answers only when a DNS
// payload runs. The daemon instead uses the first server that answers.

var defaultDNSServers = []string{"127.0.0.1:53", "223.5.5.5:53", "119.29.29.29:53", "1.1.1.1:53", "8.8.8.8:53"}

type resolver struct {
	logf func(string, ...any)

	mu      sync.Mutex
	servers []string
	chosen  string
	checked time.Time
}

func newResolver(logf func(string, ...any)) *resolver {
	r := &resolver{logf: logf, servers: defaultDNSServers}
	net.DefaultResolver = &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, network, r.server(ctx))
		},
	}
	return r
}

func (r *resolver) setServers(list []string) {
	var norm []string
	for _, s := range list {
		if _, _, err := net.SplitHostPort(s); err != nil {
			s = net.JoinHostPort(s, "53")
		}
		norm = append(norm, s)
	}
	if len(norm) == 0 {
		norm = defaultDNSServers
	}
	r.mu.Lock()
	r.servers, r.chosen = norm, ""
	r.mu.Unlock()
}

func (r *resolver) reset() {
	r.mu.Lock()
	r.chosen = ""
	r.mu.Unlock()
}

// server returns the DNS server to use, probing the list when needed.
func (r *resolver) server(ctx context.Context) string {
	r.mu.Lock()
	if r.chosen != "" && time.Since(r.checked) < 5*time.Minute {
		s := r.chosen
		r.mu.Unlock()
		return s
	}
	list := r.servers
	r.mu.Unlock()
	for _, s := range list {
		if dnsAnswers(ctx, s) {
			r.mu.Lock()
			if r.chosen != s {
				r.logf("dns: using %s", s)
			}
			r.chosen, r.checked = s, time.Now()
			r.mu.Unlock()
			return s
		}
	}
	return list[0]
}

// dnsAnswers sends one query and reports whether any answer arrives.
func dnsAnswers(ctx context.Context, server string) bool {
	ctx, cancel := context.WithTimeout(ctx, 1200*time.Millisecond)
	defer cancel()
	var d net.Dialer
	c, err := d.DialContext(ctx, "udp", server)
	if err != nil {
		return false
	}
	defer c.Close()
	if dl, ok := ctx.Deadline(); ok {
		c.SetDeadline(dl)
	}
	msg := dnsmessage.Message{
		Header:    dnsmessage.Header{ID: 0x5057, RecursionDesired: true},
		Questions: []dnsmessage.Question{{Name: dnsmessage.MustNewName("example.com."), Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}},
	}
	q, err := msg.Pack()
	if err != nil {
		return false
	}
	if _, err := c.Write(q); err != nil {
		return false
	}
	buf := make([]byte, 1500)
	n, err := c.Read(buf)
	if err != nil {
		return false
	}
	var p dnsmessage.Parser
	h, err := p.Start(buf[:n])
	return err == nil && h.ID == 0x5057 && h.Response
}

// resolveEndpoint turns "host:port" into an address, preferring IPv4 (the
// console usually has no IPv6 route).
func resolveEndpoint(hostport string) (netip.AddrPort, error) {
	host, portStr, err := net.SplitHostPort(hostport)
	if err != nil {
		return netip.AddrPort{}, err
	}
	port, err := net.LookupPort("udp", portStr)
	if err != nil {
		return netip.AddrPort{}, err
	}
	if a, err := netip.ParseAddr(host); err == nil {
		return netip.AddrPortFrom(a.Unmap(), uint16(port)), nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	addrs, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return netip.AddrPort{}, err
	}
	for _, a := range addrs {
		if a.Unmap().Is4() {
			return netip.AddrPortFrom(a.Unmap(), uint16(port)), nil
		}
	}
	if len(addrs) > 0 {
		return netip.AddrPortFrom(addrs[0], uint16(port)), nil
	}
	return netip.AddrPort{}, fmt.Errorf("no address for %s", host)
}
