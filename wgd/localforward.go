package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"
)

// Local forwards let apps on the console reach a host behind the tunnel: the
// daemon listens on the console and relays each connection through
// WireGuard. The tunnel may be restarted underneath them, so they dial
// through whatever tunnel is current.

type dialFunc func(ctx context.Context, network, addr string) (net.Conn, error)

type localForwards struct {
	dial dialFunc
	logf func(string, ...any)

	mu      sync.Mutex
	rules   []forwardRule
	tcp     []*resilientListener
	udp     []*udpRelay
	running []string
}

// set replaces the running forwards with rules.
func (lf *localForwards) set(rules []forwardRule) {
	lf.mu.Lock()
	defer lf.mu.Unlock()
	if fmt.Sprint(rules) == fmt.Sprint(lf.rules) {
		return
	}
	for _, l := range lf.tcp {
		l.Close()
	}
	for _, r := range lf.udp {
		r.stop()
	}
	lf.tcp, lf.udp, lf.running = nil, nil, nil
	lf.rules = append([]forwardRule(nil), rules...)
	for _, r := range rules {
		r := r
		desc := fmt.Sprintf("%s %s -> %s", r.Proto, r.Listen, r.Target)
		switch r.Proto {
		case "tcp":
			ln, err := listenResilient("tcp", r.Listen, lf.logf)
			if err != nil {
				lf.logf("forward %s: %v", desc, err)
				continue
			}
			lf.tcp = append(lf.tcp, ln)
			go lf.serveTCP(ln, r.Target)
		case "udp":
			relay, err := startUDPRelay(udpRelayConfig{
				name:   "forward " + desc,
				listen: func() (net.PacketConn, error) { return net.ListenPacket("udp", r.Listen) },
				dial:   func(ctx context.Context) (net.Conn, error) { return lf.dial(ctx, "udp", r.Target) },
				logf:   lf.logf,
			})
			if err != nil {
				lf.logf("forward %s: %v", desc, err)
				continue
			}
			lf.udp = append(lf.udp, relay)
		}
		lf.running = append(lf.running, desc)
		lf.logf("forward %s", desc)
	}
}

func (lf *localForwards) list() []string {
	lf.mu.Lock()
	defer lf.mu.Unlock()
	return append([]string(nil), lf.running...)
}

func (lf *localForwards) serveTCP(ln *resilientListener, target string) {
	for {
		c, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			time.Sleep(time.Second)
			continue
		}
		go func() {
			defer c.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			up, err := lf.dial(ctx, "tcp", target)
			cancel()
			if err != nil {
				lf.logf("forward -> %s: %v", target, err)
				return
			}
			defer up.Close()
			pipe(c, up)
		}()
	}
}

// pipe copies in both directions until both sides are done.
func pipe(a, b net.Conn) {
	done := make(chan struct{}, 2)
	cp := func(dst, src net.Conn) {
		io.Copy(dst, src)
		// Pass the end of the stream on, so that protocols relying on a
		// half-close (such as sending a payload to the ELF loader) work.
		if cw, ok := dst.(interface{ CloseWrite() error }); ok {
			cw.CloseWrite()
		} else {
			dst.Close()
		}
		done <- struct{}{}
	}
	go cp(a, b)
	go cp(b, a)
	<-done
	<-done
}
