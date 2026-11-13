package main

import (
	"bufio"
	"context"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"

	"ps5wireguard/netstack"
)

func echoTCP(t *testing.T) (port int) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { defer c.Close(); io.Copy(c, c) }()
		}
	}()
	return ln.Addr().(*net.TCPAddr).Port
}

func echoUDP(t *testing.T) (port int) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pc.Close() })
	go func() {
		buf := make([]byte, 2000)
		for {
			n, a, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			pc.WriteTo(append([]byte("echo:"), buf[:n]...), a)
		}
	}()
	return pc.LocalAddr().(*net.UDPAddr).Port
}

func freeUDPPort(t *testing.T) int {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	return pc.LocalAddr().(*net.UDPAddr).Port
}

func TestTunnelEndToEnd(t *testing.T) {
	consoleKey, _ := generatePrivateKey()
	clientKey, _ := generatePrivateKey()
	consolePort := freeUDPPort(t)
	tcpPort := echoTCP(t)
	udpPort := echoUDP(t)
	blockedPort := echoTCP(t)

	conf := fmt.Sprintf(`[Interface]
PrivateKey = %s
Address = 10.9.0.2/32
ListenPort = %d

[Peer]
# Name = laptop
PublicKey = %s
AllowedIPs = 10.9.0.0/24
`, keyString(consoleKey), consolePort, keyString(publicKey(clientKey)))
	cfg, err := parseWGConfig(conf)
	if err != nil {
		t.Fatal(err)
	}
	set := defaultSettings()
	set.UDPPorts = []uint16{uint16(udpPort)}
	set.BlockedTCPPorts = []uint16{uint16(blockedPort)}
	tun, err := startTunnel(cfg, func() settings { return set }, t.Logf, false)
	if err != nil {
		t.Fatal(err)
	}
	defer tun.close()

	// The "client": a second userspace WireGuard peer.
	ctdev, cnet, err := netstack.CreateNetTUN([]netip.Addr{netip.MustParseAddr("10.9.0.1")}, nil, 1420)
	if err != nil {
		t.Fatal(err)
	}
	cdev := device.NewDevice(ctdev, conn.NewDefaultBind(), device.NewLogger(device.LogLevelError, "client: "))
	defer cdev.Close()
	pub := publicKey(consoleKey)
	err = cdev.IpcSet(fmt.Sprintf("private_key=%s\npublic_key=%s\nendpoint=127.0.0.1:%d\nallowed_ip=10.9.0.2/32\npersistent_keepalive_interval=1\n",
		hex.EncodeToString(clientKey[:]), hex.EncodeToString(pub[:]), consolePort))
	if err != nil {
		t.Fatal(err)
	}
	cdev.Up()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	// Inbound TCP to the console's service.
	c, err := cnet.DialContext(ctx, "tcp", "10.9.0.2:"+strconv.Itoa(tcpPort))
	if err != nil {
		t.Fatalf("tcp dial: %v", err)
	}
	fmt.Fprintf(c, "hello\n")
	line, err := bufio.NewReader(c).ReadString('\n')
	if err != nil || line != "hello\n" {
		t.Fatalf("tcp echo: %q %v", line, err)
	}
	c.Close()

	// A blocked port and a closed port are refused.
	for _, p := range []int{blockedPort, freeUDPPort(t)} {
		dctx, dcancel := context.WithTimeout(ctx, 3*time.Second)
		c, err := cnet.DialContext(dctx, "tcp", "10.9.0.2:"+strconv.Itoa(p))
		dcancel()
		if err == nil {
			c.Close()
			t.Fatalf("port %d: connection accepted, want refused", p)
		}
	}

	// Inbound UDP on a listed port.
	u, err := cnet.DialContext(ctx, "udp", "10.9.0.2:"+strconv.Itoa(udpPort))
	if err != nil {
		t.Fatal(err)
	}
	u.Write([]byte("ping"))
	u.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 100)
	n, err := u.Read(buf)
	if err != nil || string(buf[:n]) != "echo:ping" {
		t.Fatalf("udp echo: %q %v", buf[:n], err)
	}
	u.Close()

	// Outbound: a local forward to a service behind the tunnel.
	ln, err := cnet.ListenTCP(&net.TCPAddr{IP: net.ParseIP("10.9.0.1"), Port: 2222})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err == nil {
			io.WriteString(c, "from-behind-tunnel\n")
			c.Close()
		}
	}()
	lf := &localForwards{dial: tun.dial, logf: t.Logf}
	ln2, _ := net.Listen("tcp", "127.0.0.1:0")
	listen := ln2.Addr().String()
	ln2.Close()
	lf.set([]forwardRule{{Proto: "tcp", Listen: listen, Target: "10.9.0.1:2222"}})
	defer lf.set(nil)
	fc, err := net.DialTimeout("tcp", listen, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	fc.SetReadDeadline(time.Now().Add(10 * time.Second))
	got, err := bufio.NewReader(fc).ReadString('\n')
	if err != nil || got != "from-behind-tunnel\n" {
		t.Fatalf("local forward: %q %v", got, err)
	}
	fc.Close()

	ps := tun.peers()
	if len(ps) != 1 || ps[0].LastHandshake == 0 || ps[0].Name != "laptop" || ps[0].RxBytes == 0 {
		t.Fatalf("peers: %+v", ps)
	}
}

func TestParseWGConfig(t *testing.T) {
	k, _ := generatePrivateKey()
	text := templateConfig(k)
	if _, err := parseWGConfig(text); err == nil {
		t.Fatal("template with placeholder key should not parse")
	}
	text = strings.Replace(text, "REPLACE_WITH_SERVER_PUBLIC_KEY", keyString(publicKey(k)), 1)
	cfg, err := parseWGConfig(text)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Peers[0].Name != "home" || cfg.Peers[0].Keepalive != 25 || cfg.MTU != 1420 {
		t.Fatalf("%+v", cfg)
	}
	red := redactConfig(text)
	if strings.Contains(red, keyString(k)) {
		t.Fatal("private key not hidden")
	}
	if restoreHiddenKey(red, text) != text {
		t.Fatal("restore did not give back the original")
	}
}
