// Command ps5wireguard runs a WireGuard peer on a jailbroken PS5.
//
// The PS5 kernel has no tun device, so WireGuard runs in userspace
// (wireguard-go + gVisor netstack) inside this one process. The console gets
// an address inside the tunnel; TCP connections and datagrams on listed UDP
// ports that arrive there are relayed to the console's own services on
// 127.0.0.1 (FTP, the ELF loader, Remote Play, ...). Local forwards let apps
// on the console reach hosts behind the tunnel. It is not a system VPN: games
// and PSN do not use it.
package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"sync"
	"syscall"
	"time"
)

// version is shown on the status page. Set at build time with -ldflags -X.
var version = "dev"

var dataDir = func() string {
	if d := os.Getenv("PS5WG_DATA"); d != "" {
		return d
	}
	return "/data/wireguard"
}()

func main() {
	console := newConsole()
	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		console.Printf("wireguard: cannot create %s: %v\n", dataDir, err)
		os.Exit(1)
	}
	os.MkdirAll(filepath.Join(dataDir, "tmp"), 0o755)
	logFile, err := openLog(filepath.Join(dataDir, "wireguard.log"))
	if err != nil {
		console.Printf("wireguard: cannot open log: %v\n", err)
		os.Exit(1)
	}
	logf := newLogger(logFile)

	d := &daemon{
		logf:       logf,
		console:    console,
		started:    time.Now(),
		confPath:   filepath.Join(dataDir, "wg0.conf"),
		setPath:    filepath.Join(dataDir, "settings.json"),
		quit:       make(chan struct{}),
		resolver:   newResolver(logf),
		kickRebind: make(chan struct{}, 1),
	}
	d.set, err = loadSettings(d.setPath)
	if err != nil {
		logf("settings: %v (using defaults)", err)
	}
	d.resolver.setServers(d.set.DNSServers)
	logf("ps5-wireguard %s starting (%s/%s), status page on %s", version, runtime.GOOS, runtime.GOARCH, d.set.WebAddr)

	// A payload that is sent again replaces the running instance.
	if stopRunningInstance(d.set.WebAddr) {
		logf("stopped the instance that was already running")
	}
	pidFile := filepath.Join(dataDir, "wireguard.pid")
	if pid := stopRecordedInstance(pidFile); pid != 0 {
		logf("stopped a previous instance (pid %d)", pid)
	}
	if err := recordInstance(pidFile); err != nil {
		logf("pid file: %v", err)
	}

	if err := d.run(); err != nil {
		logf("fatal: %v", err)
		notify("WireGuard 启动失败:\n%v", err)
		os.Exit(1)
	}
}

type daemon struct {
	logf     func(string, ...any)
	console  *console
	started  time.Time
	confPath string
	setPath  string
	resolver *resolver
	fwd      *localForwards

	quit       chan struct{}
	quitOnce   sync.Once
	kickRebind chan struct{}

	mu        sync.Mutex
	set       settings
	tun       *tunnel
	confErr   string // why the tunnel is not running
	pubKey    string
	connected bool // a handshake has happened since the tunnel started
}

func (d *daemon) settings() settings {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.set
}

func (d *daemon) currentTunnel() *tunnel {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.tun
}

func (d *daemon) dialTunnel(ctx context.Context, network, addr string) (net.Conn, error) {
	t := d.currentTunnel()
	if t == nil {
		return nil, errors.New("the tunnel is not running")
	}
	return t.dial(ctx, network, addr)
}

func (d *daemon) run() error {
	webLn, err := listenResilient("tcp", d.settings().WebAddr, d.logf)
	if err != nil {
		return fmt.Errorf("status page: %w", err)
	}
	webLn.onReopen = d.networkChanged
	srv := &http.Server{Handler: d.webHandler(), ReadHeaderTimeout: 10 * time.Second}
	go srv.Serve(webLn)
	d.writePriorityFile()

	d.fwd = &localForwards{dial: d.dialTunnel, logf: d.logf}
	d.fwd.set(d.settings().Forwards)

	d.restartTunnel()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go d.watch(ctx)

	sigc := make(chan os.Signal, 1)
	signal.Notify(sigc, syscall.SIGTERM, syscall.SIGINT)
	select {
	case <-d.quit:
		d.logf("stop requested")
	case s := <-sigc:
		d.logf("received %v", s)
	}
	cancel()
	webLn.Close()
	d.fwd.set(nil)
	if t := d.currentTunnel(); t != nil {
		done := make(chan struct{})
		go func() { t.close(); close(done) }()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			d.logf("shutdown timed out")
		}
	}
	d.logf("stopped")
	return nil
}

func (d *daemon) stop() { d.quitOnce.Do(func() { close(d.quit) }) }

// loadConfig reads wg0.conf, creating a template with a new key pair the
// first time.
func (d *daemon) loadConfigText() (string, error) {
	b, err := os.ReadFile(d.confPath)
	if os.IsNotExist(err) {
		priv, err := generatePrivateKey()
		if err != nil {
			return "", err
		}
		text := templateConfig(priv)
		if err := writeFileAtomic(d.confPath, []byte(text), 0o600); err != nil {
			return "", err
		}
		d.logf("created %s with a new key pair", d.confPath)
		return text, nil
	}
	return string(b), err
}

// restartTunnel (re)starts the tunnel from wg0.conf.
func (d *daemon) restartTunnel() {
	d.mu.Lock()
	old := d.tun
	d.tun, d.connected = nil, false
	d.mu.Unlock()
	if old != nil {
		old.close()
		d.logf("tunnel stopped")
	}

	text, err := d.loadConfigText()
	var cfg *wgConfig
	if err == nil {
		cfg, err = parseWGConfig(text)
	}
	if cfg != nil {
		d.mu.Lock()
		d.pubKey = keyString(publicKey(cfg.PrivateKey))
		d.mu.Unlock()
	} else if k := pubKeyFromText(text); k != "" {
		d.mu.Lock()
		d.pubKey = k
		d.mu.Unlock()
	}
	if err != nil {
		d.setConfErr(fmt.Sprintf("wg0.conf: %v", err))
		d.logf("wg0.conf: %v", err)
		d.console.Printf("WireGuard needs a configuration: open %s\n", d.webURL())
		notify("WireGuard 需要配置\n请在电脑/手机打开 %s", d.webURL())
		return
	}
	t, err := startTunnel(cfg, d.settings, d.logf, d.settings().Verbose)
	if err != nil {
		d.setConfErr(err.Error())
		d.logf("tunnel: %v", err)
		notify("WireGuard 启动失败:\n%v", err)
		return
	}
	d.mu.Lock()
	d.tun, d.confErr = t, ""
	d.mu.Unlock()
	d.logf("tunnel up: %v, %d peer(s), public key %s", cfg.Addresses, len(cfg.Peers), d.pubKey)
	d.console.Printf("WireGuard is up: %v\nStatus page: %s\n", cfg.Addresses, d.webURL())
}

func pubKeyFromText(text string) string {
	for _, line := range splitLines(text) {
		if k, v, ok := cut(line, "="); ok && eqFold(k, "privatekey") {
			if key, err := parseKey(v); err == nil {
				return keyString(publicKey(key))
			}
		}
	}
	return ""
}

func (d *daemon) setConfErr(s string) {
	d.mu.Lock()
	d.confErr = s
	d.mu.Unlock()
}

// watch tells the user when the first handshake succeeds, keeps host-name
// endpoints resolved and reopens the socket when the tunnel goes quiet.
func (d *daemon) watch(ctx context.Context) {
	tick := time.NewTicker(10 * time.Second)
	defer tick.Stop()
	var lastRefresh, lastRebind time.Time
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		case <-d.kickRebind:
			if t := d.currentTunnel(); t != nil {
				d.logf("network changed; reopening the WireGuard socket")
				d.resolver.reset()
				t.rebind()
				t.refreshEndpoints()
				lastRebind, lastRefresh = time.Now(), time.Now()
			}
			continue
		}
		t := d.currentTunnel()
		if t == nil {
			continue
		}
		peers := t.peers()
		newest := int64(0)
		hasEndpoint := false
		for _, p := range peers {
			newest = max(newest, p.LastHandshake)
			if p.Endpoint != "" || p.ConfiguredEP != "" {
				hasEndpoint = true
			}
		}
		fresh := newest > 0 && time.Since(time.Unix(newest, 0)) < 3*time.Minute
		d.mu.Lock()
		first := fresh && !d.connected && d.tun == t
		if first {
			d.connected = true
		}
		d.mu.Unlock()
		if first {
			addrs := t.localAddrs()
			d.logf("handshake complete; connected as %v", addrs)
			notify("WireGuard 已连接\n%v", addrs)
		}
		if !hasEndpoint {
			continue
		}
		// Re-resolve DDNS names every 5 minutes, or every 30 s while there
		// has been no recent handshake.
		every := 5 * time.Minute
		if !fresh {
			every = 30 * time.Second
		}
		if time.Since(lastRefresh) > every {
			t.refreshEndpoints()
			lastRefresh = time.Now()
		}
		// A dead socket shows as no handshake for a long time.
		if !fresh && time.Since(lastRebind) > 3*time.Minute && time.Since(d.started) > time.Minute {
			t.rebind()
			lastRebind = time.Now()
		}
	}
}

func (d *daemon) networkChanged() {
	select {
	case d.kickRebind <- struct{}{}:
	default:
	}
}

func (d *daemon) writePriorityFile() {
	p := d.settings().Priority
	if p == "" {
		p = "low"
	}
	os.WriteFile(filepath.Join(dataDir, "priority"), []byte(p+"\n"), 0o644)
}

// webURL is the address of the status page as seen from the local network.
func (d *daemon) webURL() string {
	_, port, _ := net.SplitHostPort(d.settings().WebAddr)
	return "http://" + net.JoinHostPort(lanIP(), port)
}

func lanIP() string {
	c, err := net.Dial("udp4", "192.0.2.1:9")
	if err != nil {
		return "127.0.0.1"
	}
	defer c.Close()
	if a, ok := c.LocalAddr().(*net.UDPAddr); ok && !a.IP.IsUnspecified() {
		return a.IP.String()
	}
	return "127.0.0.1"
}

// stopRunningInstance asks a daemon already listening on webAddr to quit.
func stopRunningInstance(webAddr string) bool {
	_, port, err := net.SplitHostPort(webAddr)
	if err != nil {
		return false
	}
	base := "http://" + net.JoinHostPort("127.0.0.1", port)
	cl := &http.Client{Timeout: 3 * time.Second}
	resp, err := cl.Post(base+"/api/quit", "text/plain", nil)
	if err != nil {
		return false
	}
	resp.Body.Close()
	for i := 0; i < 40; i++ {
		time.Sleep(250 * time.Millisecond)
		c, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", port), 500*time.Millisecond)
		if err != nil {
			return true
		}
		c.Close()
	}
	return true
}
