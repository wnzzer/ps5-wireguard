package main

import (
	_ "embed"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"time"
)

//go:embed status.html
var statusHTML []byte

func splitLines(s string) []string { return strings.Split(s, "\n") }
func cut(s, sep string) (string, string, bool) {
	a, b, ok := strings.Cut(s, sep)
	return strings.TrimSpace(a), strings.TrimSpace(b), ok
}
func eqFold(a, b string) bool { return strings.EqualFold(a, b) }

type statusResponse struct {
	Version   string       `json:"version"`
	Uptime    int64        `json:"uptime"`
	Running   bool         `json:"running"`
	Connected bool         `json:"connected"`
	Error     string       `json:"error"`
	PublicKey string       `json:"publicKey"`
	Addresses []string     `json:"addresses"`
	LanIP     string       `json:"lanIP"`
	Peers     []peerStatus `json:"peers"`
	Forwards  []string     `json:"forwards"`
	UDPPorts  []uint16     `json:"udpPorts"`
	ExposeTCP bool         `json:"exposeTCP"`
	Blocked   []uint16     `json:"blockedTCPPorts"`
	Now       int64        `json:"now"`
	Logs      []string     `json:"logs"`
}

func (d *daemon) webHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write(statusHTML)
	})
	mux.HandleFunc("GET /api/status", func(w http.ResponseWriter, r *http.Request) {
		d.mu.Lock()
		t := d.tun
		s := statusResponse{
			Version: version, Uptime: int64(time.Since(d.started).Seconds()),
			Running: t != nil, Connected: d.connected, Error: d.confErr, PublicKey: d.pubKey,
			LanIP: lanIP(), UDPPorts: d.set.UDPPorts, ExposeTCP: d.set.ExposeTCP, Blocked: d.set.BlockedTCPPorts,
			Now: time.Now().Unix(),
		}
		d.mu.Unlock()
		if t != nil {
			for _, a := range t.cfg.Addresses {
				s.Addresses = append(s.Addresses, a.String())
			}
			s.Peers = t.peers()
		}
		s.Forwards = d.fwd.list()
		s.Logs = recentLogs.snapshot()
		writeJSON(w, s)
	})
	mux.HandleFunc("GET /api/config", func(w http.ResponseWriter, r *http.Request) {
		text, err := d.loadConfigText()
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		io.WriteString(w, redactConfig(text))
	})
	mux.HandleFunc("POST /api/config", func(w http.ResponseWriter, r *http.Request) {
		if !sameOrigin(r) {
			http.Error(w, "cross-site request refused", 403)
			return
		}
		b, err := io.ReadAll(io.LimitReader(r.Body, 64<<10))
		if err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		stored, _ := d.loadConfigText()
		text := restoreHiddenKey(strings.ReplaceAll(string(b), "\r\n", "\n"), stored)
		if _, err := parseWGConfig(text); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		if err := writeFileAtomic(d.confPath, []byte(text), 0o600); err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		d.logf("wg0.conf updated from the status page")
		d.restartTunnel()
		writeJSON(w, map[string]string{"ok": "1"})
	})
	mux.HandleFunc("POST /api/newkey", func(w http.ResponseWriter, r *http.Request) {
		if !sameOrigin(r) {
			http.Error(w, "cross-site request refused", 403)
			return
		}
		priv, err := generatePrivateKey()
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		stored, _ := d.loadConfigText()
		var out []string
		replaced := false
		for _, line := range splitLines(stored) {
			if k, _, ok := cut(line, "="); ok && eqFold(k, "privatekey") {
				line = "PrivateKey = " + keyString(priv)
				replaced = true
			}
			out = append(out, line)
		}
		if !replaced {
			http.Error(w, "no PrivateKey line in wg0.conf", 400)
			return
		}
		if err := writeFileAtomic(d.confPath, []byte(strings.Join(out, "\n")), 0o600); err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		d.logf("generated a new key pair")
		d.restartTunnel()
		writeJSON(w, map[string]string{"publicKey": keyString(publicKey(priv))})
	})
	mux.HandleFunc("GET /api/settings", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, d.settings())
	})
	mux.HandleFunc("POST /api/settings", func(w http.ResponseWriter, r *http.Request) {
		if !sameOrigin(r) {
			http.Error(w, "cross-site request refused", 403)
			return
		}
		b, err := io.ReadAll(io.LimitReader(r.Body, 64<<10))
		if err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		s, err := parseSettings(b)
		if err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		if err := saveSettings(d.setPath, s); err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		d.mu.Lock()
		oldWeb := d.set.WebAddr
		d.set = s
		d.mu.Unlock()
		d.resolver.setServers(s.DNSServers)
		d.fwd.set(s.Forwards)
		d.writePriorityFile()
		d.logf("settings updated")
		msg := "saved"
		if s.WebAddr != oldWeb {
			msg = "saved; the new status page address applies after the next start"
		}
		writeJSON(w, map[string]string{"ok": msg})
	})
	mux.HandleFunc("POST /api/restart", func(w http.ResponseWriter, r *http.Request) {
		if !sameOrigin(r) {
			http.Error(w, "cross-site request refused", 403)
			return
		}
		d.restartTunnel()
		writeJSON(w, map[string]string{"ok": "1"})
	})
	mux.HandleFunc("POST /api/quit", func(w http.ResponseWriter, r *http.Request) {
		// Only from the console itself (a new instance) or a same-origin page.
		if !isLoopback(r) && !sameOrigin(r) {
			http.Error(w, "refused", 403)
			return
		}
		writeJSON(w, map[string]string{"ok": "1"})
		go func() {
			time.Sleep(200 * time.Millisecond)
			d.stop()
		}()
	})
	mux.HandleFunc("GET /api/log", func(w http.ResponseWriter, r *http.Request) {
		f, err := os.Open(dataDir + "/wireguard.log")
		if err != nil {
			http.Error(w, err.Error(), 404)
			return
		}
		defer f.Close()
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		io.Copy(w, struct{ io.Reader }{f}) // plain reader: sendfile is broken on the PS5
	})
	return mux
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	json.NewEncoder(w).Encode(v)
}

func isLoopback(r *http.Request) bool {
	host, _, _ := net.SplitHostPort(r.RemoteAddr)
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// sameOrigin blocks other web sites from changing the configuration through
// the visitor's browser: state-changing requests must come from this page.
func sameOrigin(r *http.Request) bool {
	if r.Header.Get("X-PS5WG") != "1" {
		return false
	}
	if o := r.Header.Get("Origin"); o != "" && !strings.HasSuffix(o, "://"+r.Host) {
		return false
	}
	return true
}
