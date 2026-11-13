package main

import (
	"bufio"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"

	"golang.org/x/crypto/curve25519"
)

// wgConfig is a wg-quick style configuration ([Interface] + [Peer] sections).
// Fields that only make sense with a kernel interface (Table, PostUp, ...) are
// accepted and ignored, so a file exported from a router or another client
// can be pasted as is.
type wgConfig struct {
	PrivateKey [32]byte
	Addresses  []netip.Prefix
	ListenPort int
	MTU        int
	DNS        []netip.Addr // tunnel DNS; only shown, the console does not use it
	Peers      []wgPeer
}

type wgPeer struct {
	Name         string // from a "# Name = ..." comment, optional
	PublicKey    [32]byte
	PresharedKey [32]byte
	HasPSK       bool
	AllowedIPs   []netip.Prefix
	Endpoint     string // host:port as written; resolved when applied
	Keepalive    int
}

func parseKey(s string) ([32]byte, error) {
	var k [32]byte
	b, err := base64.StdEncoding.DecodeString(strings.TrimSpace(s))
	if err != nil || len(b) != 32 {
		return k, fmt.Errorf("invalid key %q", s)
	}
	copy(k[:], b)
	return k, nil
}

func keyString(k [32]byte) string { return base64.StdEncoding.EncodeToString(k[:]) }

func publicKey(priv [32]byte) [32]byte {
	var pub [32]byte
	curve25519.ScalarBaseMult(&pub, &priv)
	return pub
}

func generatePrivateKey() ([32]byte, error) {
	var k [32]byte
	if _, err := rand.Read(k[:]); err != nil {
		return k, err
	}
	k[0] &= 248
	k[31] = (k[31] & 127) | 64
	return k, nil
}

func splitList(v string) []string {
	var out []string
	for _, f := range strings.Split(v, ",") {
		if f = strings.TrimSpace(f); f != "" {
			out = append(out, f)
		}
	}
	return out
}

func parsePrefix(s string) (netip.Prefix, error) {
	if strings.Contains(s, "/") {
		p, err := netip.ParsePrefix(s)
		return p.Masked(), err
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, err
	}
	return netip.PrefixFrom(a, a.BitLen()), nil
}

// parseWGConfig parses the text of a wg-quick configuration file.
func parseWGConfig(text string) (*wgConfig, error) {
	cfg := &wgConfig{}
	section := ""
	var peer *wgPeer
	haveKey := false
	sc := bufio.NewScanner(strings.NewReader(text))
	lineNo := 0
	pendingName := ""
	for sc.Scan() {
		lineNo++
		line := strings.TrimSpace(sc.Text())
		if strings.HasPrefix(line, "#") {
			// "# Name = foo" names the following/current peer.
			c := strings.TrimSpace(strings.TrimPrefix(line, "#"))
			if k, v, ok := strings.Cut(c, "="); ok && strings.EqualFold(strings.TrimSpace(k), "name") {
				if section == "peer" && peer != nil && peer.Name == "" {
					peer.Name = strings.TrimSpace(v)
				} else {
					pendingName = strings.TrimSpace(v)
				}
			}
			continue
		}
		if i := strings.Index(line, "#"); i >= 0 {
			line = strings.TrimSpace(line[:i])
		}
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "[") {
			switch strings.ToLower(line) {
			case "[interface]":
				section = "interface"
			case "[peer]":
				section = "peer"
				cfg.Peers = append(cfg.Peers, wgPeer{Name: pendingName})
				pendingName = ""
				peer = &cfg.Peers[len(cfg.Peers)-1]
			default:
				return nil, fmt.Errorf("line %d: unknown section %s", lineNo, line)
			}
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			return nil, fmt.Errorf("line %d: expected key = value", lineNo)
		}
		k = strings.ToLower(strings.TrimSpace(k))
		v = strings.TrimSpace(v)
		fail := func(err error) error { return fmt.Errorf("line %d (%s): %v", lineNo, k, err) }
		switch section {
		case "interface":
			switch k {
			case "privatekey":
				key, err := parseKey(v)
				if err != nil {
					return nil, fail(err)
				}
				cfg.PrivateKey, haveKey = key, true
			case "address":
				for _, s := range splitList(v) {
					p, err := netip.ParsePrefix(s)
					if err != nil {
						a, err2 := netip.ParseAddr(s)
						if err2 != nil {
							return nil, fail(err)
						}
						p = netip.PrefixFrom(a, a.BitLen())
					}
					cfg.Addresses = append(cfg.Addresses, p)
				}
			case "listenport":
				n, err := strconv.Atoi(v)
				if err != nil || n < 0 || n > 65535 {
					return nil, fail(fmt.Errorf("bad port"))
				}
				cfg.ListenPort = n
			case "mtu":
				n, err := strconv.Atoi(v)
				if err != nil || n < 576 || n > 9000 {
					return nil, fail(fmt.Errorf("bad MTU"))
				}
				cfg.MTU = n
			case "dns":
				for _, s := range splitList(v) {
					if a, err := netip.ParseAddr(s); err == nil {
						cfg.DNS = append(cfg.DNS, a)
					}
				}
			default:
				// Table, PreUp, PostUp, SaveConfig, FwMark, ...: not applicable.
			}
		case "peer":
			switch k {
			case "publickey":
				key, err := parseKey(v)
				if err != nil {
					return nil, fail(err)
				}
				peer.PublicKey = key
			case "presharedkey":
				key, err := parseKey(v)
				if err != nil {
					return nil, fail(err)
				}
				peer.PresharedKey, peer.HasPSK = key, true
			case "allowedips":
				for _, s := range splitList(v) {
					p, err := parsePrefix(s)
					if err != nil {
						return nil, fail(err)
					}
					peer.AllowedIPs = append(peer.AllowedIPs, p)
				}
			case "endpoint":
				if _, _, err := net.SplitHostPort(v); err != nil {
					return nil, fail(err)
				}
				peer.Endpoint = v
			case "persistentkeepalive":
				if strings.EqualFold(v, "off") {
					peer.Keepalive = 0
					continue
				}
				n, err := strconv.Atoi(v)
				if err != nil || n < 0 || n > 65535 {
					return nil, fail(fmt.Errorf("bad keepalive"))
				}
				peer.Keepalive = n
			default:
			}
		default:
			return nil, fmt.Errorf("line %d: setting outside of a section", lineNo)
		}
	}
	if !haveKey {
		return nil, fmt.Errorf("[Interface] PrivateKey is missing")
	}
	if len(cfg.Addresses) == 0 {
		return nil, fmt.Errorf("[Interface] Address is missing")
	}
	for i, p := range cfg.Peers {
		if p.PublicKey == ([32]byte{}) {
			return nil, fmt.Errorf("peer %d: PublicKey is missing", i+1)
		}
	}
	if cfg.MTU == 0 {
		cfg.MTU = 1420
	}
	return cfg, nil
}

// uapi renders the configuration in wireguard-go's IPC format. resolve turns
// an Endpoint as written into an ip:port; peers whose endpoint cannot be
// resolved are configured without one (they can still be reached by a peer
// that knows our address) and the error is reported.
func (c *wgConfig) uapi(resolve func(string) (netip.AddrPort, error)) (string, []error) {
	var b strings.Builder
	var errs []error
	fmt.Fprintf(&b, "private_key=%s\n", hex.EncodeToString(c.PrivateKey[:]))
	fmt.Fprintf(&b, "listen_port=%d\n", c.ListenPort)
	b.WriteString("replace_peers=true\n")
	for _, p := range c.Peers {
		fmt.Fprintf(&b, "public_key=%s\n", hex.EncodeToString(p.PublicKey[:]))
		if p.HasPSK {
			fmt.Fprintf(&b, "preshared_key=%s\n", hex.EncodeToString(p.PresharedKey[:]))
		}
		if p.Endpoint != "" {
			ap, err := resolve(p.Endpoint)
			if err != nil {
				errs = append(errs, fmt.Errorf("endpoint %s: %w", p.Endpoint, err))
			} else {
				fmt.Fprintf(&b, "endpoint=%s\n", ap)
			}
		}
		fmt.Fprintf(&b, "persistent_keepalive_interval=%d\n", p.Keepalive)
		b.WriteString("replace_allowed_ips=true\n")
		for _, a := range p.AllowedIPs {
			fmt.Fprintf(&b, "allowed_ip=%s\n", a)
		}
	}
	return b.String(), errs
}

// redactConfig hides the private key in a configuration text, for display.
func redactConfig(text string) string {
	var out []string
	for _, line := range strings.Split(text, "\n") {
		if k, _, ok := strings.Cut(line, "="); ok && strings.EqualFold(strings.TrimSpace(k), "privatekey") {
			line = "PrivateKey = " + hiddenKey
		}
		out = append(out, line)
	}
	return strings.Join(out, "\n")
}

// hiddenKey stands for the stored private key in an edited configuration.
const hiddenKey = "(hidden, unchanged)"

// restoreHiddenKey puts the stored private key back where the edited text
// still has the placeholder.
func restoreHiddenKey(edited, stored string) string {
	var storedKey string
	for _, line := range strings.Split(stored, "\n") {
		if k, v, ok := strings.Cut(line, "="); ok && strings.EqualFold(strings.TrimSpace(k), "privatekey") {
			storedKey = strings.TrimSpace(v)
		}
	}
	var out []string
	for _, line := range strings.Split(edited, "\n") {
		if k, v, ok := strings.Cut(line, "="); ok && strings.EqualFold(strings.TrimSpace(k), "privatekey") &&
			strings.TrimSpace(v) == hiddenKey && storedKey != "" {
			line = "PrivateKey = " + storedKey
		}
		out = append(out, line)
	}
	return strings.Join(out, "\n")
}

// templateConfig is written on first start: a fresh key pair and a peer to
// fill in.
func templateConfig(priv [32]byte) string {
	return fmt.Sprintf(`[Interface]
PrivateKey = %s
# Public key (give this to the server): %s
# This console's address inside the tunnel; must match the server's peer entry.
Address = 10.8.0.50/32
MTU = 1420

[Peer]
# Name = home
# The server's public key, address and port:
PublicKey = REPLACE_WITH_SERVER_PUBLIC_KEY
Endpoint = vpn.example.com:51820
# Networks reached through the tunnel (replies to clients come from these).
AllowedIPs = 10.8.0.0/24
PersistentKeepalive = 25
`, keyString(priv), keyString(publicKey(priv)))
}
