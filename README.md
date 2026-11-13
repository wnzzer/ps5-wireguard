# WireGuard for jailbroken PS5

[![LINUX DO](https://img.shields.io/badge/LINUX-DO-FFB003?style=flat&logo=data:image/svg%2bxml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCAxMjAgMTIwIj48Y2xpcFBhdGggaWQ9ImMiPjxjaXJjbGUgY3g9IjYwIiBjeT0iNjAiIHI9IjQ3Ii8+PC9jbGlwUGF0aD48Y2lyY2xlIGN4PSI2MCIgY3k9IjYwIiByPSI1MCIgZmlsbD0iI2YwZjBmMCIvPjxnIGNsaXAtcGF0aD0idXJsKCNjKSI+PHJlY3QgeD0iMCIgeT0iMTAiIHdpZHRoPSIxMjAiIGhlaWdodD0iMzAiIGZpbGw9IiMxYzFjMWUiLz48cmVjdCB4PSIwIiB5PSI0MCIgd2lkdGg9IjEyMCIgaGVpZ2h0PSI0MCIgZmlsbD0iI2YwZjBmMCIvPjxyZWN0IHg9IjAiIHk9IjgwIiB3aWR0aD0iMTIwIiBoZWlnaHQ9IjMwIiBmaWxsPSIjZmZiMDAzIi8+PC9nPjwvc3ZnPg==)](https://linux.do)

Puts a jailbroken PS5 on your own [WireGuard](https://www.wireguard.com) network
as an ordinary peer: no Tailscale account or coordination server, just a
standard `wg-quick` style config and the WireGuard server you already run
(router, VPS, ...).

- **Reach the console from anywhere through your tunnel.** Every TCP port
  that something on the console listens on (FTP, the ELF loader, web tools,
  Remote Play's session port, ...) is reachable at the console's tunnel
  address.
- **Remote Play over WireGuard.** Remote Play's UDP ports (and those of a
  Sunshine host on the console) are relayed too, so Chiaki and similar
  clients can connect to the console's tunnel address.
- **Local forwards.** Apps on the console can reach a host behind the tunnel
  through a port on the console itself (for example a Moonlight client on the
  PS5 connecting to a Sunshine host at home).
- **Status page** on port 8091: handshake, traffic, config editor, log.

> **Unofficial and experimental.** Not affiliated with WireGuard, Jason A.
> Donenfeld or Sony. It runs homebrew with full privileges on a jailbroken
> system; use it at your own risk.

This project reuses the PS5 Go runtime of
[holdmysocks/ps5-tailscale](https://github.com/holdmysocks/ps5-tailscale):
the C launcher that loads a Go program as a payload and the patch that makes
Go 1.27.1 run on the PS5 kernel. Read its
[TECHNICAL.md](https://github.com/holdmysocks/ps5-tailscale/blob/main/docs/TECHNICAL.md)
for how that works. The daemon itself is new: wireguard-go and gVisor
netstack in place of tsnet.

## What it is not

The PS5 kernel has no tunnel device, so WireGuard runs inside one process
(userspace network stack) and cannot become a system-wide VPN:

- Games, PSN and the browser do **not** go through the tunnel, and the
  console's own IP address does not change.
- The console does not route for other devices and is not an exit node.

## Requirements

- A jailbroken PS5 with an ELF loader listening on port 9021
  (for example [elfldr](https://github.com/ps5-payload-dev/elfldr)).
- A WireGuard server the console can reach (UDP).

Tested on firmware 12.40. It can run next to ps5-tailscale (different port
and data directory).

## Install and set up

1. Send the payload to the ELF loader:

   ```bash
   nc -w 60 <console-ip> 9021 < wireguard-<version>.elf
   ```

2. The first run creates `/data/wireguard/wg0.conf` with a fresh key pair.
   Open `http://<console-ip>:8091` on a phone or PC.
3. On your WireGuard server, add a peer with the **public key** shown on the
   page and `AllowedIPs = <console tunnel address>/32`.
4. On the status page, edit `wg0.conf` and save. Example:

   ```ini
   [Interface]
   PrivateKey = (hidden, unchanged)
   Address = 10.8.0.7/32
   MTU = 1420

   [Peer]
   # Name = home
   PublicKey = <server public key>
   # PresharedKey = <optional>
   Endpoint = vpn.example.com:51820
   AllowedIPs = 10.8.0.0/24
   PersistentKeepalive = 25
   ```

   The page never shows the private key; leave the placeholder line as it
   is to keep the current key. Keys created elsewhere can be pasted in as
   usual.
5. Once the state shows **connected**, use the console's tunnel address from
   any device on your WireGuard network.

The payload runs until the console restarts. After a restart and
jailbreak, send it again; the config is kept. To autoload it, keep the copy
your payload manager starts under a fixed name such as `wireguard.elf`.
Sending the payload again replaces the running instance.

### Settings

`/data/wireguard/settings.json`, editable on the status page:

| Key | Default | Meaning |
| --- | --- | --- |
| `webAddr` | `:8091` | Status page address (applies after the next start) |
| `exposeTCP` | `true` | Relay every TCP port from the tunnel to `127.0.0.1` |
| `blockedTCPPorts` | `[]` | TCP ports never exposed |
| `udpPorts` | Remote Play + Sunshine | UDP ports relayed from the tunnel |
| `allowFrom` | `[]` | Only these source prefixes may connect; empty = any peer |
| `forwards` | `[]` | `{"proto":"tcp","listen":"127.0.0.1:8022","target":"10.8.0.2:22"}` |
| `dnsServers` | `[]` | Resolvers for host-name endpoints; empty = local DNS payload, then public resolvers |
| `priority` | `low` | `high` if streams stutter under load (applies after the next start) |
| `verbose` | `false` | Include wireguard-go's own messages in the log |

Host-name endpoints are re-resolved periodically (DDNS), and the UDP socket
is reopened when the tunnel stays silent, which is what happens after the
console's network is reconfigured.

### Security

Anyone who can reach port 8091 can change the tunnel config. On a typical
jailbreak setup the LAN can already run arbitrary code through port 9021, so
the page adds no password; state-changing requests require a custom header
so other web sites cannot trigger them. Through the tunnel the console's
services are as open as on the LAN; use `allowFrom` and `blockedTCPPorts` to
narrow that.

Files in `/data/wireguard`: `wg0.conf` (mode 0600), `settings.json`,
`wireguard.log`, `launcher.log`, `priority`.

## Building

Works on macOS and Linux. Nothing is installed system-wide:

```
goroot/                     Go 1.27.1 with patches/go1.27.1-ps5.patch applied,
                            then `go install cmd/go cmd/link` with the original go
toolchain/llvm/bin/         clang, ld.lld (LLVM 20 or newer), plus `prospero-lld`:
                            a two-line script that execs ld.lld
toolchain/ps5-payload-sdk/  ps5-payload-sdk v0.43
```

```bash
tools/build.sh 0.1.0        # -> out/wireguard-0.1.0.elf
```

Tests run on the build machine and bring up a second wireguard-go peer to
check inbound TCP/UDP, refused ports and local forwards end to end:

```bash
cd wgd && go test ./...
```

## License

GPL-3.0, as the ps5-tailscale code it builds on. `wgd/netstack/tun.go` is
from wireguard-go (MIT).
