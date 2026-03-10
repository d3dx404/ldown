# ldown
Deterministic self-healing WireGuard mesh orchestrator for Linux — no coordination server, pure bash.

> Created 7/3/26 or for you americans 3/7/26— actively in development

---

## What it does

ldown forms a full WireGuard mesh between nodes using only a shared roster file. No central server, no cloud dependency, no coordination daemon. Nodes bootstrap key exchange directly, form the mesh, and can rebuild themselves from scratch using only the roster and their private keys.

---

## Requirements

- Kali / Debian-based Linux
- `bash` >= 4.2
- `wireguard-tools`
- `ncat` (nmap's netcat)
- `openssl`
- Root / sudo

---

## Installation

```bash
git clone https://github.com/d3dx404/ldown
cd ldown
chmod +x bin/ldown
```

---

## Quick Start

**1. Write your roster on all nodes** — `/etc/ldown/roster.conf`:

```bash
SUBNET=10.10.0
WG_PORT=51820
LDOWN_PORT=51821

203.0.113.10 --name nyc-vps --czar --relay
203.0.113.11 --name lon-vps --keepalive 25
192.168.1.5  --name home-office --keepalive 25
```

Or use the interactive wizard:
```bash
sudo bin/ldown make_roster
```

**2. Initialize each node** (run on every node):
```bash
sudo bin/ldown mesh init
```

**3. Form the mesh** (run on all nodes simultaneously):
```bash
sudo bin/ldown mesh start
```

---

## Commands

### `make_roster`
Interactive wizard to build `/etc/ldown/roster.conf`.
```bash
sudo bin/ldown make_roster
```

---

### `mesh init`
Set up this node — generates WireGuard keypair, TLS cert, writes mesh.conf.
```bash
sudo bin/ldown mesh init
```

---

### `mesh start`
Form the full mesh. Run on all nodes at the same time after init is complete on all.
```bash
sudo bin/ldown mesh start
```

---

### `mesh join`
Join a live mesh via the czar. Run on a new node after init.
```bash
sudo bin/ldown mesh join
```

---

### `mesh leave`
Gracefully leave the mesh, notify czar, tear down interface.
```bash
sudo bin/ldown mesh leave
```

---

### `mesh recover`
**The killer feature.** Rebuild the mesh from zero saved state. Only requires roster.conf and private keys — no mesh.conf needed. Run after a server rebuild or full state wipe.
```bash
sudo bin/ldown mesh recover
```

---

### `mesh export`
Create an encrypted onboarding bundle for a new node. Contains roster, TLS cert, and bootstrap info — no private keys.
```bash
sudo bin/ldown mesh export [output_dir]
```

---

### `mesh import`
Unpack an export bundle on a new node. Run before init + join.
```bash
sudo bin/ldown mesh import <bundle.tar.gz.enc>
```

---

### `mesh reset`
Nuclear option — wipe all ldown state from this node.
```bash
sudo bin/ldown mesh reset
```

---

### `mesh status`
Show each peer: up/down/stale, last handshake, bytes sent/received.
```bash
sudo bin/ldown mesh status
```

---

### `mesh doctor`
Full health check — keys, TLS cert, interface, roster hash, handshake ages, czar reachable.
```bash
sudo bin/ldown mesh doctor
```

---

### `mesh diff`
Compare what the roster expects vs what WireGuard actually has configured. Detects missing and rogue peers.
```bash
sudo bin/ldown mesh diff
```

---

### `mesh neighbors`
Reachability table — direct/stale/unreachable with tunnel latency and handshake age.
```bash
sudo bin/ldown mesh neighbors
```

---

## Roster Format

```bash
# global settings
SUBNET=10.10.0       # tunnel subnet prefix
WG_PORT=51820        # WireGuard port
LDOWN_PORT=51821     # ldown bootstrap/listener port

# nodes — one per line
# format: <public_ip> [--name <name>] [--czar] [--relay] [--tunnel <ip>] [--keepalive <seconds>]

203.0.113.10 --name nyc-vps --czar --relay
203.0.113.11 --name lon-vps
192.168.1.5  --name home-office --keepalive 25
```

Flags:
```
--name        node name (used for key filenames and display)
--czar        this node is the mesh coordinator (exactly one required)
--relay       this node can relay traffic for NAT-traversal
--tunnel      override auto-assigned tunnel IP (default: SUBNET.POSITION)
--keepalive   PersistentKeepalive in seconds (use for nodes behind NAT)
```

---

## Runtime Layout

```
/etc/ldown/
  mesh.conf           node identity and mesh state
  roster.conf         shared roster (same on all nodes)
  tls.cert / tls.key  node TLS certificate
  keys/
    <name>.private.key
    <name>.public.key
  wg0/
    interface.conf    WireGuard interface block
    wg0.conf          assembled config
    peers/
      peer-<tunnel_ip>.conf   one per peer

/var/log/ldown/
  ldown.log
  listener.log
  sync.log
  security.log
```

---

## Architecture

- **No coordination server** — nodes exchange pubkeys directly on LDOWN_PORT during bootstrap
- **Deterministic** — peers sorted by tunnel IP, same order on every node
- **Self-healing** — `mesh recover` rebuilds topology from roster + live peers
- **Czar election** — first alive node in roster wins, epoch prevents split-brain
- **Relay rules** — direct preferred, relay fallback, relay→relay forbidden

---

## Project Structure

```
ldown/
├── bin/
│   └── ldown              entry point, subcommand dispatcher
├── lib/
│   ├── common.sh          logging, output, validation, helpers
│   ├── wireguard.sh       key gen, config writing, interface control
│   ├── roster.sh          roster parsing and validation
│   ├── mesh.sh            all mesh commands
│   └── make_roster.sh     interactive roster wizard
├── conf/
│   ├── defaults.conf      default values
│   └── roster.conf.example
```

---

## Roadmap

### Phase 3 — listener.sh
Persistent daemon on LDOWN_PORT handling JOIN/LEAVE from peers and replacing the bootstrap ncat server.

### Phase 4 — sync.sh
Passive peer discovery loop — nodes periodically probe for missing peers and reconnect automatically.

### Phase 5 — network.sh
IP forwarding, NAT/masquerade, killswitch, route management.

### Phase 6 — observability.sh
Structured logging, metrics, alerting hooks.

---

## License

This project is dual-licensed.

- **Open Source License:** GNU General Public License v3.0 (GPLv3) — see [LICENSE](LICENSE)
- **Commercial License:** If you wish to use this software in a closed-source, proprietary, or private environment, you must obtain a commercial license.

For commercial licensing inquiries, please contact the project author.

---

## Author

d3dx404
