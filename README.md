# ldown
Deterministic self-healing WireGuard mesh orchestrator for Linux — written entirely in bash.

> v0.2.1-alpha — actively in development

---

## What it does

ldown forms a full WireGuard mesh between nodes using only a shared roster file. Nodes bootstrap key exchange automatically, form the mesh, and self-heal through a background sync loop. The czar node handles trust, membership, and coordination — but is never in the data path. All traffic flows directly peer-to-peer over encrypted WireGuard tunnels.

**The design philosophy:** Nodes reconnect from evidence-backed trusted state, corroborate topology through known neighbors, use the czar only for trust and epoch authority, and log every decision clearly enough that a human can see exactly why the mesh acted the way it did.

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
git clone -b alpha https://github.com/d3dx404/ldown
cd ldown
chmod +x bin/ldown
```

---

## Quick Start

### 1. Write the roster on every node

Create `/etc/ldown/roster.conf` — this is the one file you distribute manually:

```
SUBNET=10.10.0
WG_PORT=51820
LDOWN_PORT=51821
BOOTSTRAP_PORT=51822

203.0.113.10 --name kali1 --czar --relay
203.0.113.11 --name kali2 --keepalive 25
192.168.1.5  --name kali3 --keepalive 25
```

### 2. Initialize and start the czar

```bash
# on czar node
sudo bin/ldown mesh init
sudo bin/ldown mesh start --bootstrap
```

This initializes the czar, generates all keys and a CA, exports an encrypted onboarding bundle, and opens a bootstrap listener on port 51822. You will be prompted for an export passphrase — share it securely with your peers.

### 3. Bootstrap all peer nodes

```bash
# on every non-czar node (once czar bootstrap is serving)
sudo bin/ldown mesh init --bootstrap
```

This generates local keys, contacts the czar bootstrap port, receives the bundle, imports it, and automatically joins the mesh. You will be prompted for the export passphrase.

That's it. The mesh is live.

---

## How it works

### Czar role

The czar is the trust and membership authority — not a traffic router. It handles JOIN/LEAVE requests, distributes peer lists, signs node TLS certificates, and notifies all nodes when membership changes. It is never in the data path. All WireGuard traffic flows directly between peers.

### Joining the mesh

When a node runs `mesh join`:

1. Sends a signed JOIN to the czar with its WireGuard pubkey, node signing pubkey, TLS CSR, and admission ticket
2. Czar verifies the node is in the roster and the ticket is valid
3. Czar stores the pubkey, signs the node's TLS cert with the CA, adds the node to its WireGuard interface, and sends the full peer list back
4. Czar notifies all existing nodes with a signed PEER_ADD
5. Node connects directly to all peers using the received list
6. Listener and sync loop start automatically

### Self-healing sync loop

The sync loop runs on every node every 30 seconds. It:

- Checks WireGuard handshake age for each peer
- Re-adds peers with stale or missing handshakes
- Verifies the re-add worked — if not, increments a failure counter
- After 3 consecutive failures, reports the peer as down to czar
- Czar broadcasts a fresh PEER_ADD to all nodes to force re-connection
- Restarts the listener if it has died

### Leaving the mesh

When a node runs `mesh leave`:

1. Sends a signed LEAVE to czar — best effort, local cleanup always happens regardless
2. Czar sends PEER_REMOVE to all other nodes
3. Interface torn down, mesh.conf deleted, daemons stopped

---

## Commands

### `mesh init`

Generates WireGuard keypair, Ed25519 node signing keypair, ECDSA TLS key and CSR, writes `mesh.conf`. On czar nodes also generates the ECDSA P-256 CA and Ed25519 control-plane signing keypair.

```bash
sudo bin/ldown mesh init
sudo bin/ldown mesh init --bootstrap   # peer path: skip PSK prompt, auto-join after
```

### `mesh start`

Forms the mesh. Czar only. Starts listener and sync automatically.

```bash
sudo bin/ldown mesh start
sudo bin/ldown mesh start --bootstrap            # also open bootstrap listener on port 51822
sudo bin/ldown mesh start --bootstrap --time 300 # bootstrap timeout in seconds (default 120)
sudo bin/ldown mesh start --watch                # open mesh watch after start
```

### `mesh join`

Joins a live mesh via the czar. Non-czar nodes only. Starts listener and sync automatically.

```bash
sudo bin/ldown mesh join
sudo bin/ldown mesh join --watch   # open mesh watch after join
```

### `mesh leave`

Gracefully leaves the mesh. Notifies czar, tears down interface, stops daemons.

```bash
sudo bin/ldown mesh leave
```

### `mesh recover`

Rebuilds the mesh from zero saved state. Only requires `roster.conf` and private keys. Probes all peers directly — no czar needed. Starts listener and sync automatically.

```bash
sudo bin/ldown mesh recover
```

### `mesh watch`

Live dashboard showing peer status, handshake ages, traffic, listener/sync health, and bootstrap progress.

```bash
sudo bin/ldown mesh watch
sudo bin/ldown mesh watch --logs   # log viewer with history and IP resolution
sudo bin/ldown mesh watch --once   # single snapshot, exits immediately
```

### `mesh export`

Creates an encrypted onboarding bundle. Contains roster, CA cert, czar signing public key, and PSK. No private keys included.

```bash
sudo bin/ldown mesh export
```

### `mesh import`

Unpacks an export bundle. Installs CA cert, PSK, czar public key, and roster. Run before `mesh init` + `mesh join` on manual onboarding flows.

```bash
sudo bin/ldown mesh import <bundle.tar.gz.enc>
```

### `mesh reset`

Wipes all ldown state from this node — keys, certs, configs, logs, and WireGuard interface.

```bash
sudo bin/ldown mesh reset
sudo bin/ldown mesh reset -y   # skip confirmation
```

### `listener` / `sync`

Manage the control-plane listener and sync loop daemons directly (normally started automatically).

```bash
sudo bin/ldown listener start
sudo bin/ldown listener stop
sudo bin/ldown listener status

sudo bin/ldown sync start
sudo bin/ldown sync stop
sudo bin/ldown sync status
```

### `mesh ticket`

Manage one-time admission tickets. Tickets are auto-created during bootstrap.

```bash
sudo bin/ldown mesh ticket create <n>
sudo bin/ldown mesh ticket create --from-roster   # create tickets for all roster nodes
sudo bin/ldown mesh ticket list
sudo bin/ldown mesh ticket revoke <n>
```

---

## Roster format

```
# global settings
SUBNET=10.10.0          # tunnel subnet prefix
WG_PORT=51820           # WireGuard port (default 51820)
LDOWN_PORT=51821        # ldown control plane port (default 51821)
BOOTSTRAP_PORT=51822    # bootstrap onboarding port (default 51822)

# nodes — one per line
# format: <public_ip> --name <n> [flags]

203.0.113.10 --name kali1 --czar --relay
203.0.113.11 --name kali2 --keepalive 25
192.168.1.5  --name kali3 --keepalive 25
```

**Flags:**

| Flag | Description |
|---|---|
| `--name` | Node name — used for keys, logs, display (required) |
| `--czar` | Mesh coordinator — exactly one required |
| `--relay` | Can relay traffic for NAT traversal |
| `--tunnel` | Override auto-assigned tunnel IP (default: SUBNET.POSITION) |
| `--keepalive` | PersistentKeepalive in seconds — use for nodes behind NAT |
| `--port` | Override WireGuard listen port for this node |

Tunnel IPs are assigned by line position — line 1 gets SUBNET.1, line 2 gets SUBNET.2, etc. Never reorder lines after the mesh is live unless you also update `--tunnel`.

---

## Adding a new node manually

If bootstrap is not running, onboard manually:

```bash
# on czar
sudo bin/ldown mesh export
# produces: ldown-export-<date>.tar.gz.enc

# on new node — write roster first, then:
sudo bin/ldown mesh import ldown-export-<date>.tar.gz.enc
sudo bin/ldown mesh init
sudo bin/ldown mesh join
```

---

## Runtime layout

```
/etc/ldown/
  mesh.conf               node identity and mesh state
  roster.conf             shared roster (same on all nodes)
  tls.cert / tls.key      node TLS certificate (CA-signed at JOIN)
  keys/
    <n>.private.key       WireGuard private key
    <n>.public.key        WireGuard public key
    <n>-node.key          Ed25519 node signing private key
    <n>-node.pub          Ed25519 node signing public key
    czar-control.key      Ed25519 czar control-plane signing key (czar only)
    czar-control.pub      Ed25519 czar control-plane public key (all nodes)
    ca.key                ECDSA P-256 CA private key (czar only)
    ca.cert               ECDSA P-256 CA certificate (all nodes)
    mesh.psk              WireGuard pre-shared key (all nodes)
  wg0/
    wg0.conf              assembled WireGuard config
    peers/
      peer-<tunnel_ip>.conf

/var/log/ldown/
  ldown.log
  listener.log
  sync.log
  security.log

/run/ldown/
  listener.pid
  sync.pid
  bootstrap.pid
  bootstrap_joined
  bootstrap_meta
  nonces/
```

---

## Security model

Five overlapping control layers:

| Layer | Mechanism |
|---|---|
| Tunnel encryption | WireGuard Curve25519 + optional PSK derived from mesh passphrase |
| Control plane auth | Ed25519 per-node signing — every message signed by sender |
| Replay resistance | V1\|timestamp\|nonce envelope — 60s window, nonce stored 2 minutes |
| Roster pinning | PEER_ADD/PEER_REMOVE rejected if name+tunnel not in roster |
| Transport encryption | ncat --ssl on all control plane connections (port 51821) |

**Message signing rules:**

- `JOIN`, `LEAVE` — signed with sender's `{name}-node.key` (Ed25519)
- `PEER_ADD`, `PEER_REMOVE`, `RECONNECT`, `REVIVE` — signed with `czar-control.key` (Ed25519)
- `JOIN` is self-authenticating — verified against the embedded pubkey in the payload
- All others — verified against stored `{sender}-node.pub`

**What nodes can do without czar:**
Re-add previously trusted peers, retry known endpoints, log and buffer reports.

**What requires czar:**
Admit new nodes, trust new pubkeys, broadcast membership changes, sign TLS certificates, issue admission tickets.

---

## Architecture direction

ldown is evolving from czar-driven to evidence-backed autonomy.

**Czar as epoch authority, not traffic cop.** Normal nodes self-heal locally. Czar settles membership, trust, epoch changes, and partition reconciliation. All data traffic flows directly peer-to-peer.

**Peer immune states.** Each peer will have a confidence score based on handshake freshness, neighbor corroboration, endpoint stability, and pubkey consistency. States: `HEALTHY` → `ALTERED_SELF` → `SUSPECT` → `QUARANTINED` → `DARK`.

**Metabolism modes.** Sync interval scales with mesh stress: `CALM` (30s) → `ALERT` (15s) → `REPAIR` (5s) → `PARTITION` (5s). Fever triggers at 3+ simultaneous peer degradations.

**Escalation ladder.** L0 passive → L1 local retry → L2 alternate endpoint → L3 relay → L4 PROBE corroboration → L5 czar report → L6 quarantine → L7 epoch intervention.

---

## Project structure

```
ldown/
├── bin/
│   └── ldown              entry point, subcommand dispatcher
├── lib/
│   ├── common.sh          logging, output, signing, validation
│   ├── wireguard.sh       key gen, config writing, interface control
│   ├── roster.sh          roster parsing and validation
│   ├── mesh.sh            all mesh commands
│   ├── listener.sh        persistent control-plane daemon + handler
│   ├── sync.sh            background self-healing loop
│   └── make_roster.sh     interactive roster wizard
└── conf/
    ├── defaults.conf      default values
    └── roster.conf.example
```

---

## Roadmap

**Phase 0 — Correctness ✓ Complete**
20 correctness bugs fixed. Mesh forms, joins, leaves, and recovers correctly. All gate tests pass.

**Phase 1 — Trust hardening ✓ Complete**
- Ed25519 per-node signing keypairs — every message signed and verified
- Czar Ed25519 control-plane keypair — separate authority key for czar-only messages
- ECDSA P-256 CA — czar acts as certificate authority, signs 7-day node TLS certs at JOIN
- mTLS on control plane — all ncat connections use SSL with CA-signed certs
- Admission tickets — one-time tokens consumed at JOIN, auto-created during bootstrap
- Roster-pinned pubkeys — PEER_ADD/PEER_REMOVE rejected if not in roster
- WireGuard PSK — optional mesh passphrase derived into a shared PSK
- Replay protection — V1|timestamp|nonce envelope on every signed message
- Bootstrap protocol — `mesh start --bootstrap` on czar + `mesh init --bootstrap` on peers does everything automatically
- CLUSTER_TOKEN removed entirely — replaced by Ed25519 signing

**Phase 1 UX/reliability fixes (also complete)**
- `mesh start` and `mesh join` pre-flight teardown — kills stale listener, sync, and wg0 before starting
- `--keep-open` removed from ncat listener — was causing CLOSE-WAIT connection pile-up under load
- `wg set preshared-key` file path fix — was silently hanging every peer add with PSK
- `BOOTSTRAP_PORT` header line excluded from roster node parsing
- `CLUSTER_PUB` path corrected to `/etc/ldown/keys/czar-control.pub`
- `NCAT_REMOTE_ADDR` used as authoritative public IP in JOIN — peer-claimed IP can be wrong
- `--time` flag parsing fixed in bin/ldown
- Handler trap fixed — no longer deletes handler file while listener loop is live
- Node signing keypair hard-checked after generation — init fails fast instead of hanging sync later
- Handshake wait removed from `mesh join` — sync loop handles it, was blocking on large meshes
- Auto-export bundle in `mesh start --bootstrap` if none exists
- REPORT handler on czar — when peer reports a node down, czar broadcasts fresh PEER_ADD to all nodes
- Sync failure tracking — 3 consecutive re-add failures triggers REPORT to czar

**Phase 2 — Observable healing (next)**
Structured logs, confidence scoring engine, peer-evidence state, metabolism modes, fever detection, REPORT gossip, escalation ladder.

**Phase 3 — Bounded local autonomy**
Local reconnect from evidence, relay policy enforcement, PROBE corroboration, recovery/scar tissue, host process isolation via network namespace.

**Phase 4 — Partition and election**
Regent election, split-brain handling, czar return, epoch reconciliation.

**Phase 5 — Operator convenience**
Roster helpers, mesh evidence, mesh metabolism, post-quantum consideration.

---

## License

ldown is dual-licensed under the GNU Affero General Public License v3.0 (AGPLv3) and a Commercial License.

**Open Source License**
Available under AGPLv3. See [LICENSE](LICENSE) for the full text.

**Commercial License**
Organizations that need to use this software without complying with AGPL source disclosure requirements must obtain a commercial license from the author.

**Nonprofit Consideration**
Nonprofit organizations with humanitarian or animal welfare missions are encouraged to apply for a no-cost commercial license.

For licensing inquiries contact the author.

---

## Author

d3dx404
