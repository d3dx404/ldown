# ldown
Deterministic self-healing WireGuard mesh orchestrator for Linux — written entirely in bash.

> Created 7/3/26 or for you americans 3/7/26 — actively in development (v0.1.0-alpha)

---

## What it does

ldown forms a full WireGuard mesh between nodes using only a shared roster file. Nodes bootstrap key exchange directly, form the mesh, and can rebuild themselves from scratch using only the roster and their private keys. The czar node handles trust, membership, and coordination — but is never in the data path. All traffic flows directly peer-to-peer over encrypted WireGuard tunnels.

**The design philosophy:** ldown should behave like an immune-capable organism, not a command tree. Nodes reconnect from evidence-backed trusted state, corroborate topology through known neighbors, use the czar only for trust and epoch authority, and log every decision clearly enough that a human can see exactly why the mesh acted the way it did.

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


Quick Start
1. Build your roster on the czar node:

sudo bin/ldown make_roster


Or write /etc/ldown/roster.conf manually:

SUBNET=10.10.0
WG_PORT=51820
LDOWN_PORT=51821
CLUSTER_TOKEN=your-secret-token

203.0.113.10 --name kali1 --czar --relay
203.0.113.11 --name kali2 --keepalive 25
192.168.1.5  --name kali3 --keepalive 25


2. Distribute roster.conf to all nodes at /etc/ldown/roster.conf
3. Initialize each node:

sudo bin/ldown mesh init


4. Start the czar first:

# on czar node only
sudo bin/ldown mesh start


5. Join all other nodes:

# on every non-czar node
sudo bin/ldown mesh join


How it actually works
Czar role
The czar is the trust and membership authority — not a traffic router. It handles JOIN/LEAVE requests, distributes peer lists, and notifies all nodes when membership changes. It is never in the data path. All WireGuard traffic flows directly between peers.
Joining the mesh
When a node runs mesh join:
	1.	It sends a signed JOIN to the czar with its WireGuard pubkey and node signing pubkey
	2.	Czar verifies the node is in the roster
	3.	Czar stores the pubkey, adds the node to its WireGuard interface, and sends the full peer list back
	4.	Czar notifies all existing nodes with a signed PEER_ADD
	5.	Node connects directly to all peers using the received list
Leaving the mesh
When a node runs mesh leave:
	1.	It sends a signed LEAVE to czar — best effort, czar notification is not required for local teardown
	2.	Local cleanup always happens regardless of czar response
	3.	Czar sends PEER_REMOVE to all other nodes
	4.	Interface torn down, mesh.conf deleted, daemons stopped
Recovery
mesh recover rebuilds the entire mesh state from scratch. It only needs:
	∙	/etc/ldown/roster.conf
	∙	/etc/ldown/keys/<name>.private.key
It probes every peer directly, fetches pubkeys, rebuilds mesh.conf and all peer configs, brings up the interface, and starts the listener and sync loop. No czar required.

Commands
make_roster
Interactive wizard to build /etc/ldown/roster.conf.

sudo bin/ldown make_roster


mesh init
Generates WireGuard keypair, Ed25519 node signing keypair, TLS cert, writes mesh.conf. On czar nodes also generates the control-plane signing keypair.

sudo bin/ldown mesh init


mesh start
Forms the full mesh. Czar only. Non-czar nodes use mesh join.

sudo bin/ldown mesh start


mesh join
Joins a live mesh via the czar. Non-czar nodes only. Run after mesh init.

sudo bin/ldown mesh join


mesh leave
Gracefully leaves the mesh. Notifies czar, tears down interface, stops daemons. Local cleanup always happens even if czar is unreachable.

sudo bin/ldown mesh leave


mesh recover
Rebuilds the mesh from zero saved state. Only requires roster.conf and private keys. Probes all peers directly, no czar needed. Starts listener and sync automatically on completion.

sudo bin/ldown mesh recover


mesh status
Shows each peer: up/down/not configured, last handshake, bytes sent/received.

sudo bin/ldown mesh status


mesh export
Creates an encrypted onboarding bundle for a new node. Contains roster, TLS cert, and czar signing public key. No private keys included.

sudo bin/ldown mesh export


mesh import
Unpacks an export bundle on a new node. Installs czar public key and roster. Run before mesh init + mesh join.

sudo bin/ldown mesh import <bundle.tar.gz.enc>


mesh diff
Compares what the roster expects vs what WireGuard actually has configured. Detects missing, unloaded, drifted, and rogue peers.

sudo bin/ldown mesh diff


mesh neighbors
Reachability table — direct/unreachable with tunnel latency and handshake age.

sudo bin/ldown mesh neighbors


mesh doctor
Full health check — keys, TLS cert, interface state, roster, handshake ages, czar reachability.

sudo bin/ldown mesh doctor


mesh reset
Wipes all ldown state from this node. Keeps roster.conf and private keys by default.

sudo bin/ldown mesh reset


listener start / stop / status
Manages the persistent control-plane listener daemon on LDOWN_PORT.

sudo bin/ldown listener start
sudo bin/ldown listener stop
sudo bin/ldown listener status


sync start / stop / status
Manages the background self-healing sync loop.

sudo bin/ldown sync start
sudo bin/ldown sync stop
sudo bin/ldown sync status


Roster Format

# global settings
SUBNET=10.10.0        # tunnel subnet prefix
WG_PORT=51820         # WireGuard port
LDOWN_PORT=51821      # ldown control plane port
CLUSTER_TOKEN=secret  # shared signing token (replaced by Ed25519 in Phase 1)

# nodes — one per line
# format: <public_ip> --name <name> [flags]

203.0.113.10 --name kali1 --czar --relay
203.0.113.11 --name kali2 --keepalive 25
192.168.1.5  --name kali3 --keepalive 25


Flags:

--name        node name (required, used for keys and display)
--czar        this node is the mesh coordinator (exactly one required)
--relay       this node can relay traffic for NAT traversal
--tunnel      override auto-assigned tunnel IP (default: SUBNET.POSITION)
--keepalive   PersistentKeepalive seconds (use for nodes behind NAT)


Onboarding a new node
The operator exports a bundle from the czar and sends it to the new node:

# on czar
sudo bin/ldown mesh export
# sends: ldown-export-<date>.tar.gz.enc

# on new node
sudo bin/ldown mesh import ldown-export-<date>.tar.gz.enc
sudo bin/ldown mesh init
sudo bin/ldown mesh join


The new node needs only the encrypted bundle and the passphrase used during export.

Runtime layout

/etc/ldown/
  mesh.conf               node identity and mesh state
  roster.conf             shared roster (same on all nodes)
  tls.cert / tls.key      node TLS certificate
  keys/
    <name>.private.key    WireGuard private key
    <name>.public.key     WireGuard public key
    <name>-node.key       Ed25519 node signing private key
    <name>-node.pub       Ed25519 node signing public key
    czar-control.key      czar control-plane signing key (czar only)
    czar-control.pub      czar control-plane public key (all nodes)
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


Security model
Current (Phase 0 / Phase 1 in progress)
	∙	Signed control-plane messages — every message signed by sender, verified by receiver
	∙	Per-node Ed25519 signing keypairs — each node has its own identity keypair generated at init
	∙	Czar control-plane keypair — czar has a dedicated signing keypair separate from WireGuard keys
	∙	Source-IP enforcement — PEER_ADD, PEER_REMOVE, and other czar-only messages rejected if not from czar IP
	∙	No unsafe file sourcing — import bundles and runtime configs parsed with whitelist parsers, never sourced
	∙	Tar path traversal protection — extracted paths verified to stay within tmpdir
Allowed without czar
Re-add previously trusted peers, retry known endpoints, adjust confidence scores, log and buffer reports, respond to PROBE requests.
Forbidden without czar
Admit new nodes, trust new pubkeys, change epoch, accept relayed claims from unknown peers, rewrite roster membership, revive dark peers.
Coming in Phase 1 (in progress)
	∙	mTLS short-lived node certificates
	∙	Admission tickets with expiry
	∙	Roster-pinned pubkeys
	∙	Mesh passphrase → WireGuard PSK
	∙	Replay protection (timestamp + nonce)

Architecture direction
ldown is evolving from czar-driven to evidence-backed autonomy.
Czar as epoch authority, not traffic cop. Normal nodes self-heal locally. Czar settles membership, trust, epoch changes, and partition reconciliation. All data traffic flows directly peer-to-peer — czar never sees it.
Peer immune states. Each peer has a confidence score (0–100) based on handshake freshness, neighbor corroboration, endpoint stability, and pubkey consistency. States: HEALTHY → ALTERED_SELF → SUSPECT → QUARANTINED → DARK. RECOVERY is a flag applied to revived peers.
Metabolism modes. Sync interval scales with mesh stress: CALM (30s) → ALERT (15s) → REPAIR (5s) → PARTITION (5s). Fever triggers at 3+ simultaneous peer degradations.
Escalation ladder. L0 passive → L1 local retry → L2 alternate endpoint → L3 relay → L4 PROBE corroboration → L5 czar report → L6 quarantine → L7 epoch intervention.

Project structure

ldown/
├── bin/
│   └── ldown              entry point, subcommand dispatcher
├── lib/
│   ├── common.sh          logging, output, signing, validation
│   ├── wireguard.sh       key gen, config writing, interface control
│   ├── roster.sh          roster parsing and validation
│   ├── mesh.sh            all mesh commands
│   ├── listener.sh        persistent control-plane daemon
│   ├── sync.sh            background self-healing loop
│   └── make_roster.sh     interactive roster wizard
└── conf/
    ├── defaults.conf      default values
    └── roster.conf.example


Roadmap
Phase 0 — Correctness ✓ Complete
All fundamental bugs fixed. Mesh forms, joins, leaves, and recovers correctly.
Phase 1 — Trust hardening (in progress)
Ed25519 per-node signing, czar control-plane keypair, mTLS certificates, admission tickets, roster-pinned pubkeys, PSK, replay protection.
Phase 2 — Observable healing
Structured logs, confidence scoring engine, sync.state, peer-evidence.state, metabolism modes, fever detection, REPORT gossip, escalation ladder, mesh diff –fix.
Phase 3 — Bounded local autonomy
Local reconnect from evidence, relay policy enforcement, PROBE corroboration, recovery/scar tissue, host process isolation via network namespace.
Phase 4 — Partition and election
Regent election, split-brain handling, czar return, epoch reconciliation.
Phase 5 — Operator convenience
mesh status –watch, mesh doctor –fix, mesh evidence, mesh metabolism, listener –foreground.

License
ldown is dual-licensed under the GNU Affero General Public License v3.0 (AGPLv3) and a Commercial License.
Open Source License
Available under AGPLv3. See LICENSE for the full text.
Commercial License
Organizations that need to use this software without complying with AGPL source disclosure requirements must obtain a commercial license from the author.
Nonprofit Consideration
Nonprofit organizations with humanitarian or animal welfare missions are encouraged to apply for a no-cost commercial license.
For licensing inquiries contact the author.

Author
d3dx404
