# ldown Phase 1 Migration Guide

## Overview

Phase 1 replaces the entire control plane security model. This is a
**breaking change** — old nodes cannot communicate with new nodes.
All nodes must be upgraded simultaneously.

## What Changed

### Removed
- **CLUSTER_TOKEN** — no longer used for any authentication
  - Remove `CLUSTER_TOKEN=` line from roster.conf (optional, parser ignores it)
  - HMAC signing/verification completely removed

### Added
- **Ed25519 per-node signing** — every node signs messages with its own key
- **Czar control key** — PEER_ADD/PEER_REMOVE signed with czar-control.key
- **V1 message envelope** — `V1|timestamp|nonce|ACTION fields...`
  - 60-second timestamp window
  - Nonce replay protection (stored in /run/ldown/nonces/)
- **ECDSA P-256 TLS certificates** — all ncat connections use SSL
  - Czar acts as Certificate Authority (ca.key/ca.cert)
  - Node certs signed by czar at JOIN (7-day lifetime)
- **WireGuard PSK** — optional passphrase-derived pre-shared key
- **Roster-pinned verification** — PEER_ADD/PEER_REMOVE rejected if name+tunnel not in roster
- **Source IP verification** — czar-only messages checked against CZAR_IP
- **Admission tickets** — optional one-time JOIN tokens

## Migration Steps

### Prerequisites
- All nodes must be able to reach czar
- All nodes must have the same roster.conf
- Schedule downtime — mesh will be fully offline during migration

### Step 1: Stop the mesh on ALL nodes

On every non-czar node first:

```bash
sudo ldown mesh leave
```

This sends a LEAVE to the czar, tears down the WireGuard interface, and
removes mesh.conf. Keys are kept so they can be replaced cleanly.

Then on czar:

```bash
sudo ldown stop
```

> **Order matters.** Stopping czar last ensures LEAVE messages are processed.
> If peers are unreachable, `ldown stop` on each node is fine — the czar
> will see them as gone when the new mesh forms.

### Step 2: Update ldown on ALL nodes

```bash
cd /path/to/ldown
git pull origin alpha    # or your branch
```

Repeat on every node. Do not start ldown yet.

### Step 3: Full reset on czar

The old czar state is incompatible. Wipe it and regenerate everything:

```bash
sudo ldown mesh reset
```

This removes `/etc/ldown/`, `/var/log/ldown/`, and the WireGuard interface.
It will ask for confirmation twice.

Then run init to generate all new keys, CA, and TLS cert:

```bash
sudo ldown mesh init
```

During init, czar will:
- Generate an Ed25519 node signing keypair (`<name>-node.key/.pub`)
- Generate an Ed25519 czar control keypair (`czar-control.key/.pub`)
- Generate an ECDSA P-256 Certificate Authority (`ca.key` / `ca.cert`)
- Generate an ECDSA P-256 TLS keypair + CSR, sign it with the CA (7-day cert)
- Optionally derive a WireGuard PSK from a passphrase

If you want all nodes to share a WireGuard PSK, enter the same passphrase
on czar when prompted. Leave blank to skip (PSK is optional).

> **Keep the passphrase secret.** If you use one, every node must use the
> exact same passphrase during their own `ldown mesh init`. Alternatively,
> skip the passphrase on czar and distribute the PSK via the export bundle
> (czar's init derives the PSK and exports it automatically).

### Step 4: Create admission tickets for each peer

For each non-czar node that will join the mesh, create a one-time ticket:

```bash
sudo ldown mesh ticket create <node-name>
```

Example for a three-node mesh with peers `node-a` and `node-b`:

```bash
sudo ldown mesh ticket create node-a
sudo ldown mesh ticket create node-b
```

Each command prints the token to stdout and writes it to
`/etc/ldown/tickets/<node-name>` on the czar. The token is consumed
(deleted) the moment the peer successfully joins — it cannot be reused.

List pending tickets at any time:

```bash
sudo ldown mesh ticket list
```

To revoke a ticket before it is used:

```bash
sudo ldown mesh ticket revoke <node-name>
```

> **If no tickets directory exists** on the czar, JOIN is accepted without
> a ticket (open mode). As soon as `/etc/ldown/tickets/` contains any file,
> every node without a matching ticket will be rejected. This lets you
> adopt tickets incrementally if needed.

### Step 5: Export the onboarding bundle

On czar, export a bundle containing everything peers need to bootstrap:

```bash
sudo ldown mesh export
```

You will be prompted for an encryption passphrase. The output is an
AES-256-CBC encrypted tarball:

```
ldown-export-<timestamp>.tar.gz.enc
```

The bundle contains:
- `roster.conf` — the shared peer list
- `cluster.pub` — czar's Ed25519 control public key
- `tls.cert` — czar's TLS certificate (peers use this as a temporary
  bootstrap; their own cert is issued by czar at JOIN)
- `mesh.psk` — WireGuard pre-shared key, if one was configured
- `mesh_export.conf` — czar IP, port, subnet

> **The bundle does not contain any private keys.** It is safe to
> transmit over a reasonably trusted channel. The AES passphrase is the
> primary confidentiality control — share it via a separate secure path
> (Signal, in-person, etc.).

### Step 6: Distribute bundle and tickets to each peer

For each peer, you need to transfer:
1. The export bundle (`ldown-export-*.tar.gz.enc`)
2. The AES decryption passphrase (separate channel)
3. The admission ticket token (separate channel)

Ticket tokens are printed by `ldown mesh ticket create` and stored on
czar at `/etc/ldown/tickets/<name>`. Read them back if needed:

```bash
cat /etc/ldown/tickets/node-a
```

Transfer the bundle via any secure channel:

```bash
scp ldown-export-*.tar.gz.enc user@node-a:/tmp/
```

### Step 7: Reset and init each peer node

On **each peer node**:

#### 7a. Wipe old state

```bash
sudo ldown mesh reset
```

#### 7b. Import the bundle

```bash
sudo ldown mesh import /tmp/ldown-export-*.tar.gz.enc
```

Enter the AES decryption passphrase when prompted. This installs:
- `/etc/ldown/roster.conf`
- `/etc/ldown/keys/czar-control.pub` (czar signing key)
- `/etc/ldown/keys/mesh.psk` (if included)
- `/etc/ldown/mesh_export.conf` (network config)

#### 7c. Run init

```bash
sudo ldown mesh init
```

The node will:
- Generate its Ed25519 node signing keypair
- Generate an ECDSA P-256 TLS keypair and CSR
- Create a self-signed TLS placeholder cert (czar replaces this at JOIN)
- Write `mesh.conf` with its own identity

If the mesh uses a WireGuard PSK, init will prompt for the passphrase.
If `mesh.psk` was included in the bundle, init skips the prompt (PSK
already present). Must match what czar used.

#### 7d. Install the admission ticket

The peer reads its own ticket from `/etc/ldown/tickets/<my-name>`:

```bash
sudo mkdir -p /etc/ldown/tickets
echo "<TOKEN-FROM-CZAR>" | sudo tee /etc/ldown/tickets/<my-name>
sudo chmod 600 /etc/ldown/tickets/<my-name>
```

Replace `<TOKEN-FROM-CZAR>` with the value printed by
`ldown mesh ticket create` on the czar.
Replace `<my-name>` with this node's name as it appears in roster.conf.

### Step 8: Start the mesh on czar

```bash
sudo ldown mesh start
```

Czar brings up the WireGuard interface, starts the listener (with TLS),
and starts the self-healing sync loop.

### Step 9: Join from each peer node

On each peer (order does not matter):

```bash
sudo ldown mesh join
```

The JOIN flow:
1. Peer sends: `JOIN <name> <tunnel_ip> <public_ip> <wg_pubkey> <node_pub_b64> <csr_b64> <ticket>`
2. Czar verifies Ed25519 signature, checks V1 envelope (timestamp + nonce)
3. Czar verifies ticket → consumes it (one-time)
4. Czar signs peer's TLS CSR with CA → returns `CERT:<b64>` + `CA:<b64>`
5. Peer installs signed cert (`/etc/ldown/tls.cert`) and CA cert (`/etc/ldown/keys/ca.cert`)
6. Czar sends PEER_ADD (czar-control signed) to all existing peers
7. Peer receives existing peer list, adds them to WireGuard
8. Peer starts listener (TLS) and sync loop

Add `--watch` for a live dashboard after join:

```bash
sudo ldown mesh join --watch
```

### Step 10: Verify the mesh

On any node:

```bash
sudo ldown mesh watch
```

All peers should show a recent handshake timestamp. A peer with `⊘ left`
means it sent a LEAVE and is intentionally offline.

Check TLS cert details on any node:

```bash
openssl x509 -in /etc/ldown/tls.cert -noout -issuer -subject -dates
```

Czar-signed certs will show `issuer=CN=ldown-ca`. The cert is valid for
7 days and automatically renewed on the next `mesh join`.

Check WireGuard PSK is active (if configured):

```bash
sudo wg show wg0 preshared-keys
```

All peers should show a non-empty preshared-key entry.

---

## File Inventory After Migration

| Path | Node | Contents |
|------|------|----------|
| `/etc/ldown/keys/ca.key` | czar only | CA private key — never leaves czar |
| `/etc/ldown/keys/ca.cert` | all nodes | CA certificate (installed at JOIN) |
| `/etc/ldown/keys/czar-control.key` | czar only | Czar Ed25519 signing key |
| `/etc/ldown/keys/czar-control.pub` | all nodes | Czar Ed25519 verifying key |
| `/etc/ldown/keys/<name>-node.key` | owner only | Node Ed25519 signing key |
| `/etc/ldown/keys/<name>-node.pub` | all nodes | Node Ed25519 verifying key |
| `/etc/ldown/keys/mesh.psk` | all nodes | WireGuard PSK (if configured) |
| `/etc/ldown/tls.key` | owner only | Node TLS private key |
| `/etc/ldown/tls.cert` | owner only | Node TLS cert (CA-signed, 7-day) |
| `/etc/ldown/tickets/<name>` | czar only | Pending one-time JOIN token |
| `/run/ldown/nonces/` | all nodes | Seen nonces (TTL 2 min, auto-cleaned) |
| `/run/ldown/left_peers` | czar | Names of nodes that sent LEAVE |

---

## Rollback

There is no in-place rollback. The protocol is not backward-compatible.

To revert to the old version:
1. `sudo ldown stop` on all nodes
2. `git checkout <old-commit>` on all nodes
3. `sudo ldown mesh reset` on all nodes
4. Re-run your old `ldown mesh init` + `ldown mesh start/join` flow

---

## Troubleshooting

### JOIN rejected: "invalid ticket"
The token in `/etc/ldown/tickets/<name>` on the **peer** does not match
what is in `/etc/ldown/tickets/<name>` on the **czar**.
Revoke and recreate the ticket on czar, then update the file on the peer.

### JOIN rejected: "ticket required"
The czar's `/etc/ldown/tickets/` directory is non-empty but this peer has
no ticket file. Create one: `sudo ldown mesh ticket create <name>` on czar.

### JOIN rejected: "sig verify failed"
The joining node's Ed25519 signing key does not match the embedded
`node_pub_b64` in the message, or the signature is malformed.
Re-run `ldown mesh init` on the peer to regenerate signing keys.

### JOIN rejected: "stale message" or "replay detected"
The node's clock is out of sync (>60 seconds from czar), or the same
nonce was reused. Sync system clocks with `chronyc makestep` or
`ntpdate -u <server>`.

### ncat TLS connection refused
The czar listener expects `--ssl`. All client connections use
`ncat --ssl`. If you see a TLS handshake error, the node is likely
running old code. Update and re-run `ldown mesh init`.

### WireGuard PSK mismatch
If PSK is configured on czar but not on a peer (or vice versa),
WireGuard will not complete handshake (silently fails). Check
`/etc/ldown/keys/mesh.psk` exists on all nodes and contains the same
32-byte base64 value. The export bundle distributes the PSK automatically.

### Cert expired (7-day TLS cert)
Node TLS certs are renewed automatically at `mesh join`. If a long-lived
node has an expired cert, `ldown stop` it and run `ldown mesh join` again.
The czar will re-sign a fresh 7-day cert.
