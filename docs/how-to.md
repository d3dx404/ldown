# ldown — Bootstrap & Setup Guide

Everything you need to get a mesh running from scratch.

---

## What you need before starting

- Two or more Linux nodes (Kali / Debian-based)
- `wireguard-tools`, `ncat`, `openssl` installed on all nodes
- Root / sudo on all nodes
- All nodes able to reach each other on ports `51820` (WireGuard), `51821` (control plane), `51822` (bootstrap)
- ldown cloned on every node:

```bash
git clone -b alpha https://github.com/d3dx404/ldown
cd ldown
chmod +x bin/ldown
```

---

## Step 1 — Write the roster on every node

The roster is the one file you write manually. It describes every node in the mesh — their IPs, names, roles, and network settings. It must be identical on every node.

```bash
sudo mkdir -p /etc/ldown
sudo nano /etc/ldown/roster.conf
```

Paste this structure and fill in your actual IPs:

```
SUBNET=10.10.0
WG_PORT=51820
LDOWN_PORT=51821
BOOTSTRAP_PORT=51822

203.0.113.10 --name kali1 --czar --relay
203.0.113.11 --name kali2 --keepalive 25
203.0.113.12 --name kali3 --keepalive 25
```

**What each line means:**

`SUBNET=10.10.0` — the tunnel subnet. Nodes get tunnel IPs of `10.10.0.1`, `10.10.0.2`, etc. based on their line position. Do not include the last octet.

`WG_PORT=51820` — the WireGuard listen port. Same on all nodes unless you override per-node with `--port`.

`LDOWN_PORT=51821` — the ldown control plane port. The listener runs here. Must be the same on all nodes.

`BOOTSTRAP_PORT=51822` — the bootstrap port. Used during initial onboarding only. Can be closed after all nodes have joined.

**Node line format:** `<public_ip> --name <name> [flags]`

| Flag | Required | Description |
|---|---|---|
| `--name` | yes | Human-readable node name. Used for keys, logs, display. Letters, numbers, hyphens only. |
| `--czar` | one node | Designates the mesh coordinator. Exactly one node must have this. |
| `--relay` | optional | This node can forward traffic for NAT-blocked peers. Should have a publicly reachable IP. |
| `--keepalive` | NAT nodes | Sets `PersistentKeepalive` in seconds. Use `25` for nodes behind NAT. |
| `--tunnel` | optional | Override the auto-assigned tunnel IP. Default is `SUBNET.POSITION`. |
| `--port` | optional | Override the WireGuard listen port for this specific node. |

**Tunnel IP assignment:**
Nodes get tunnel IPs by line position — line 1 gets `SUBNET.1`, line 2 gets `SUBNET.2`, and so on. The ordering of nodes in the roster determines their tunnel IPs. Never reorder lines after the mesh is live unless you also set `--tunnel` explicitly.

**Distribute the roster:**
Copy the roster to every node before continuing. The simplest way:

```bash
# from czar, SCP to each peer
sudo scp /etc/ldown/roster.conf user@<peer-ip>:/tmp/roster.conf
ssh user@<peer-ip> "sudo mkdir -p /etc/ldown && sudo mv /tmp/roster.conf /etc/ldown/roster.conf"
```

Or use the tee method directly on each node:

```bash
sudo tee /etc/ldown/roster.conf << 'ROSTER'
SUBNET=10.10.0
WG_PORT=51820
LDOWN_PORT=51821
BOOTSTRAP_PORT=51822

203.0.113.10 --name kali1 --czar --relay
203.0.113.11 --name kali2 --keepalive 25
203.0.113.12 --name kali3 --keepalive 25
ROSTER
```

Verify it looks right on every node:

```bash
cat /etc/ldown/roster.conf
```

---

## Step 2 — Initialize the czar

Run this on the czar node only:

```bash
sudo bin/ldown mesh init
```

**What this does:**

ldown reads the roster, identifies this machine by matching its IP against the roster entries, and sets up everything it needs.

- **WireGuard keypair** — generates `<name>.private.key` and `<name>.public.key` in `/etc/ldown/keys/`. These are your WireGuard identity keys. If they already exist, init skips generation.

- **Ed25519 node signing keypair** — generates `<name>-node.key` and `<name>-node.pub`. Every message sent by this node is signed with this key. Other nodes verify messages against the stored pub key.

- **Ed25519 czar control keypair** — czar only. Generates `czar-control.key` and `czar-control.pub`. Messages that only czar is allowed to send (`PEER_ADD`, `PEER_REMOVE`) are signed with this key. All nodes verify czar messages against `czar-control.pub`.

- **ECDSA P-256 Certificate Authority** — czar only. Generates `ca.key` and `ca.cert`. The CA signs 7-day TLS certificates for every node that joins. Nodes use these certs for SSL on the control plane.

- **TLS certificate** — czar gets a CA-signed cert immediately. Peers get a self-signed placeholder here; the real CA-signed cert is issued by czar at JOIN.

- **WireGuard PSK** — optional. If you enter a passphrase, ldown derives a 32-byte pre-shared key and writes it to `/etc/ldown/keys/mesh.psk`. This adds a second layer of encryption to all WireGuard tunnels. All nodes must use the same passphrase. If you skip it on czar, PSK is distributed via the export bundle.

- **mesh.conf** — writes `/etc/ldown/mesh.conf` with this node's identity: name, IP, tunnel IP, czar IP, ports, TLS fingerprint, signing pubkey.

After init you should see keys in `/etc/ldown/keys/`:

```bash
sudo ls /etc/ldown/keys/
```

Expected on czar:
```
ca.cert          ca.key           czar-control.key  czar-control.pub
kali1-node.key   kali1-node.pub   kali1.private.key kali1.public.key
mesh.psk         kali1.csr
```

WireGuard is still down at this point — init only generates keys and writes config. Nothing is running yet.

```bash
sudo wg show
# interface: (nothing)
```

---

## Step 3 — Start the czar with bootstrap

```bash
sudo bin/ldown mesh start --bootstrap --time 300
```

**What `mesh start` does:**

1. **Pre-flight cleanup** — kills any stale listener, sync loop, or ncat processes. Tears down wg0 if it exists. Ensures a clean slate.

2. **Brings up WireGuard** — creates the `wg0` interface, assigns the czar's tunnel IP (`10.10.0.1/24`), sets the listen port.

3. **Starts the listener** — launches an ncat SSL listener on `LDOWN_PORT` (51821). This is the control plane — it accepts JOIN, LEAVE, PEER_ADD, PUBKEY, PING, and REPORT messages. All connections are TLS-encrypted using the CA-signed cert.

4. **Starts the sync loop** — launches the self-healing background daemon. It runs every 30 seconds, checks handshake age for every peer, re-adds stale peers, and reports persistent failures to czar.

5. **Auto-generates export bundle** — if no bundle exists, ldown automatically runs `mesh export`. You will be prompted for an export passphrase. This passphrase encrypts the bundle — share it securely with your peers (Signal, in-person, etc.). The bundle contains everything peers need to join: roster, CA cert, czar signing key, PSK.

6. **Opens bootstrap listener** — opens a plaintext listener on `BOOTSTRAP_PORT` (51822). Peers connect here to receive the bundle and an admission ticket automatically. This listener closes automatically once all peers have joined or the timeout expires.

**The `--time 300` flag** sets the bootstrap timeout to 300 seconds (5 minutes). Default is 120 seconds. Use a longer timeout if you have many peers or slow connections.

You should see:

```
✓ interface up        wg0 — 10.10.0.1/24
✓ listener            pid XXXX on 192.168.108.128:51821
✓ sync loop started   pid XXXX — every 30s
✓ bootstrap listener  pid XXXX on 192.168.108.128:51822
[*] waiting for 5 peers — auto-closes after all join or 300s
```

The czar is now live and waiting. Move to the peer nodes.

---

## Step 4 — Bootstrap peer nodes

Run this on **every non-czar node**:

```bash
sudo bin/ldown mesh init --bootstrap
```

**What `mesh init --bootstrap` does:**

The `--bootstrap` flag changes the init flow for peers:

1. **Generates local keys** — WireGuard keypair, Ed25519 node signing keypair, TLS key and CSR. Same as regular init, except:
   - PSK prompt is skipped (the bundle delivers the PSK)
   - CA generation is skipped (czar is the CA)
   - TLS cert is a self-signed placeholder (czar will replace it at JOIN)

2. **Contacts czar bootstrap port** — connects to czar on port 51822 and sends `BOOTSTRAP|<name>`. Czar looks up the node name in the roster, auto-creates an admission ticket, and responds with the encrypted bundle.

3. **Receives the bundle** — you will be prompted for the export passphrase (the one you set on czar in Step 3). Enter it to decrypt. The bundle is unpacked and installs:
   - `/etc/ldown/roster.conf` — the shared roster
   - `/etc/ldown/keys/czar-control.pub` — czar's signing key (used to verify PEER_ADD messages)
   - `/etc/ldown/keys/ca.cert` — the CA certificate (used for TLS verification)
   - `/etc/ldown/keys/mesh.psk` — WireGuard PSK (if configured)
   - `/etc/ldown/tickets/<name>` — the one-time admission ticket for this node

4. **Automatically runs mesh join** — no manual step needed. After import completes, the node:
   - Brings up WireGuard
   - Sends a signed JOIN to czar over SSL (port 51821)
   - Czar verifies the signature, validates the ticket (consumed immediately), signs the node's TLS CSR with the CA, and returns a CA-signed cert + full peer list
   - Node installs the signed cert, connects to all peers, starts the listener and sync loop

**What the JOIN exchange delivers to the peer:**

- `CERT:<b64>` — CA-signed TLS certificate valid for 7 days. Replaces the self-signed placeholder.
- `CA:<b64>` — CA certificate. Stored at `/etc/ldown/keys/ca.cert`.
- One line per existing peer: `<name> <tunnel_ip> <endpoint> <wg_pubkey> <keepalive> <node_pub_b64>`

The peer adds every node in that list to its WireGuard interface and starts trying to handshake.

**Czar simultaneously:**

After processing the JOIN, czar sends a signed `PEER_ADD` message to every existing node telling them about the new peer. They add it to their WireGuard interface. This is how a joining node gets distributed to the rest of the mesh without the other nodes doing anything manually.

---

## Step 5 — Watch the mesh come up

On czar (or any node after it joins):

```bash
sudo bin/ldown mesh watch
```

You should see peers appearing as `✓ up` as they complete their JOIN and handshakes succeed. The bootstrap counter in the SYSTEM section shows how many peers have joined.

```
bootstrap ✦ serving  3/5 joined  120s remaining
```

Once all peers have joined:

```
bootstrap ✓ complete  5/5 joined
```

All peers should show `✓ up` with handshake ages under 150 seconds. The sync loop handles anything that doesn't connect immediately — it re-adds stale peers automatically every 30 seconds.

**Peer status indicators:**

| Symbol | Meaning |
|---|---|
| `✓ up` | Handshake within last 150 seconds — tunnel is live |
| `~ stale` | Handshake between 150–190 seconds — sync loop is re-adding |
| `✗ down` | No handshake in over 190 seconds — sync loop is working on it |
| `◝ wait` | Peer exists in wg0 but no handshake yet — connecting |
| `⊘ left` | Peer sent LEAVE — intentionally offline |

---

## Step 6 — Verify everything is working

Check WireGuard is up and peers are connected:

```bash
sudo wg show
```

You should see all peers listed with recent handshake timestamps and traffic flowing.

Check TLS certificates are CA-signed:

```bash
openssl x509 -in /etc/ldown/tls.cert -noout -issuer -subject -dates
```

Czar-signed certs show `issuer=CN=ldown-ca`. The cert expires in 7 days and is renewed automatically at the next `mesh join`.

Check the PSK is active (if configured):

```bash
sudo wg show wg0 preshared-keys
```

All peers should show a non-empty preshared-key value.

Check the sync loop is running:

```bash
sudo bin/ldown sync status
sudo tail -f /var/log/ldown/sync.log
```

---

## What runs permanently

After a successful bootstrap, three things run continuously on every node:

**WireGuard interface (`wg0`)** — the encrypted mesh tunnel. Traffic flows directly between peers. Czar is never in the data path.

**Listener daemon** — ncat SSL server on port 51821. Accepts control plane messages: JOIN, LEAVE, PEER_ADD, PEER_REMOVE, PUBKEY, PING, REPORT. Runs the handler script that processes each message.

**Sync loop** — background daemon running every 30 seconds. Checks handshake age for every peer. If a peer is stale, re-adds it to WireGuard and pings the tunnel IP to trigger a handshake. After 3 consecutive failed re-adds, sends a REPORT to czar. Czar receives the report and broadcasts a fresh PEER_ADD to all nodes to force everyone to re-add the peer.

---

## Day 2 operations

### Adding a new node after bootstrap is closed

```bash
# on czar — create a ticket for the new node first
sudo bin/ldown mesh ticket create <new-node-name>

# on czar — export a fresh bundle
sudo bin/ldown mesh export

# transfer bundle to new node, then on new node:
sudo bin/ldown mesh import ldown-export-<timestamp>.tar.gz.enc
sudo bin/ldown mesh init
sudo bin/ldown mesh join
```

### A node leaves the mesh

```bash
# on the leaving node
sudo bin/ldown mesh leave
```

This sends a signed LEAVE to czar, which broadcasts PEER_REMOVE to all nodes. The leaving node's WireGuard interface is torn down and mesh.conf is deleted. Keys are kept so it can rejoin later.

### Rejoining after a leave

```bash
sudo bin/ldown mesh init
sudo bin/ldown mesh join
```

Czar will need a new ticket if tickets are being enforced:

```bash
# on czar
sudo bin/ldown mesh ticket create <name>
```

### A node crashes or loses state

If a node loses its mesh.conf but keeps its keys:

```bash
sudo bin/ldown mesh init
sudo bin/ldown mesh join
```

If a node loses everything (full reset needed):

```bash
sudo bin/ldown mesh reset -y
# then follow Steps 1-4 again for that node
```

### Wiping a node completely

```bash
sudo bin/ldown mesh reset -y
```

This removes `/etc/ldown/`, `/var/log/ldown/`, and the WireGuard interface. Keys, certs, and all state are gone. Notifies czar via LEAVE before wiping if mesh.conf exists.

### Stopping all ldown daemons

```bash
sudo bin/ldown stop
```

Kills listener and sync loop. Does not tear down WireGuard. Use `mesh leave` for a clean departure.

---

## Troubleshooting

### `could not detect this machine's IP from roster`

ldown couldn't match this machine's IP to any roster entry. Check:

```bash
ip route get 1.1.1.1   # should return your public/LAN IP
cat /etc/ldown/roster.conf   # verify your IP appears as the first field on a node line
```

Make sure the roster format is `<ip> --name <name>` not `--name <name> --ip <ip>`.

### `could not reach czar bootstrap at <ip>:51822`

The czar's bootstrap listener isn't running or the timeout expired. Check on czar:

```bash
sudo cat /run/ldown/bootstrap.pid
sudo kill -0 $(sudo cat /run/ldown/bootstrap.pid) && echo "running" || echo "dead"
sudo ss -tlnp | grep 51822
```

If dead, restart czar bootstrap:

```bash
sudo bin/ldown mesh start --bootstrap --time 600
```

### `sig verify failed for PEER_ADD from czar`

The czar-control.pub on this node doesn't match what czar is signing with. This usually means the bundle was exported before czar regenerated its keys. Export a fresh bundle from czar and re-run `mesh init --bootstrap` on the affected peer.

### Peer shows `✗ down` in watch

The sync loop will attempt to re-add it automatically within 30 seconds. If it stays down:

```bash
sudo tail -20 /var/log/ldown/sync.log
sudo wg show wg0 latest-handshakes
```

If the peer has a handshake timestamp of `0` (never connected), it may have the wrong endpoint. A clean `mesh join` on the affected peer fixes it.

### ncat SSL connection timeout

The listener is up but SSL handshake is hanging. Check for CLOSE-WAIT connections on czar:

```bash
sudo ss -tnp | grep 51821
```

If you see many `CLOSE-WAIT` entries, restart the listener:

```bash
sudo bin/ldown listener stop
sudo bin/ldown listener start
```

### WireGuard PSK mismatch (no handshake, no error)

If PSK is configured on czar but not on a peer, WireGuard silently refuses to handshake. Check all nodes have the same PSK:

```bash
sudo cat /etc/ldown/keys/mesh.psk | wc -c   # should be 45 (44 chars + newline)
```

The export bundle distributes the PSK automatically. If a node is missing it, re-import the bundle.

### Clock skew: `stale message` or `replay detected`

Messages include a timestamp and are rejected if older than 60 seconds. If clocks are out of sync:

```bash
sudo chronyc makestep
# or
sudo ntpdate -u pool.ntp.org
```

---

## Security notes

**The export bundle is encrypted but not authenticated.** Anyone with the passphrase can import it. Treat the passphrase like a password — share it over a separate secure channel from the bundle itself.

**Admission tickets are one-time.** Each ticket is consumed at JOIN and cannot be reused. If a JOIN fails after the ticket is consumed, create a new one on czar with `mesh ticket create <name>`.

**TLS certificates expire in 7 days.** They are renewed automatically at `mesh join`. Long-lived nodes that never rejoin will eventually have expired certs. Run `mesh join` to renew.

**The CA private key never leaves czar.** `ca.key` is generated on czar and never included in export bundles. If czar is compromised, the CA is compromised. Rotate by running `mesh reset` on czar and re-bootstrapping.

**WireGuard keys are permanent until rotated.** There is no automatic key rotation. Use `mesh init --rotate-keys` (Phase 5) when implemented, or `mesh reset` + `mesh init` for a full rotation.
