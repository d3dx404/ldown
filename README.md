# ldown
WireGuard provisioning and network lockdown tool for Linux — client, gateway, and uplink.

> Created 7/3/26 or for you americans 3/7/26— actively in development

---

## Current State

The core library and CLI are functional. Key generation, config writing, and tunnel handshake are working. Network hardening, firewall, and DNS layers are in progress.

---

## Usage

```bash
sudo ./bin/ldown <command> [options]
```

---

## Commands

### `keygen` — generate or manage WireGuard keypairs

```bash
# generate and store a keypair
sudo ./bin/ldown keygen --name server-a

# show existing keypair without regenerating
sudo ./bin/ldown keygen --name server-a --show

# export public key only (pipe-friendly)
sudo ./bin/ldown keygen --name server-a --export

# rotate keypair — backs up old keys with timestamp
sudo ./bin/ldown keygen --name server-a --rotate

# json output
sudo ./bin/ldown keygen --name server-a --format json

# with comment
sudo ./bin/ldown keygen --name server-a --comment "NYC node"
```

Options:
```
--name        keypair name (required)
--dir         key directory (default: /etc/ldown/keys)
--rotate      regenerate keypair, backup old with timestamp
--regen       alias for --rotate
--show        display existing keypair without regenerating
--export      print public key only to stdout
--format      text (default) | json
--comment     label stored in metadata
```

---

### `keys` — display stored keypairs

```bash
# list all keypairs
sudo ./bin/ldown keys

# show specific keypair
sudo ./bin/ldown keys --name server-a

# json output
sudo ./bin/ldown keys --format json
```

Options:
```
--name        show specific keypair only
--dir         key directory (default: /etc/ldown/keys)
--format      text (default) | json
```

---

### `handshake` — configure tunnel and verify peer connection

```bash
sudo ./bin/ldown handshake \
  --name server-a \
  --addr 10.10.0.1/24 \
  --port 51820 \
  --peer-pub <peer public key> \
  --peer-endpoint 192.168.99.1:51820 \
  --peer-allowed 10.10.0.2/32
```

All options can be omitted for interactive mode — ldown will prompt for each value.

Options:
```
--name            keypair to use (from /etc/ldown/keys)
--iface           WireGuard interface name (default: wg0)
--addr            tunnel IP for this machine (e.g. 10.10.0.1/24)
--port            listen port (default: 51820)
--peer-pub        peer's WireGuard public key
--peer-endpoint   peer's real IP and port (e.g. 192.168.99.1:51820)
--peer-allowed    peer's allowed IPs (e.g. 10.10.0.2/32)
--keepalive       PersistentKeepalive in seconds (omit for direct connections)
```

Flow:
```
1. validate inputs
2. write interface config
3. write peer config
4. assemble wg0.conf
5. bring up interface
6. check interface, wireguard, peer
7. wait up to 20s for handshake
8. report success or failure with reason
```

---

## Key Storage

Keys are stored in `/etc/ldown/keys/` with the following layout:

```
/etc/ldown/keys/
  server-a.private.key      chmod 600 — never shared
  server-a.public.key       chmod 600 — share with peers
  server-a.meta             created timestamp and comment
  server-a.private.key.TIMESTAMP.bak   created on --rotate
```

Private keys are never printed after initial generation.

---

## Config Layout

```
/etc/ldown/
  wg0/
    interface.conf     [Interface] block
    peers/
      peer.conf        [Peer] block — one file per peer
    wg0.conf           assembled from above — never hand-edited
```

---

## Current Structure

```
ldown/
├── bin/
│   └── ldown              ← entry point, subcommand dispatcher
├── lib/
│   ├── common.sh          ← logging, output, validation, execution helpers
│   └── wireguard.sh       ← key gen, config writing, interface control, diagnostics
```

---

## Roadmap

### Near term
```
lib/network.sh
  → IP forwarding
  → NAT / masquerade
  → killswitch (drop traffic if tunnel goes down)
  → IPv6 disable
  → DHCP control
  → route management

lib/firewall.sh
  → nftables ruleset generation
  → iptables fallback
  → per-mode rulesets (client / gateway / uplink)

lib/dns.sh
  → dnscrypt-proxy setup
  → DNS leak prevention
  → resolver config
```

### CLI commands
```
ldown status          → live tunnel state, handshake age, transfer stats
ldown down            → tear down tunnel and restore network state
ldown peer add        → add peer to existing tunnel without restart
ldown peer list       → list configured peers
ldown peer remove     → remove peer by name or pubkey
ldown serve-key       → serve public key over local HTTP for exchange
ldown fetch-key       → fetch peer public key from remote ldown instance
```

### Modes (future)
```
ldown --mode client    → road warrior client setup
ldown --mode gateway   → LAN gateway with NAT and firewall
ldown --mode uplink    → VPS or uplink node
```

### Other
```
conf/defaults.conf     → default values, overridable per deployment
templates/             → WireGuard and nftables config templates
log rotation           → already implemented in common.sh
mac randomization      → macchanger integration
dry-run mode           → already implemented in common.sh via DRY_RUN
```

---

## Requirements

- Kali / Debian-based Linux
- `wireguard-tools`
- `nftables` or `iptables`
- `bash` >= 4.2
- Root / sudo

Optional (for future features):
- `macchanger`
- `dnscrypt-proxy`

---

## License

GNU General Public License v3.0 — see [LICENSE](LICENSE)

---

## Author

d3dx404
