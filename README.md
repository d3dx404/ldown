# ldown

WireGuard provisioning and network lockdown tool for Linux — client, gateway, and uplink.

created 7/3/26 or for you americans 3/7/26 : still being worked on
---

## Usage

```bash
sudo ./ldown --mode client|gateway|uplink [OPTIONS]
```

## Options

```
--mode              client | gateway | uplink
--iface-lan         LAN interface (e.g. ens37)
--iface-wan         WAN interface (e.g. ens35)
--ip                Static IP with CIDR (e.g. 192.168.99.2/24)
--peer-pubkey       WireGuard public key of peer
--peer-endpoint     Peer address and port (e.g. 192.168.99.1:51820)
--port              WireGuard listen port (default: 51820)
--uplink-type       vps | vpn  (uplink mode only)
--disable-dhcp      Disable DHCP on LAN interface
--no-ipv6           Disable IPv6
--dns-encrypt       Enable dnscrypt-proxy
--killswitch        Enable kill switch (drops traffic if tunnel goes down)
--verbosity         0=quiet 1=normal 2=verbose 3=debug
--dry-run           Show what would happen without making changes
--status            Show current state of tunnel, firewall, and interfaces
--down              Tear down tunnel and restore network state
--rotate-keys       Rotate WireGuard keypair
--log               Log file path (default: /var/log/ldown.log)
```

## Examples

```bash
# Gateway
sudo ./ldown --mode gateway --iface-lan ens34 --iface-wan ens35 --ip 192.168.99.1/24 --no-ipv6 --killswitch --verbosity 2

# Client
sudo ./ldown --mode client --iface-lan ens37 --ip 192.168.99.2/24 --peer-pubkey <key> --peer-endpoint 192.168.99.1:51820 --killswitch

# Uplink (VPS)
sudo ./ldown --mode uplink --uplink-type vps --iface-wan ens35 --ip 10.0.0.1/24 --port 51820

# Dry run
sudo ./ldown --mode gateway --iface-lan ens34 --iface-wan ens35 --ip 192.168.99.1/24 --dry-run --verbosity 3

# Tear down
sudo ./ldown --down

# Status
sudo ./ldown --status
```

## Structure

```
ldown/
├── ldown                  ← entry point
├── lib/                   ← common, preflight, detect, crypto, network,
│                             firewall, dns, tunnel, services, verify
├── modules/               ← client.sh, gateway.sh, uplink.sh
├── conf/                  ← ldown.conf.example, defaults.conf
├── templates/             ← WireGuard and nftables templates
├── rotate/                ← rotate-keys.sh
├── keys/                  ← never committed
└── logs/                  ← never committed
```

## Requirements

- Kali / Debian-based Linux
- `wireguard-tools`
- `nftables` or `iptables`
- `macchanger`
- `dnscrypt-proxy` (if using `--dns-encrypt`)
- Root / sudo

## License

GNU General Public License v3.0 — see [LICENSE](LICENSE)

## Author

d3dx404
