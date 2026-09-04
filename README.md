![Logo](admin/wireguard-s2s.svg)

# ioBroker.wireguard-s2s

[![NPM version](https://img.shields.io/npm/v/iobroker.wireguard-s2s.svg)](https://www.npmjs.com/package/iobroker.wireguard-s2s)
[![Downloads](https://img.shields.io/npm/dm/iobroker.wireguard-s2s.svg)](https://www.npmjs.com/package/iobroker.wireguard-s2s)
![Number of installations](https://iobroker.live/badges/wireguard-s2s-installed.svg)
![Current version in stable repository](https://iobroker.live/badges/wireguard-s2s-stable.svg)
[![Test and Release](https://github.com/System-9/ioBroker.wireguard-s2s/actions/workflows/test-and-release.yml/badge.svg)](https://github.com/System-9/ioBroker.wireguard-s2s/actions/workflows/test-and-release.yml)

This adapter configures and monitors **one WireGuard site-to-site peer** on the Linux host running ioBroker. It creates a dedicated `iowgN` interface, assigns tunnel addresses, installs routes for the remote networks and exposes handshake and traffic states in ioBroker.

It integrates the open-source [WireGuard VPN](https://www.wireguard.com/) with ioBroker. WireGuard is a registered trademark of Jason A. Donenfeld.

The first release deliberately has a narrow scope: one adapter instance manages one interface and one peer. Run a second instance for another site.

## What it does

- creates or updates a dedicated WireGuard interface (`iowg0` … `iowg999`);
- supports IPv4, IPv6, an optional endpoint and a preshared key;
- installs explicit routes for the remote tunnel address and remote LANs;
- can enable kernel IP forwarding at runtime;
- reports interface state, public key, endpoint, last handshake, RX and TX counters;
- exposes `control.apply`, `control.down` and `control.refresh` buttons;
- encrypts the private key and preshared key using ioBroker `encryptedNative` storage.

It does **not** modify nftables/iptables, configure NAT, open a router port, change the remote peer or create permanent sysctl files. Firewall policy and LAN router routes are environment-specific and remain under administrator control.

## Requirements

- Linux ioBroker host;
- Node.js 22 or newer;
- ioBroker js-controller 6.0.11 or newer;
- ioBroker Admin 7.6.20 or newer;
- installed `wireguard-tools`, `iproute2`, `procps`/`sysctl` and `sudo`;
- UDP port forwarding on the internet router when this site accepts incoming WireGuard connections.

On Debian/Ubuntu, the system packages are normally installed with:

```bash
sudo apt update
sudo apt install wireguard-tools iproute2 procps sudo
```

## Installation

Install the adapter in ioBroker, then install its privileged helper once on the ioBroker host. The default ioBroker installation path is shown below; adjust it if your installation uses a different installation directory:

```bash
sudo /opt/iobroker/node_modules/iobroker.wireguard-s2s/scripts/install-helper.sh
```

The installer:

1. verifies all required system commands;
2. copies the helper to `/usr/local/libexec/iobroker-wireguard-s2s-helper` as a root-owned file;
3. creates `/etc/sudoers.d/iobroker-wireguard-s2s` for the `iobroker` service user;
4. validates the sudoers entry with `visudo`.

For a different service user:

```bash
sudo IOBROKER_SERVICE_USER=my-iobroker-user /opt/iobroker/node_modules/iobroker.wireguard-s2s/scripts/install-helper.sh
```

Do not point the sudo policy at the helper inside `node_modules`: package files may be writable during updates. The installed root-owned copy is an intentional security boundary.

## Generate keys

The easiest method is the **Generate new private and public key** button on the adapter's Tunnel configuration tab. The adapter instance must be running, but the privileged helper is not required for key generation. The generated private key is inserted into the password field and the public key is shown in a copyable read-only field. Save the adapter configuration afterwards; ioBroker then stores the private key using `encryptedNative`.

Generating a replacement key invalidates the old public key. Copy the new public key to the peer configuration on the remote site.

Alternatively, generate one key pair on each site's command line. Keep each private key only on its own site:

```bash
umask 077
wg genkey | tee privatekey | wg pubkey > publickey
wg genpsk > presharedkey
```

The preshared key is optional, but if used it must be identical on both sides.

## Example topology

| Setting | Site A | Site B |
|---|---|---|
| Tunnel address | `10.200.0.1/30` | `10.200.0.2/30` |
| Local LAN | `192.168.1.0/24` | `192.168.2.0/24` |
| Remote networks / AllowedIPs | `10.200.0.2/32, 192.168.2.0/24` | `10.200.0.1/32, 192.168.1.0/24` |
| Listen port | `51820` | `51820` |
| Peer public key | Public key of B | Public key of A |
| Endpoint | Public DNS/IP of B | Public DNS/IP of A |

Only one side needs a fixed, configured endpoint if the other side initiates the tunnel with `PersistentKeepalive = 25`. Leave the responder endpoint empty when it should learn the roaming endpoint from authenticated traffic.

### Routing outside the ioBroker host

For a real site-to-site link, clients in both LANs must know where to send the remote LAN traffic.

- If the ioBroker host is the LAN gateway, its WireGuard route is sufficient, subject to the host firewall.
- If another router is the LAN gateway, add a static route on that router. Example at Site A: route `192.168.2.0/24` via the Site A ioBroker host's LAN address.
- Add the reverse route at Site B.
- Ensure the host firewall permits forwarding between the LAN interface and `iowgN` in both directions.

Avoid NAT for a normal site-to-site design; routed subnets preserve the original client addresses. Use NAT only when the surrounding network cannot carry the required reverse routes and you understand the loss of end-to-end addressing.

## Adapter configuration

- **Interface name:** restricted to `iowg0` … `iowg999`. The helper refuses to take over an existing unowned interface.
- **Local tunnel addresses:** addresses assigned to this interface, including prefix, for example `10.200.0.1/30`.
- **Local LAN networks:** documentation state used to make the reverse peer configuration clear. These networks are not added as local routes.
- **Remote networks:** WireGuard `AllowedIPs` and the routes installed through this interface. Default routes are intentionally rejected.
- **Private key:** this site's WireGuard private key. It is protected and encrypted in the adapter's native configuration.
- **Endpoint:** optional on a responder; a hostname, IPv4 address or IPv6 address without brackets.
- **IP forwarding:** enables the kernel setting at runtime. The helper does not turn forwarding off again because other host services may depend on it.
- **Auto apply:** when enabled, recreates/applies the tunnel at adapter startup. Start with this disabled, test with `control.apply`, and enable it after the routes are verified.

The adapter considers the peer connected when the interface is up and the latest authenticated handshake is newer than **Connected timeout**. An idle tunnel without keepalives can therefore be healthy while shown as disconnected; increase the timeout or configure keepalive if the state is used for alerts.

## Security model

The ioBroker process does not run arbitrary root commands. It sends a small JSON document to a root-owned helper through a non-interactive sudo rule. The helper independently validates every value and:

- accepts only dedicated `iowgN` interface names;
- invokes fixed `ip`, `wg` and `sysctl` binaries without a shell;
- rejects newlines, malformed keys/CIDRs, oversized requests and default routes;
- refuses interfaces without a root-owned ownership marker;
- writes temporary WireGuard configuration with mode `0600` under `/run` and deletes it immediately;
- never returns or persists the private key in its status/state file.

The root-owned state directory is `/var/lib/iobroker-wireguard-s2s`. `control.down` removes the managed interface and its ownership marker. Stopping the adapter alone leaves the interface running; this avoids interrupting network connectivity during an ioBroker restart.

## Development

```bash
npm run check
npm run lint
npm run test
npm run test:integration
npm run coverage
node --check helper/iobroker-wireguard-s2s-helper.js
```

The project structure is generated from the official `@iobroker/create-adapter` TypeScript/JSONConfig template. Unit tests cover configuration normalization, endpoint formatting, keys and the rejection of command-style interface names and default routes. The integration test starts the adapter in the standard ioBroker test harness. End-to-end WireGuard network tests still require a disposable Linux network namespace or virtual machine and root permissions.

Use `npm run release` to prepare releases after npm trusted publishing and the deploy job in `.github/workflows/test-and-release.yml` have been configured.

## Uninstall the helper

Bring down every managed instance first, then run:

```bash
sudo /opt/iobroker/node_modules/iobroker.wireguard-s2s/scripts/uninstall-helper.sh
```

The uninstaller removes the helper and sudo policy. It intentionally leaves interfaces and `/var/lib/iobroker-wireguard-s2s` untouched so uninstalling a package cannot silently destroy live network state.

## Changelog

### **WORK IN PROGRESS**

- Migrate the project to the current official ioBroker Adapter Creator structure.
- Add standard linting, type checking, package tests, integration tests and release workflow.
- Move JSONConfig texts to the ioBroker i18n structure.
- Use adapter-managed timers and stop active helper processes during unload.

### 0.2.0 (2026-09-02)

- Add private/public WireGuard key generation to the adapter configuration.
- Return generated keys only to ioBroker Admin instances.
- Store the private key through ioBroker's encrypted native configuration.

### 0.1.0 (2026-08-31)

- Initial implementation.
- Configure one IPv4/IPv6 WireGuard site-to-site peer.
- Monitor interface state, handshakes and traffic counters.
- Add a root-owned, strictly validating privileged helper.

## License

MIT

Copyright (c) 2026 Andreas Metag
