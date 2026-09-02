# Changelog

## 0.2.0 (2026-09-02)

- Add private/public WireGuard key generation to the adapter configuration.
- Return generated keys only to ioBroker Admin instances.
- Store the private key through ioBroker's encrypted native configuration.

## 0.1.0 (2026-08-31)

- Initial implementation.
- Configure one IPv4/IPv6 WireGuard site-to-site peer.
- Monitor interface state, handshakes and traffic counters.
- Add a root-owned, strictly validating privileged helper.
