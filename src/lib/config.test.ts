import assert from "node:assert/strict";
import { formatEndpoint, isWireGuardKey, splitList, validateConfig, type AdapterNativeConfig } from "./config";

const keyA = Buffer.alloc(32, 1).toString("base64");
const keyB = Buffer.alloc(32, 2).toString("base64");

function validConfig(overrides: Partial<AdapterNativeConfig> = {}): AdapterNativeConfig {
    return {
        interfaceName: "iowg0",
        localAddresses: "10.200.0.1/30",
        localNetworks: "192.168.1.0/24",
        remoteNetworks: "10.200.0.2/32, 192.168.2.0/24",
        privateKey: keyA,
        listenPort: 51820,
        peerPublicKey: keyB,
        peerPresharedKey: "",
        endpointHost: "vpn.example.org",
        endpointPort: 51820,
        persistentKeepalive: 25,
        mtu: 1420,
        enableIPv4Forwarding: true,
        enableIPv6Forwarding: false,
        autoApply: false,
        pollInterval: 15,
        handshakeTimeout: 180,
        ...overrides,
    };
}

describe("configuration validation", () => {
    it("normalizes comma and whitespace separated lists", () => {
        assert.deepEqual(splitList("10.0.0.0/24,  10.0.1.0/24\n10.0.0.0/24"), ["10.0.0.0/24", "10.0.1.0/24"]);
    });

    it("accepts valid WireGuard keys and rejects malformed values", () => {
        assert.equal(isWireGuardKey(keyA), true);
        assert.equal(isWireGuardKey("not-a-key"), false);
    });

    it("formats IPv4, DNS and IPv6 endpoints safely", () => {
        assert.equal(formatEndpoint("vpn.example.org", 51820), "vpn.example.org:51820");
        assert.equal(formatEndpoint("203.0.113.7", 51820), "203.0.113.7:51820");
        assert.equal(formatEndpoint("2001:db8::1", 51820), "[2001:db8::1]:51820");
        assert.equal(formatEndpoint("", 51820), undefined);
    });

    it("builds the structured helper request", () => {
        const result = validateConfig(validConfig());
        assert.equal(result.helperConfig.interfaceName, "iowg0");
        assert.equal(result.helperConfig.peer.endpoint, "vpn.example.org:51820");
        assert.deepEqual(result.helperConfig.peer.allowedIPs, ["10.200.0.2/32", "192.168.2.0/24"]);
    });

    it("rejects interface command injection", () => {
        assert.throws(() => validateConfig(validConfig({ interfaceName: "wg0;reboot" })), /interfaceName/);
    });

    it("rejects default routes", () => {
        assert.throws(() => validateConfig(validConfig({ remoteNetworks: "0.0.0.0/0" })), /Default routes/);
        assert.throws(() => validateConfig(validConfig({ remoteNetworks: "::/0" })), /Default routes/);
    });

    it("rejects missing or malformed keys", () => {
        assert.throws(() => validateConfig(validConfig({ privateKey: "" })), /privateKey/);
        assert.throws(() => validateConfig(validConfig({ peerPresharedKey: "bad" })), /peerPresharedKey/);
    });
});
