"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const {
    buildWireGuardConfig,
    validateApplyConfig,
    validateEndpoint,
    validateInterfaceName,
} = require("../helper/iobroker-wireguard-s2s-helper.js");

const privateKey = Buffer.alloc(32, 3).toString("base64");
const publicKey = Buffer.alloc(32, 4).toString("base64");

function helperConfig(overrides = {}) {
    return {
        interfaceName: "iowg12",
        localAddresses: ["10.200.0.1/30"],
        privateKey,
        listenPort: 51820,
        peer: {
            publicKey,
            allowedIPs: ["10.200.0.2/32", "192.168.2.0/24"],
            persistentKeepalive: 25,
            endpoint: "vpn.example.org:51820",
        },
        mtu: 1420,
        enableIPv4Forwarding: true,
        enableIPv6Forwarding: false,
        ...overrides,
    };
}

test("helper accepts the structured request and emits a WireGuard configuration", () => {
    const validated = validateApplyConfig(helperConfig());
    const output = buildWireGuardConfig(validated);
    assert.match(output, /^\[Interface]/);
    assert.match(output, /AllowedIPs = 10\.200\.0\.2\/32, 192\.168\.2\.0\/24/);
    assert.match(output, /Endpoint = vpn\.example\.org:51820/);
});

test("helper interface names cannot escape the dedicated namespace", () => {
    assert.equal(validateInterfaceName("iowg999"), "iowg999");
    assert.throws(() => validateInterfaceName("wg0"), /interfaceName/);
    assert.throws(() => validateInterfaceName("iowg0; shutdown"), /interfaceName/);
});

test("helper rejects newline endpoint injection", () => {
    assert.throws(() => validateEndpoint("vpn.example.org:51820\nPostUp=reboot"), /invalid/);
});

test("helper rejects default and malformed routes independently of the adapter", () => {
    assert.throws(
        () => validateApplyConfig(helperConfig({ peer: { ...helperConfig().peer, allowedIPs: ["0.0.0.0/0"] } })),
        /default route/,
    );
    assert.throws(
        () => validateApplyConfig(helperConfig({ peer: { ...helperConfig().peer, allowedIPs: ["10.0.0.0/24;reboot"] } })),
        /invalid CIDR/,
    );
});

test("helper rejects oversized route sets", () => {
    const allowedIPs = Array.from({ length: 129 }, (_, index) => `10.0.${Math.floor(index / 256)}.${index % 256}/32`);
    assert.throws(
        () => validateApplyConfig(helperConfig({ peer: { ...helperConfig().peer, allowedIPs } })),
        /at most 128/,
    );
});
