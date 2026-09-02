"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const { isWireGuardKey } = require("../build/lib/config.js");
const {
    deriveWireGuardPublicKey,
    generateWireGuardKeyPair,
} = require("../build/lib/keys.js");
const { isAuthorizedAdminSender } = require("../build/lib/message-security.js");

test("generates WireGuard-compatible private and public keys", () => {
    const pair = generateWireGuardKeyPair();
    assert.equal(isWireGuardKey(pair.privateKey), true);
    assert.equal(isWireGuardKey(pair.publicKey), true);
    assert.equal(deriveWireGuardPublicKey(pair.privateKey), pair.publicKey);
});

test("generates a different key pair every time", () => {
    const first = generateWireGuardKeyPair();
    const second = generateWireGuardKeyPair();
    assert.notEqual(first.privateKey, second.privateKey);
    assert.notEqual(first.publicKey, second.publicKey);
});

test("rejects malformed private keys during public key derivation", () => {
    assert.throws(() => deriveWireGuardPublicKey("not-a-key"), /valid WireGuard key/);
});

test("allows key delivery only to exact ioBroker Admin instance senders", () => {
    assert.equal(isAuthorizedAdminSender("system.adapter.admin.0"), true);
    assert.equal(isAuthorizedAdminSender("admin.12"), true);
    assert.equal(isAuthorizedAdminSender("system.adapter.javascript.0"), false);
    assert.equal(isAuthorizedAdminSender("system.adapter.admin.0.attacker"), false);
});
