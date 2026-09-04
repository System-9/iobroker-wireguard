import assert from "node:assert/strict";
import { isWireGuardKey } from "./config";
import { deriveWireGuardPublicKey, generateWireGuardKeyPair } from "./keys";
import { isAuthorizedAdminSender } from "./message-security";

describe("WireGuard keys", () => {
    it("generates WireGuard-compatible private and public keys", () => {
        const pair = generateWireGuardKeyPair();
        assert.equal(isWireGuardKey(pair.privateKey), true);
        assert.equal(isWireGuardKey(pair.publicKey), true);
        assert.equal(deriveWireGuardPublicKey(pair.privateKey), pair.publicKey);
    });

    it("generates a different key pair every time", () => {
        const first = generateWireGuardKeyPair();
        const second = generateWireGuardKeyPair();
        assert.notEqual(first.privateKey, second.privateKey);
        assert.notEqual(first.publicKey, second.publicKey);
    });

    it("rejects malformed private keys during public key derivation", () => {
        assert.throws(() => deriveWireGuardPublicKey("not-a-key"), /valid WireGuard key/);
    });
});

describe("key delivery authorization", () => {
    it("allows only exact ioBroker Admin instance senders", () => {
        assert.equal(isAuthorizedAdminSender("system.adapter.admin.0"), true);
        assert.equal(isAuthorizedAdminSender("admin.12"), true);
        assert.equal(isAuthorizedAdminSender("system.adapter.javascript.0"), false);
        assert.equal(isAuthorizedAdminSender("system.adapter.admin.0.attacker"), false);
    });
});
