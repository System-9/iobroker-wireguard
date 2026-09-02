import { createPrivateKey, createPublicKey, randomBytes } from "node:crypto";
import { isWireGuardKey } from "./config";

const X25519_PKCS8_PREFIX = Buffer.from("302e020100300506032b656e04220420", "hex");

export interface WireGuardKeyPair {
    privateKey: string;
    publicKey: string;
}

/**
 * Creates a WireGuard-compatible X25519 private/public key pair without
 * invoking an external command or writing either key to disk.
 */
export function generateWireGuardKeyPair(): WireGuardKeyPair {
    const privateBytes = randomBytes(32);

    // This is the same clamping applied by wg genkey for a Curve25519 scalar.
    privateBytes[0] &= 248;
    privateBytes[31] &= 127;
    privateBytes[31] |= 64;

    const privateKey = privateBytes.toString("base64");
    privateBytes.fill(0);
    return {
        privateKey,
        publicKey: deriveWireGuardPublicKey(privateKey),
    };
}

/** Derives the public X25519 key belonging to a WireGuard private key. */
export function deriveWireGuardPublicKey(privateKey: string): string {
    if (!isWireGuardKey(privateKey)) {
        throw new Error("Private key is not a valid WireGuard key");
    }

    const privateBytes = Buffer.from(privateKey, "base64");
    try {
        const privateKeyObject = createPrivateKey({
            key: Buffer.concat([X25519_PKCS8_PREFIX, privateBytes]),
            format: "der",
            type: "pkcs8",
        });
        const publicJwk = createPublicKey(privateKeyObject).export({ format: "jwk" });
        if (typeof publicJwk.x !== "string") {
            throw new Error("X25519 public key export failed");
        }
        const publicBytes = Buffer.from(publicJwk.x, "base64url");
        if (publicBytes.length !== 32) {
            throw new Error("X25519 public key has an unexpected length");
        }
        return publicBytes.toString("base64");
    } finally {
        privateBytes.fill(0);
    }
}
