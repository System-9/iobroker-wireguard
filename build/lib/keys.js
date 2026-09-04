"use strict";
var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, { get: all[name], enumerable: true });
};
var __copyProps = (to, from, except, desc) => {
  if (from && typeof from === "object" || typeof from === "function") {
    for (let key of __getOwnPropNames(from))
      if (!__hasOwnProp.call(to, key) && key !== except)
        __defProp(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable });
  }
  return to;
};
var __toCommonJS = (mod) => __copyProps(__defProp({}, "__esModule", { value: true }), mod);
var keys_exports = {};
__export(keys_exports, {
  deriveWireGuardPublicKey: () => deriveWireGuardPublicKey,
  generateWireGuardKeyPair: () => generateWireGuardKeyPair
});
module.exports = __toCommonJS(keys_exports);
var import_node_crypto = require("node:crypto");
var import_config = require("./config");
const X25519_PKCS8_PREFIX = Buffer.from("302e020100300506032b656e04220420", "hex");
function generateWireGuardKeyPair() {
  const privateBytes = (0, import_node_crypto.randomBytes)(32);
  privateBytes[0] &= 248;
  privateBytes[31] &= 127;
  privateBytes[31] |= 64;
  const privateKey = privateBytes.toString("base64");
  privateBytes.fill(0);
  return {
    privateKey,
    publicKey: deriveWireGuardPublicKey(privateKey)
  };
}
function deriveWireGuardPublicKey(privateKey) {
  if (!(0, import_config.isWireGuardKey)(privateKey)) {
    throw new Error("Private key is not a valid WireGuard key");
  }
  const privateBytes = Buffer.from(privateKey, "base64");
  try {
    const privateKeyObject = (0, import_node_crypto.createPrivateKey)({
      key: Buffer.concat([X25519_PKCS8_PREFIX, privateBytes]),
      format: "der",
      type: "pkcs8"
    });
    const publicJwk = (0, import_node_crypto.createPublicKey)(privateKeyObject).export({ format: "jwk" });
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
// Annotate the CommonJS export names for ESM import in node:
0 && (module.exports = {
  deriveWireGuardPublicKey,
  generateWireGuardKeyPair
});
//# sourceMappingURL=keys.js.map
