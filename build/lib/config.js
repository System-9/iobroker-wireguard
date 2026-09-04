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
var config_exports = {};
__export(config_exports, {
  formatEndpoint: () => formatEndpoint,
  isWireGuardKey: () => isWireGuardKey,
  splitList: () => splitList,
  validateCidr: () => validateCidr,
  validateConfig: () => validateConfig
});
module.exports = __toCommonJS(config_exports);
var import_node_net = require("node:net");
const INTERFACE_PATTERN = /^iowg[0-9]{1,3}$/;
const HOSTNAME_PATTERN = /^(?=.{1,253}$)(?!-)(?:[a-zA-Z0-9-]{1,63}\.)*[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$/;
function splitList(value) {
  return [
    ...new Set(
      String(value ?? "").split(/[\s,;]+/).map((item) => item.trim()).filter(Boolean)
    )
  ];
}
function validateCidr(value, field) {
  const parts = value.split("/");
  if (parts.length !== 2) {
    throw new Error(`${field}: '${value}' is not a CIDR network`);
  }
  const family = (0, import_node_net.isIP)(parts[0]);
  const prefix = Number(parts[1]);
  const maximum = family === 4 ? 32 : family === 6 ? 128 : -1;
  if (maximum < 0 || !Number.isInteger(prefix) || prefix < 0 || prefix > maximum) {
    throw new Error(`${field}: '${value}' is not a valid CIDR network`);
  }
  return family;
}
function isWireGuardKey(value) {
  if (!/^[A-Za-z0-9+/]{43}=$/.test(value)) {
    return false;
  }
  try {
    return Buffer.from(value, "base64").length === 32;
  } catch {
    return false;
  }
}
function formatEndpoint(hostValue, port) {
  let host = String(hostValue ?? "").trim();
  if (!host) {
    return void 0;
  }
  if (host.startsWith("[") && host.endsWith("]")) {
    host = host.slice(1, -1);
  }
  const family = (0, import_node_net.isIP)(host);
  if (!family && !HOSTNAME_PATTERN.test(host)) {
    throw new Error("endpointHost must be an IPv4/IPv6 address or a DNS hostname");
  }
  assertIntegerRange(port, 1, 65535, "endpointPort");
  return family === 6 ? `[${host}]:${port}` : `${host}:${port}`;
}
function validateConfig(config) {
  const interfaceName = String(config.interfaceName ?? "").trim();
  if (!INTERFACE_PATTERN.test(interfaceName)) {
    throw new Error("interfaceName must match iowg0 through iowg999");
  }
  const localAddresses = splitList(config.localAddresses);
  const localNetworks = splitList(config.localNetworks);
  const remoteNetworks = splitList(config.remoteNetworks);
  if (localAddresses.length === 0) {
    throw new Error("At least one local tunnel address is required");
  }
  if (remoteNetworks.length === 0) {
    throw new Error("At least one remote tunnel or LAN network is required");
  }
  localAddresses.forEach((value) => {
    validateCidr(value, "localAddresses");
    if (Number(value.split("/")[1]) === 0) {
      throw new Error("localAddresses must not contain a default route");
    }
  });
  localNetworks.forEach((value) => validateCidr(value, "localNetworks"));
  remoteNetworks.forEach((value) => {
    validateCidr(value, "remoteNetworks");
    const prefix = Number(value.split("/")[1]);
    if (prefix === 0) {
      throw new Error("Default routes (0.0.0.0/0 and ::/0) are intentionally not allowed");
    }
  });
  const privateKey = String(config.privateKey ?? "").trim();
  const peerPublicKey = String(config.peerPublicKey ?? "").trim();
  const peerPresharedKey = String(config.peerPresharedKey ?? "").trim();
  if (!isWireGuardKey(privateKey)) {
    throw new Error("privateKey is missing or is not a valid WireGuard key");
  }
  if (!isWireGuardKey(peerPublicKey)) {
    throw new Error("peerPublicKey is missing or is not a valid WireGuard key");
  }
  if (peerPresharedKey && !isWireGuardKey(peerPresharedKey)) {
    throw new Error("peerPresharedKey is not a valid WireGuard key");
  }
  const listenPort = Number(config.listenPort);
  const persistentKeepalive = Number(config.persistentKeepalive);
  const mtu = Number(config.mtu);
  const pollInterval = Number(config.pollInterval);
  const handshakeTimeout = Number(config.handshakeTimeout);
  assertIntegerRange(listenPort, 1, 65535, "listenPort");
  assertIntegerRange(persistentKeepalive, 0, 65535, "persistentKeepalive");
  assertIntegerRange(mtu, 0, 9e3, "mtu");
  if (mtu > 0 && mtu < 576) {
    throw new Error("mtu must be 0 (automatic) or between 576 and 9000");
  }
  assertIntegerRange(pollInterval, 5, 3600, "pollInterval");
  assertIntegerRange(handshakeTimeout, 30, 86400, "handshakeTimeout");
  const endpoint = formatEndpoint(config.endpointHost, Number(config.endpointPort));
  const helperConfig = {
    interfaceName,
    localAddresses,
    privateKey,
    listenPort,
    peer: {
      publicKey: peerPublicKey,
      allowedIPs: remoteNetworks,
      persistentKeepalive,
      ...peerPresharedKey ? { presharedKey: peerPresharedKey } : {},
      ...endpoint ? { endpoint } : {}
    },
    ...mtu > 0 ? { mtu } : {},
    enableIPv4Forwarding: Boolean(config.enableIPv4Forwarding),
    enableIPv6Forwarding: Boolean(config.enableIPv6Forwarding)
  };
  return {
    helperConfig,
    localNetworks,
    pollInterval,
    handshakeTimeout,
    autoApply: Boolean(config.autoApply)
  };
}
function assertIntegerRange(value, minimum, maximum, field) {
  if (!Number.isInteger(value) || value < minimum || value > maximum) {
    throw new Error(`${field} must be an integer between ${minimum} and ${maximum}`);
  }
}
// Annotate the CommonJS export names for ESM import in node:
0 && (module.exports = {
  formatEndpoint,
  isWireGuardKey,
  splitList,
  validateCidr,
  validateConfig
});
//# sourceMappingURL=config.js.map
