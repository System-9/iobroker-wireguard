import { isIP } from "node:net";
import type { HelperApplyConfig } from "./types";

export interface AdapterNativeConfig {
    interfaceName: string;
    localAddresses: string;
    localNetworks: string;
    remoteNetworks: string;
    privateKey: string;
    localPublicKey?: string;
    listenPort: number;
    peerPublicKey: string;
    peerPresharedKey: string;
    endpointHost: string;
    endpointPort: number;
    persistentKeepalive: number;
    mtu: number;
    enableIPv4Forwarding: boolean;
    enableIPv6Forwarding: boolean;
    autoApply: boolean;
    pollInterval: number;
    handshakeTimeout: number;
}

export interface ValidatedConfig {
    helperConfig: HelperApplyConfig;
    localNetworks: string[];
    pollInterval: number;
    handshakeTimeout: number;
    autoApply: boolean;
}

const INTERFACE_PATTERN = /^iowg[0-9]{1,3}$/;
const HOSTNAME_PATTERN = /^(?=.{1,253}$)(?!-)(?:[a-zA-Z0-9-]{1,63}\.)*[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$/;

export function splitList(value: string): string[] {
    return [
        ...new Set(
            String(value ?? "")
                .split(/[\s,;]+/)
                .map(item => item.trim())
                .filter(Boolean),
        ),
    ];
}

export function validateCidr(value: string, field: string): 4 | 6 {
    const parts = value.split("/");
    if (parts.length !== 2) {
        throw new Error(`${field}: '${value}' is not a CIDR network`);
    }

    const family = isIP(parts[0]);
    const prefix = Number(parts[1]);
    const maximum = family === 4 ? 32 : family === 6 ? 128 : -1;
    if (maximum < 0 || !Number.isInteger(prefix) || prefix < 0 || prefix > maximum) {
        throw new Error(`${field}: '${value}' is not a valid CIDR network`);
    }
    return family as 4 | 6;
}

export function isWireGuardKey(value: string): boolean {
    if (!/^[A-Za-z0-9+/]{43}=$/.test(value)) {
        return false;
    }
    try {
        return Buffer.from(value, "base64").length === 32;
    } catch {
        return false;
    }
}

export function formatEndpoint(hostValue: string, port: number): string | undefined {
    let host = String(hostValue ?? "").trim();
    if (!host) {
        return undefined;
    }
    if (host.startsWith("[") && host.endsWith("]")) {
        host = host.slice(1, -1);
    }
    const family = isIP(host);
    if (!family && !HOSTNAME_PATTERN.test(host)) {
        throw new Error("endpointHost must be an IPv4/IPv6 address or a DNS hostname");
    }
    assertIntegerRange(port, 1, 65535, "endpointPort");
    return family === 6 ? `[${host}]:${port}` : `${host}:${port}`;
}

export function validateConfig(config: AdapterNativeConfig): ValidatedConfig {
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

    localAddresses.forEach(value => {
        validateCidr(value, "localAddresses");
        if (Number(value.split("/")[1]) === 0) {
            throw new Error("localAddresses must not contain a default route");
        }
    });
    localNetworks.forEach(value => validateCidr(value, "localNetworks"));
    remoteNetworks.forEach(value => {
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
    assertIntegerRange(mtu, 0, 9000, "mtu");
    if (mtu > 0 && mtu < 576) {
        throw new Error("mtu must be 0 (automatic) or between 576 and 9000");
    }
    assertIntegerRange(pollInterval, 5, 3600, "pollInterval");
    assertIntegerRange(handshakeTimeout, 30, 86400, "handshakeTimeout");

    const endpoint = formatEndpoint(config.endpointHost, Number(config.endpointPort));
    const helperConfig: HelperApplyConfig = {
        interfaceName,
        localAddresses,
        privateKey,
        listenPort,
        peer: {
            publicKey: peerPublicKey,
            allowedIPs: remoteNetworks,
            persistentKeepalive,
            ...(peerPresharedKey ? { presharedKey: peerPresharedKey } : {}),
            ...(endpoint ? { endpoint } : {}),
        },
        ...(mtu > 0 ? { mtu } : {}),
        enableIPv4Forwarding: Boolean(config.enableIPv4Forwarding),
        enableIPv6Forwarding: Boolean(config.enableIPv6Forwarding),
    };

    return {
        helperConfig,
        localNetworks,
        pollInterval,
        handshakeTimeout,
        autoApply: Boolean(config.autoApply),
    };
}

function assertIntegerRange(value: number, minimum: number, maximum: number, field: string): void {
    if (!Number.isInteger(value) || value < minimum || value > maximum) {
        throw new Error(`${field} must be an integer between ${minimum} and ${maximum}`);
    }
}
