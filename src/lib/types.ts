export interface HelperApplyConfig {
    interfaceName: string;
    localAddresses: string[];
    privateKey: string;
    listenPort: number;
    peer: {
        publicKey: string;
        presharedKey?: string;
        endpoint?: string;
        allowedIPs: string[];
        persistentKeepalive: number;
    };
    mtu?: number;
    enableIPv4Forwarding: boolean;
    enableIPv6Forwarding: boolean;
}

export interface HelperPeerStatus {
    publicKey: string;
    endpoint: string;
    allowedIPs: string[];
    latestHandshake: number;
    rxBytes: number;
    txBytes: number;
    persistentKeepalive: number;
}

export interface HelperStatus {
    exists: boolean;
    owned: boolean;
    up: boolean;
    interfaceName: string;
    publicKey: string;
    listenPort: number;
    peers: HelperPeerStatus[];
}

export interface HelperDoctorResult {
    platform: string;
    helperVersion: string;
    binaries: Record<string, string>;
}
