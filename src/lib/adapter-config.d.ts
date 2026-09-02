declare global {
    namespace ioBroker {
        interface AdapterConfig {
            interfaceName: string;
            localAddresses: string;
            localNetworks: string;
            remoteNetworks: string;
            privateKey: string;
            localPublicKey: string;
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
    }
}

export {};
