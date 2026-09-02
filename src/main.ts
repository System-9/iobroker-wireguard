import * as utils from "@iobroker/adapter-core";
import { validateConfig, type AdapterNativeConfig, type ValidatedConfig } from "./lib/config";
import { HelperClient } from "./lib/helper-client";
import { deriveWireGuardPublicKey, generateWireGuardKeyPair } from "./lib/keys";
import { isAuthorizedAdminSender } from "./lib/message-security";
import type { HelperStatus } from "./lib/types";

export class WireguardS2S extends utils.Adapter {
    private readonly helper = new HelperClient();
    private pollTimer?: NodeJS.Timeout;
    private validated?: ValidatedConfig;
    private operationChain: Promise<void> = Promise.resolve();
    private lastReportedError = "";

    public constructor(options: Partial<utils.AdapterOptions> = {}) {
        super({
            ...options,
            name: "wireguard-s2s",
        });
        this.on("ready", this.onReady.bind(this));
        this.on("message", this.onMessage.bind(this));
        this.on("stateChange", this.onStateChange.bind(this));
        this.on("unload", this.onUnload.bind(this));
    }

    private async onReady(): Promise<void> {
        await this.setStateAsync("info.connection", false, true);
        await this.setStateAsync("info.interfaceUp", false, true);
        await this.setStateAsync("info.helperReady", false, true);
        await this.setStateAsync("info.configValid", false, true);
        this.subscribeStates("control.*");

        try {
            const doctor = await this.helper.doctor();
            this.log.info(`Privileged helper ${doctor.helperVersion} is ready`);
            await this.setStateAsync("info.helperReady", true, true);
        } catch (error) {
            await this.reportError(this.errorMessage(error));
            this.log.error(
                `WireGuard helper is unavailable. Install it with 'npm run helper:install'. ${this.errorMessage(error)}`,
            );
            return;
        }

        try {
            this.validated = validateConfig(this.config as unknown as AdapterNativeConfig);
            await this.setStateAsync("info.configValid", true, true);
            await this.setStateAsync("info.interfaceName", this.validated.helperConfig.interfaceName, true);
            await this.setStateAsync("info.localNetworks", this.validated.localNetworks.join(", "), true);
            await this.setStateAsync("peer.publicKey", this.validated.helperConfig.peer.publicKey, true);
        } catch (error) {
            await this.reportError(this.errorMessage(error));
            this.log.error(`Configuration is invalid: ${this.errorMessage(error)}`);
            return;
        }

        if (this.validated.autoApply) {
            try {
                await this.applyConfiguration();
            } catch (error) {
                const message = this.errorMessage(error);
                this.log.error(`Could not apply the WireGuard configuration: ${message}`);
                await this.reportError(message);
            }
        } else {
            await this.refreshStatus(false);
        }
        this.startPolling();
    }

    private onUnload(callback: () => void): void {
        if (this.pollTimer) {
            clearInterval(this.pollTimer);
        }
        this.setState("info.connection", false, true, () => callback());
    }

    private onMessage(message: ioBroker.Message): void {
        if (!message?.callback || message.command !== "generateKeypair") {
            return;
        }

        if (!isAuthorizedAdminSender(message.from)) {
            this.log.warn(`Rejected key generation request from ${message.from}`);
            this.sendTo(message.from, message.command, { error: "notAuthorized" }, message.callback);
            return;
        }

        try {
            const keyPair = generateWireGuardKeyPair();
            this.sendTo(
                message.from,
                message.command,
                {
                    result: "keypairGenerated",
                    native: {
                        privateKey: keyPair.privateKey,
                        localPublicKey: keyPair.publicKey,
                    },
                    saveConfig: true,
                },
                message.callback,
            );
        } catch (error) {
            this.log.error(`Could not generate a WireGuard key pair: ${this.errorMessage(error)}`);
            this.sendTo(message.from, message.command, { error: "generationFailed" }, message.callback);
        }
    }

    private onStateChange(id: string, state: ioBroker.State | null | undefined): void {
        if (!state || state.ack || state.val !== true) {
            return;
        }
        const localId = id.startsWith(`${this.namespace}.`) ? id.slice(this.namespace.length + 1) : id;
        const actions: Record<string, () => Promise<void>> = {
            "control.apply": () => this.applyConfiguration(),
            "control.down": () => this.bringDown(),
            "control.refresh": () => this.refreshStatus(true),
        };
        const action = actions[localId];
        if (!action) {
            return;
        }

        this.operationChain = this.operationChain
            .then(action, action)
            .catch(async error => {
                const message = this.errorMessage(error);
                this.log.error(`WireGuard control action failed: ${message}`);
                await this.reportError(message);
            })
            .finally(() => this.setStateAsync(localId, false, true).then(() => undefined));
    }

    private startPolling(): void {
        if (!this.validated) {
            return;
        }
        this.pollTimer = setInterval(
            () => void this.refreshStatus(false),
            this.validated.pollInterval * 1_000,
        );
    }

    private async applyConfiguration(): Promise<void> {
        this.validated = validateConfig(this.config as unknown as AdapterNativeConfig);
        this.log.info(`Applying WireGuard configuration to ${this.validated.helperConfig.interfaceName}`);
        const status = await this.helper.apply(this.validated.helperConfig);
        await this.updateStatus(status);
        await this.reportError("");
    }

    private async bringDown(): Promise<void> {
        if (!this.validated) {
            this.validated = validateConfig(this.config as unknown as AdapterNativeConfig);
        }
        this.log.info(`Bringing down managed WireGuard interface ${this.validated.helperConfig.interfaceName}`);
        const status = await this.helper.down(this.validated.helperConfig.interfaceName);
        await this.updateStatus(status);
        await this.reportError("");
    }

    private async refreshStatus(logErrors: boolean): Promise<void> {
        if (!this.validated) {
            return;
        }
        try {
            const status = await this.helper.status(this.validated.helperConfig.interfaceName);
            await this.updateStatus(status);
            await this.reportError("");
        } catch (error) {
            const message = this.errorMessage(error);
            await this.setStateAsync("info.connection", false, true);
            await this.setStateAsync("peer.connected", false, true);
            if (logErrors || message !== this.lastReportedError) {
                this.log.warn(`Cannot read WireGuard status: ${message}`);
            }
            await this.reportError(message);
        }
    }

    private async updateStatus(status: HelperStatus): Promise<void> {
        const nowSeconds = Math.floor(Date.now() / 1_000);
        const peer = status.peers.find(item => item.publicKey === this.validated?.helperConfig.peer.publicKey)
            ?? status.peers[0];
        const handshakeAge = peer?.latestHandshake ? Math.max(0, nowSeconds - peer.latestHandshake) : -1;
        const connected = Boolean(
            status.exists
            && status.up
            && peer
            && handshakeAge >= 0
            && handshakeAge <= (this.validated?.handshakeTimeout ?? 180),
        );

        await Promise.all([
            this.setStateAsync("info.connection", connected, true),
            this.setStateAsync("info.interfaceUp", status.exists && status.up, true),
            this.setStateAsync("info.interfaceName", status.interfaceName, true),
            this.setStateAsync(
                "info.localPublicKey",
                status.publicKey || deriveWireGuardPublicKey(this.validated?.helperConfig.privateKey || ""),
                true,
            ),
            this.setStateAsync("info.listenPort", status.listenPort || 0, true),
            this.setStateAsync("peer.connected", connected, true),
            this.setStateAsync("peer.endpoint", peer?.endpoint || "", true),
            this.setStateAsync("peer.allowedIPs", peer?.allowedIPs.join(", ") || "", true),
            this.setStateAsync("peer.latestHandshake", peer?.latestHandshake ? peer.latestHandshake * 1_000 : 0, true),
            this.setStateAsync("peer.handshakeAge", handshakeAge, true),
            this.setStateAsync("peer.rxBytes", peer?.rxBytes || 0, true),
            this.setStateAsync("peer.txBytes", peer?.txBytes || 0, true),
        ]);
    }

    private async reportError(message: string): Promise<void> {
        this.lastReportedError = message;
        await this.setStateAsync("info.lastError", message, true);
    }

    private errorMessage(error: unknown): string {
        return error instanceof Error ? error.message : String(error);
    }
}

if (require.main !== module) {
    module.exports = (options: Partial<utils.AdapterOptions> | undefined) => new WireguardS2S(options);
} else {
    (() => new WireguardS2S())();
}
