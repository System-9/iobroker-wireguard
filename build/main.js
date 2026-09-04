"use strict";
var __create = Object.create;
var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __getProtoOf = Object.getPrototypeOf;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __copyProps = (to, from, except, desc) => {
  if (from && typeof from === "object" || typeof from === "function") {
    for (let key of __getOwnPropNames(from))
      if (!__hasOwnProp.call(to, key) && key !== except)
        __defProp(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable });
  }
  return to;
};
var __toESM = (mod, isNodeMode, target) => (target = mod != null ? __create(__getProtoOf(mod)) : {}, __copyProps(
  // If the importer is in node compatibility mode or this is not an ESM
  // file that has been converted to a CommonJS file using a Babel-
  // compatible transform (i.e. "__esModule" has not been set), then set
  // "default" to the CommonJS "module.exports" for node compatibility.
  isNodeMode || !mod || !mod.__esModule ? __defProp(target, "default", { value: mod, enumerable: true }) : target,
  mod
));
var utils = __toESM(require("@iobroker/adapter-core"));
var import_config = require("./lib/config");
var import_helper_client = require("./lib/helper-client");
var import_keys = require("./lib/keys");
var import_message_security = require("./lib/message-security");
class WireguardS2S extends utils.Adapter {
  helper;
  pollTimer;
  validated;
  operationChain = Promise.resolve();
  lastReportedError = "";
  shuttingDown = false;
  constructor(options = {}) {
    super({
      ...options,
      name: "wireguard-s2s"
    });
    this.helper = new import_helper_client.HelperClient({
      scheduleTimeout: (callback, timeout) => this.setTimeout(callback, timeout),
      cancelTimeout: (timeout) => this.clearTimeout(timeout)
    });
    this.on("ready", this.onReady.bind(this));
    this.on("message", this.onMessage.bind(this));
    this.on("stateChange", this.onStateChange.bind(this));
    this.on("unload", this.onUnload.bind(this));
  }
  async onReady() {
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
        `WireGuard helper is unavailable. Install it with 'npm run helper:install'. ${this.errorMessage(error)}`
      );
      return;
    }
    try {
      this.validated = (0, import_config.validateConfig)(this.config);
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
  onUnload(callback) {
    this.shuttingDown = true;
    if (this.pollTimer) {
      this.clearInterval(this.pollTimer);
      this.pollTimer = void 0;
    }
    this.helper.close();
    void this.setState("info.connection", false, true, () => callback());
  }
  onMessage(message) {
    if (!message?.callback || message.command !== "generateKeypair") {
      return;
    }
    if (!(0, import_message_security.isAuthorizedAdminSender)(message.from)) {
      this.log.warn(`Rejected key generation request from ${message.from}`);
      this.sendTo(message.from, message.command, { error: "notAuthorized" }, message.callback);
      return;
    }
    try {
      const keyPair = (0, import_keys.generateWireGuardKeyPair)();
      this.sendTo(
        message.from,
        message.command,
        {
          result: "keypairGenerated",
          native: {
            privateKey: keyPair.privateKey,
            localPublicKey: keyPair.publicKey
          },
          saveConfig: true
        },
        message.callback
      );
    } catch (error) {
      this.log.error(`Could not generate a WireGuard key pair: ${this.errorMessage(error)}`);
      this.sendTo(message.from, message.command, { error: "generationFailed" }, message.callback);
    }
  }
  onStateChange(id, state) {
    if (this.shuttingDown || !state || state.ack || state.val !== true) {
      return;
    }
    const localId = id.startsWith(`${this.namespace}.`) ? id.slice(this.namespace.length + 1) : id;
    const actions = {
      "control.apply": () => this.applyConfiguration(),
      "control.down": () => this.bringDown(),
      "control.refresh": () => this.refreshStatus(true)
    };
    const action = actions[localId];
    if (!action) {
      return;
    }
    this.operationChain = this.operationChain.then(action, action).catch(async (error) => {
      const message = this.errorMessage(error);
      if (this.shuttingDown) {
        return;
      }
      this.log.error(`WireGuard control action failed: ${message}`);
      await this.reportError(message);
    }).finally(() => {
      if (!this.shuttingDown) {
        return this.setStateAsync(localId, false, true).then(() => void 0);
      }
    });
  }
  startPolling() {
    if (!this.validated) {
      return;
    }
    this.pollTimer = this.setInterval(() => void this.refreshStatus(false), this.validated.pollInterval * 1e3);
  }
  async applyConfiguration() {
    this.validated = (0, import_config.validateConfig)(this.config);
    this.log.info(`Applying WireGuard configuration to ${this.validated.helperConfig.interfaceName}`);
    const status = await this.helper.apply(this.validated.helperConfig);
    await this.updateStatus(status);
    await this.reportError("");
  }
  async bringDown() {
    if (!this.validated) {
      this.validated = (0, import_config.validateConfig)(this.config);
    }
    this.log.info(`Bringing down managed WireGuard interface ${this.validated.helperConfig.interfaceName}`);
    const status = await this.helper.down(this.validated.helperConfig.interfaceName);
    await this.updateStatus(status);
    await this.reportError("");
  }
  async refreshStatus(logErrors) {
    if (this.shuttingDown || !this.validated) {
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
  async updateStatus(status) {
    const nowSeconds = Math.floor(Date.now() / 1e3);
    const peer = status.peers.find((item) => item.publicKey === this.validated?.helperConfig.peer.publicKey) ?? status.peers[0];
    const handshakeAge = peer?.latestHandshake ? Math.max(0, nowSeconds - peer.latestHandshake) : -1;
    const connected = Boolean(
      status.exists && status.up && peer && handshakeAge >= 0 && handshakeAge <= (this.validated?.handshakeTimeout ?? 180)
    );
    await Promise.all([
      this.setStateAsync("info.connection", connected, true),
      this.setStateAsync("info.interfaceUp", status.exists && status.up, true),
      this.setStateAsync("info.interfaceName", status.interfaceName, true),
      this.setStateAsync(
        "info.localPublicKey",
        status.publicKey || (0, import_keys.deriveWireGuardPublicKey)(this.validated?.helperConfig.privateKey || ""),
        true
      ),
      this.setStateAsync("info.listenPort", status.listenPort || 0, true),
      this.setStateAsync("peer.connected", connected, true),
      this.setStateAsync("peer.endpoint", peer?.endpoint || "", true),
      this.setStateAsync("peer.allowedIPs", peer?.allowedIPs.join(", ") || "", true),
      this.setStateAsync("peer.latestHandshake", peer?.latestHandshake ? peer.latestHandshake * 1e3 : 0, true),
      this.setStateAsync("peer.handshakeAge", handshakeAge, true),
      this.setStateAsync("peer.rxBytes", peer?.rxBytes || 0, true),
      this.setStateAsync("peer.txBytes", peer?.txBytes || 0, true)
    ]);
  }
  async reportError(message) {
    this.lastReportedError = message;
    await this.setStateAsync("info.lastError", message, true);
  }
  errorMessage(error) {
    return error instanceof Error ? error.message : String(error);
  }
}
if (require.main !== module) {
  module.exports = (options) => new WireguardS2S(options);
} else {
  (() => new WireguardS2S())();
}
//# sourceMappingURL=main.js.map
