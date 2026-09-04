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
var helper_client_exports = {};
__export(helper_client_exports, {
  HelperClient: () => HelperClient
});
module.exports = __toCommonJS(helper_client_exports);
var import_node_fs = require("node:fs");
var import_node_child_process = require("node:child_process");
class HelperClient {
  constructor(timers) {
    this.timers = timers;
    this.sudoPath = ["/usr/bin/sudo", "/bin/sudo"].find(import_node_fs.existsSync) ?? "/usr/bin/sudo";
  }
  static helperPath = "/usr/local/libexec/iobroker-wireguard-s2s-helper";
  sudoPath;
  activeChildren = /* @__PURE__ */ new Set();
  closed = false;
  close() {
    this.closed = true;
    for (const child of this.activeChildren) {
      child.kill("SIGKILL");
    }
    this.activeChildren.clear();
  }
  doctor() {
    return this.call("doctor");
  }
  apply(config) {
    return this.call("apply", config);
  }
  down(interfaceName) {
    return this.call("down", { interfaceName });
  }
  status(interfaceName) {
    return this.call("status", { interfaceName });
  }
  call(action, payload) {
    if (this.closed) {
      return Promise.reject(new Error("Privileged helper client is closed"));
    }
    return new Promise((resolve, reject) => {
      const child = (0, import_node_child_process.spawn)(this.sudoPath, ["-n", "--", HelperClient.helperPath, action], {
        stdio: ["pipe", "pipe", "pipe"]
      });
      this.activeChildren.add(child);
      let stdout = "";
      let stderr = "";
      let outputTooLarge = false;
      const timeout = this.timers.scheduleTimeout(() => child.kill("SIGKILL"), 15e3);
      child.stdout.setEncoding("utf8");
      child.stderr.setEncoding("utf8");
      child.stdout.on("data", (chunk) => {
        stdout += chunk;
        if (stdout.length > 1048576) {
          outputTooLarge = true;
          child.kill("SIGKILL");
        }
      });
      child.stderr.on("data", (chunk) => {
        stderr += chunk;
        if (stderr.length > 65536) {
          child.kill("SIGKILL");
        }
      });
      child.on("error", (error) => {
        if (timeout) {
          this.timers.cancelTimeout(timeout);
        }
        this.activeChildren.delete(child);
        reject(new Error(`Cannot start the privileged helper: ${error.message}`));
      });
      child.on("close", (code) => {
        if (timeout) {
          this.timers.cancelTimeout(timeout);
        }
        this.activeChildren.delete(child);
        if (outputTooLarge) {
          reject(new Error("Privileged helper returned too much data"));
          return;
        }
        let envelope;
        try {
          envelope = JSON.parse(stdout);
        } catch {
          const detail = stderr.trim() || `exit code ${code ?? "unknown"}`;
          reject(new Error(`Privileged helper failed: ${detail}`));
          return;
        }
        if (code !== 0 || !envelope.ok || envelope.data === void 0) {
          reject(new Error(envelope.error || stderr.trim() || "Privileged helper failed"));
          return;
        }
        resolve(envelope.data);
      });
      child.stdin.on("error", () => void 0);
      child.stdin.end(payload === void 0 ? "" : JSON.stringify(payload));
    });
  }
}
// Annotate the CommonJS export names for ESM import in node:
0 && (module.exports = {
  HelperClient
});
//# sourceMappingURL=helper-client.js.map
