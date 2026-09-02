import { existsSync } from "node:fs";
import { spawn } from "node:child_process";
import type { HelperApplyConfig, HelperDoctorResult, HelperStatus } from "./types";

interface HelperEnvelope<T> {
    ok: boolean;
    data?: T;
    error?: string;
}

export class HelperClient {
    public static readonly helperPath = "/usr/local/libexec/iobroker-wireguard-s2s-helper";
    private readonly sudoPath: string;

    public constructor() {
        this.sudoPath = ["/usr/bin/sudo", "/bin/sudo"].find(existsSync) ?? "/usr/bin/sudo";
    }

    public doctor(): Promise<HelperDoctorResult> {
        return this.call<HelperDoctorResult>("doctor");
    }

    public apply(config: HelperApplyConfig): Promise<HelperStatus> {
        return this.call<HelperStatus>("apply", config);
    }

    public down(interfaceName: string): Promise<HelperStatus> {
        return this.call<HelperStatus>("down", { interfaceName });
    }

    public status(interfaceName: string): Promise<HelperStatus> {
        return this.call<HelperStatus>("status", { interfaceName });
    }

    private call<T>(action: string, payload?: unknown): Promise<T> {
        return new Promise<T>((resolve, reject) => {
            const child = spawn(
                this.sudoPath,
                ["-n", "--", HelperClient.helperPath, action],
                { stdio: ["pipe", "pipe", "pipe"] },
            );
            let stdout = "";
            let stderr = "";
            let outputTooLarge = false;
            const timeout = setTimeout(() => child.kill("SIGKILL"), 15_000);

            child.stdout.setEncoding("utf8");
            child.stderr.setEncoding("utf8");
            child.stdout.on("data", (chunk: string) => {
                stdout += chunk;
                if (stdout.length > 1_048_576) {
                    outputTooLarge = true;
                    child.kill("SIGKILL");
                }
            });
            child.stderr.on("data", (chunk: string) => {
                stderr += chunk;
                if (stderr.length > 65_536) {
                    child.kill("SIGKILL");
                }
            });
            child.on("error", error => {
                clearTimeout(timeout);
                reject(new Error(`Cannot start the privileged helper: ${error.message}`));
            });
            child.on("close", code => {
                clearTimeout(timeout);
                if (outputTooLarge) {
                    reject(new Error("Privileged helper returned too much data"));
                    return;
                }
                let envelope: HelperEnvelope<T>;
                try {
                    envelope = JSON.parse(stdout) as HelperEnvelope<T>;
                } catch {
                    const detail = stderr.trim() || `exit code ${code ?? "unknown"}`;
                    reject(new Error(`Privileged helper failed: ${detail}`));
                    return;
                }
                if (code !== 0 || !envelope.ok || envelope.data === undefined) {
                    reject(new Error(envelope.error || stderr.trim() || "Privileged helper failed"));
                    return;
                }
                resolve(envelope.data);
            });

            child.stdin.on("error", () => undefined);
            child.stdin.end(payload === undefined ? "" : JSON.stringify(payload));
        });
    }
}
