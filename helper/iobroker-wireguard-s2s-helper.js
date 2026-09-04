#!/usr/bin/env node
"use strict";

const fs = require("node:fs");
const path = require("node:path");
const net = require("node:net");
const { execFile } = require("node:child_process");
const { promisify } = require("node:util");

const execFileAsync = promisify(execFile);
const VERSION = "0.2.0";
const STATE_DIRECTORY = "/var/lib/iobroker-wireguard-s2s";
const MANAGED_BY = "ioBroker.wireguard-s2s";
const INTERFACE_PATTERN = /^iowg[0-9]{1,3}$/;
const HOSTNAME_PATTERN = /^(?=.{1,253}$)(?!-)(?:[a-zA-Z0-9-]{1,63}\.)*[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$/;
const BINARIES = {
    ip: ["/usr/sbin/ip", "/usr/bin/ip", "/sbin/ip", "/bin/ip"],
    wg: ["/usr/bin/wg", "/usr/sbin/wg", "/bin/wg", "/sbin/wg"],
    sysctl: ["/usr/sbin/sysctl", "/sbin/sysctl", "/usr/bin/sysctl"],
};

function send(data) {
    process.stdout.write(`${JSON.stringify({ ok: true, data })}\n`);
}

function fail(error) {
    const message = error instanceof Error ? error.message : String(error);
    process.stdout.write(`${JSON.stringify({ ok: false, error: message })}\n`);
    process.exitCode = 1;
}

function requireRoot() {
    if (process.platform !== "linux") {
        throw new Error("The WireGuard helper supports Linux only");
    }
    if (typeof process.geteuid !== "function" || process.geteuid() !== 0) {
        throw new Error("The WireGuard helper must run as root through the installed sudo policy");
    }
}

function binary(name) {
    const result = BINARIES[name].find(candidate => {
        try {
            fs.accessSync(candidate, fs.constants.X_OK);
            return true;
        } catch {
            return false;
        }
    });
    if (!result) {
        throw new Error(`Required executable '${name}' is not installed`);
    }
    return result;
}

async function run(name, args, allowFailure = false) {
    try {
        const result = await execFileAsync(binary(name), args, {
            encoding: "utf8",
            timeout: 10_000,
            maxBuffer: 1_048_576,
            env: { PATH: "/usr/sbin:/usr/bin:/sbin:/bin", LANG: "C", LC_ALL: "C" },
        });
        return { ok: true, stdout: String(result.stdout), stderr: String(result.stderr) };
    } catch (error) {
        if (allowFailure) {
            return {
                ok: false,
                stdout: typeof error.stdout === "string" ? error.stdout : "",
                stderr: typeof error.stderr === "string" ? error.stderr : "",
            };
        }
        const detail = typeof error.stderr === "string" && error.stderr.trim() ? error.stderr.trim() : error.message;
        throw new Error(`${name} failed: ${detail}`);
    }
}

function ensureStateDirectory() {
    fs.mkdirSync(STATE_DIRECTORY, { recursive: true, mode: 0o700 });
    const stat = fs.lstatSync(STATE_DIRECTORY);
    if (!stat.isDirectory() || stat.isSymbolicLink() || stat.uid !== 0) {
        throw new Error(`Unsafe helper state directory: ${STATE_DIRECTORY}`);
    }
    fs.chmodSync(STATE_DIRECTORY, 0o700);
}

function statePath(interfaceName) {
    validateInterfaceName(interfaceName);
    return path.join(STATE_DIRECTORY, `${interfaceName}.json`);
}

function readState(interfaceName) {
    ensureStateDirectory();
    const file = statePath(interfaceName);
    try {
        const stat = fs.lstatSync(file);
        if (!stat.isFile() || stat.isSymbolicLink() || stat.uid !== 0 || (stat.mode & 0o077) !== 0) {
            throw new Error(`Unsafe helper state file for ${interfaceName}`);
        }
        const value = JSON.parse(fs.readFileSync(file, "utf8"));
        if (value.managedBy !== MANAGED_BY || value.interfaceName !== interfaceName) {
            throw new Error(`Invalid ownership marker for ${interfaceName}`);
        }
        return value;
    } catch (error) {
        if (error && error.code === "ENOENT") {
            return undefined;
        }
        throw error;
    }
}

function writeState(interfaceName, state) {
    ensureStateDirectory();
    const target = statePath(interfaceName);
    const temporary = path.join(STATE_DIRECTORY, `.${interfaceName}.${process.pid}.tmp`);
    const descriptor = fs.openSync(temporary, "wx", 0o600);
    try {
        fs.writeFileSync(descriptor, `${JSON.stringify(state)}\n`, "utf8");
        fs.fsyncSync(descriptor);
    } finally {
        fs.closeSync(descriptor);
    }
    fs.renameSync(temporary, target);
    fs.chmodSync(target, 0o600);
}

function removeState(interfaceName) {
    try {
        fs.unlinkSync(statePath(interfaceName));
    } catch (error) {
        if (!error || error.code !== "ENOENT") {
            throw error;
        }
    }
}

async function readJsonInput() {
    const chunks = [];
    let size = 0;
    for await (const chunk of process.stdin) {
        size += chunk.length;
        if (size > 65_536) {
            throw new Error("Helper input exceeds 64 KiB");
        }
        chunks.push(chunk);
    }
    const text = Buffer.concat(chunks).toString("utf8");
    if (!text) {
        throw new Error("The helper requires a JSON request");
    }
    try {
        return JSON.parse(text);
    } catch {
        throw new Error("The helper request is not valid JSON");
    }
}

function validateInterfaceName(value) {
    if (typeof value !== "string" || !INTERFACE_PATTERN.test(value)) {
        throw new Error("interfaceName must match iowg0 through iowg999");
    }
    return value;
}

function validateKey(value, field, optional = false) {
    if (optional && (value === undefined || value === "")) {
        return undefined;
    }
    if (typeof value !== "string" || !/^[A-Za-z0-9+/]{43}=$/.test(value)) {
        throw new Error(`${field} is not a valid WireGuard key`);
    }
    if (Buffer.from(value, "base64").length !== 32) {
        throw new Error(`${field} is not a valid WireGuard key`);
    }
    return value;
}

function validateCidr(value, field, allowDefault = false) {
    if (typeof value !== "string") {
        throw new Error(`${field} contains a non-string value`);
    }
    const parts = value.split("/");
    const family = parts.length === 2 ? net.isIP(parts[0]) : 0;
    const prefix = Number(parts[1]);
    const maximum = family === 4 ? 32 : family === 6 ? 128 : -1;
    if (maximum < 0 || !Number.isInteger(prefix) || prefix < 0 || prefix > maximum) {
        throw new Error(`${field} contains an invalid CIDR network`);
    }
    if (!allowDefault && prefix === 0) {
        throw new Error(`${field} must not contain a default route`);
    }
    return { value, family };
}

function validateInteger(value, minimum, maximum, field) {
    if (!Number.isInteger(value) || value < minimum || value > maximum) {
        throw new Error(`${field} must be an integer between ${minimum} and ${maximum}`);
    }
    return value;
}

function validateEndpoint(value) {
    if (value === undefined || value === "") {
        return undefined;
    }
    if (typeof value !== "string" || value.includes("\n") || value.includes("\r")) {
        throw new Error("peer.endpoint is invalid");
    }

    let host;
    let portText;
    const bracketMatch = /^\[([^\]]+)]:(\d{1,5})$/.exec(value);
    if (bracketMatch) {
        host = bracketMatch[1];
        portText = bracketMatch[2];
        if (net.isIP(host) !== 6) {
            throw new Error("peer.endpoint contains an invalid IPv6 address");
        }
    } else {
        const separator = value.lastIndexOf(":");
        if (separator < 1) {
            throw new Error("peer.endpoint must contain a port");
        }
        host = value.slice(0, separator);
        portText = value.slice(separator + 1);
        if (net.isIP(host) !== 4 && !HOSTNAME_PATTERN.test(host)) {
            throw new Error("peer.endpoint contains an invalid hostname");
        }
    }
    validateInteger(Number(portText), 1, 65535, "peer endpoint port");
    return value;
}

function validateApplyConfig(value) {
    if (!value || typeof value !== "object" || Array.isArray(value)) {
        throw new Error("Apply configuration must be an object");
    }
    const interfaceName = validateInterfaceName(value.interfaceName);
    const localAddresses = validateCidrArray(value.localAddresses, "localAddresses");
    const allowedIPs = validateCidrArray(value.peer && value.peer.allowedIPs, "peer.allowedIPs");
    if (localAddresses.length === 0 || allowedIPs.length === 0) {
        throw new Error("localAddresses and peer.allowedIPs must not be empty");
    }
    const mtu = value.mtu === undefined ? undefined : validateInteger(value.mtu, 576, 9000, "mtu");
    return {
        interfaceName,
        localAddresses: localAddresses.map(item => item.value),
        privateKey: validateKey(value.privateKey, "privateKey"),
        listenPort: validateInteger(value.listenPort, 1, 65535, "listenPort"),
        peer: {
            publicKey: validateKey(value.peer && value.peer.publicKey, "peer.publicKey"),
            presharedKey: validateKey(value.peer && value.peer.presharedKey, "peer.presharedKey", true),
            endpoint: validateEndpoint(value.peer && value.peer.endpoint),
            allowedIPs: allowedIPs.map(item => item.value),
            persistentKeepalive: validateInteger(
                value.peer && value.peer.persistentKeepalive,
                0,
                65535,
                "peer.persistentKeepalive",
            ),
        },
        mtu,
        enableIPv4Forwarding: value.enableIPv4Forwarding === true,
        enableIPv6Forwarding: value.enableIPv6Forwarding === true,
    };
}

function validateCidrArray(value, field) {
    if (!Array.isArray(value) || value.length > 128) {
        throw new Error(`${field} must be an array with at most 128 entries`);
    }
    return [...new Set(value)].map(item => validateCidr(item, field));
}

async function interfaceExists(interfaceName) {
    return (await run("ip", ["link", "show", "dev", interfaceName], true)).ok;
}

async function currentPublicKey(interfaceName, allowFailure = false) {
    const result = await run("wg", ["show", interfaceName, "public-key"], allowFailure);
    return result.ok ? result.stdout.trim() : "";
}

async function assertOwnership(interfaceName, existingState, exists) {
    if (!exists) {
        return;
    }
    if (!existingState) {
        throw new Error(`Refusing to manage existing interface ${interfaceName} without an ownership marker`);
    }
    const publicKey = await currentPublicKey(interfaceName, true);
    if (!publicKey || (existingState.publicKey && publicKey !== existingState.publicKey)) {
        throw new Error(`Ownership check failed for existing interface ${interfaceName}`);
    }
}

function buildWireGuardConfig(config) {
    const lines = [
        "[Interface]",
        `PrivateKey = ${config.privateKey}`,
        `ListenPort = ${config.listenPort}`,
        "",
        "[Peer]",
        `PublicKey = ${config.peer.publicKey}`,
    ];
    if (config.peer.presharedKey) {
        lines.push(`PresharedKey = ${config.peer.presharedKey}`);
    }
    lines.push(`AllowedIPs = ${config.peer.allowedIPs.join(", ")}`);
    if (config.peer.endpoint) {
        lines.push(`Endpoint = ${config.peer.endpoint}`);
    }
    if (config.peer.persistentKeepalive > 0) {
        lines.push(`PersistentKeepalive = ${config.peer.persistentKeepalive}`);
    }
    return `${lines.join("\n")}\n`;
}

function createTemporaryConfig(contents) {
    const directory = fs.mkdtempSync("/run/iobroker-wireguard-s2s-");
    fs.chmodSync(directory, 0o700);
    const file = path.join(directory, "wireguard.conf");
    fs.writeFileSync(file, contents, { encoding: "utf8", mode: 0o600, flag: "wx" });
    return { directory, file };
}

function removeTemporaryConfig(temporary) {
    if (!temporary) {
        return;
    }
    try {
        fs.unlinkSync(temporary.file);
    } catch {
        // Best effort cleanup; the temporary directory is root-only and /run is ephemeral.
    }
    try {
        fs.rmdirSync(temporary.directory);
    } catch {
        // Best effort cleanup.
    }
}

async function apply(configValue) {
    const config = validateApplyConfig(configValue);
    ensureStateDirectory();
    const oldState = readState(config.interfaceName);
    const existed = await interfaceExists(config.interfaceName);
    await assertOwnership(config.interfaceName, oldState, existed);
    let created = false;
    let temporary;

    try {
        if (!existed) {
            await run("ip", ["link", "add", "dev", config.interfaceName, "type", "wireguard"]);
            created = true;
        }
        temporary = createTemporaryConfig(buildWireGuardConfig(config));
        await run("wg", ["syncconf", config.interfaceName, temporary.file]);
        await run("ip", ["address", "flush", "dev", config.interfaceName, "scope", "global"]);
        for (const address of config.localAddresses) {
            await run("ip", ["address", "add", address, "dev", config.interfaceName]);
        }
        if (config.mtu !== undefined) {
            await run("ip", ["link", "set", "dev", config.interfaceName, "mtu", String(config.mtu)]);
        }
        await run("ip", ["link", "set", "dev", config.interfaceName, "up"]);

        const staleRoutes = Array.isArray(oldState && oldState.routes)
            ? oldState.routes.filter(route => !config.peer.allowedIPs.includes(route))
            : [];
        for (const route of staleRoutes) {
            const familyFlag = net.isIP(route.split("/")[0]) === 6 ? "-6" : "-4";
            await run("ip", [familyFlag, "route", "del", route, "dev", config.interfaceName], true);
        }
        for (const route of config.peer.allowedIPs) {
            const familyFlag = net.isIP(route.split("/")[0]) === 6 ? "-6" : "-4";
            await run("ip", [familyFlag, "route", "replace", route, "dev", config.interfaceName]);
        }

        if (config.enableIPv4Forwarding) {
            await run("sysctl", ["-w", "net.ipv4.ip_forward=1"]);
        }
        if (config.enableIPv6Forwarding) {
            await run("sysctl", ["-w", "net.ipv6.conf.all.forwarding=1"]);
        }

        const publicKey = await currentPublicKey(config.interfaceName);
        writeState(config.interfaceName, {
            managedBy: MANAGED_BY,
            interfaceName: config.interfaceName,
            publicKey,
            routes: config.peer.allowedIPs,
            addresses: config.localAddresses,
            updatedAt: new Date().toISOString(),
        });
        return status(config.interfaceName);
    } catch (error) {
        if (created) {
            await run("ip", ["link", "delete", "dev", config.interfaceName], true);
            removeState(config.interfaceName);
        }
        throw error;
    } finally {
        removeTemporaryConfig(temporary);
    }
}

async function down(interfaceNameValue) {
    const interfaceName = validateInterfaceName(interfaceNameValue);
    const existingState = readState(interfaceName);
    const exists = await interfaceExists(interfaceName);
    await assertOwnership(interfaceName, existingState, exists);
    if (exists) {
        await run("ip", ["link", "delete", "dev", interfaceName]);
    }
    removeState(interfaceName);
    return emptyStatus(interfaceName);
}

function emptyStatus(interfaceName) {
    return {
        exists: false,
        owned: false,
        up: false,
        interfaceName,
        publicKey: "",
        listenPort: 0,
        peers: [],
    };
}

async function status(interfaceNameValue) {
    const interfaceName = validateInterfaceName(interfaceNameValue);
    const existingState = readState(interfaceName);
    const exists = await interfaceExists(interfaceName);
    if (!exists) {
        return { ...emptyStatus(interfaceName), owned: Boolean(existingState) };
    }
    await assertOwnership(interfaceName, existingState, exists);

    const [dump, link] = await Promise.all([
        run("wg", ["show", interfaceName, "dump"]),
        run("ip", ["-json", "link", "show", "dev", interfaceName]),
    ]);
    const lines = dump.stdout.trim().split("\n");
    const interfaceFields = (lines.shift() || "").split("\t");
    if (interfaceFields.length < 4) {
        throw new Error(`Unexpected WireGuard status for ${interfaceName}`);
    }
    const linkData = JSON.parse(link.stdout);
    const flags = Array.isArray(linkData[0] && linkData[0].flags) ? linkData[0].flags : [];
    const peers = lines.filter(Boolean).map(line => {
        const fields = line.split("\t");
        if (fields.length < 8) {
            throw new Error(`Unexpected peer status for ${interfaceName}`);
        }
        return {
            publicKey: fields[0],
            endpoint: fields[2] === "(none)" ? "" : fields[2],
            allowedIPs: fields[3] === "(none)" ? [] : fields[3].split(",").filter(Boolean),
            latestHandshake: safeNumber(fields[4]),
            rxBytes: safeNumber(fields[5]),
            txBytes: safeNumber(fields[6]),
            persistentKeepalive: safeNumber(fields[7]),
        };
    });
    return {
        exists: true,
        owned: true,
        up: flags.includes("UP"),
        interfaceName,
        publicKey: interfaceFields[1] === "(none)" ? "" : interfaceFields[1],
        listenPort: safeNumber(interfaceFields[2]),
        peers,
    };
}

function safeNumber(value) {
    const number = Number(value);
    return Number.isSafeInteger(number) && number >= 0 ? number : 0;
}

async function doctor() {
    requireRoot();
    return {
        platform: process.platform,
        helperVersion: VERSION,
        binaries: Object.fromEntries(Object.keys(BINARIES).map(name => [name, binary(name)])),
    };
}

async function main() {
    requireRoot();
    const action = process.argv[2];
    if (action === "doctor") {
        send(await doctor());
        return;
    }
    const request = await readJsonInput();
    if (action === "apply") {
        send(await apply(request));
    } else if (action === "down") {
        send(await down(request && request.interfaceName));
    } else if (action === "status") {
        send(await status(request && request.interfaceName));
    } else {
        throw new Error("Unknown helper action");
    }
}

if (require.main === module) {
    main().catch(fail);
} else {
    module.exports = {
        buildWireGuardConfig,
        validateApplyConfig,
        validateCidr,
        validateEndpoint,
        validateInterfaceName,
        validateKey,
    };
}
