/**
 * pi-tor-proxy
 *
 * Self-contained Pi extension that routes all requests through Tor.
 * Automatically downloads and manages a Tor binary - no system install required.
 *
 * Commands:
 *   /tor-start  - Enable Tor mode (downloads on first run)
 *   /tor-stop   - Disable Tor mode
 *   /tor-status - Show current Tor status and IP
 *   /tor-cycle  - Get a new Tor circuit (new IP)
 */

import type { ExtensionAPI, ExtensionCommandContext, ExtensionUIContext } from "@earendil-works/pi-coding-agent";
import { spawn, execFileSync, type ChildProcess } from "node:child_process";
import { createHash } from "node:crypto";
import { chmodSync, createReadStream, createWriteStream, existsSync, mkdirSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import net from "node:net";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { pipeline } from "node:stream/promises";
import { Readable } from "node:stream";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

/** Tor configuration */
const TOR_SOCKS_HOST = "127.0.0.1";
const TOR_SOCKS_PORT = 9050;
const TOR_SOCKS_PROXY = `socks5h://${TOR_SOCKS_HOST}:${TOR_SOCKS_PORT}`;

/** Status key for footer display */
const STATUS_KEY = "tor";

/** Directory to store Tor binary */
const TOR_DIR = join(__dirname, ".tor");
const TOR_DATA_DIR = join(TOR_DIR, "data");
const TOR_STATE_FILE = join(TOR_DATA_DIR, "enabled");
const TOR_STARTING_FILE = join(TOR_DATA_DIR, "starting");
const LEASE_DIR = join(TOR_DIR, "leases");
const LEASE_TTL_MS = 90_000;
const STARTING_TTL_MS = 120_000;
const HEARTBEAT_MS = 30_000;
const MAX_CYCLE_ATTEMPTS = 3;
const CYCLE_FIRST_WAIT_MS = 35_000;
const CYCLE_RETRY_WAIT_MS = 20_000;
const CYCLE_RETRY_DELAY_MS = 10_000;
const TOR_BUNDLE_SHA256: Record<string, string> = {
  "tor-expert-bundle-linux-x86_64-14.5.3.tar.gz": "34bac6a9cddfbd5cd8e74e546e00dcfa7aa988a19c3b5574ba7b52babe6c6e1a",
  "tor-expert-bundle-macos-x86_64-14.5.3.tar.gz": "28f1a7355abd17d3ad0cc0438caf0a5c563939115e6e22885ea470a8bda55a27",
  "tor-expert-bundle-macos-aarch64-14.5.3.tar.gz": "a57479977c07a270390b40bebff6a85f80de3007e0b637d63322e078f09c6ec9",
  "tor-expert-bundle-linux-aarch64-16.0a7.tar.gz": "1a51b37cc68f2df4d8952d3f343794f2f966c59d84fe580c56192377c00fcc1b",
};
const TOR_CONTROL_HOST = "127.0.0.1";
const TOR_CONTROL_PORT_FILE = join(TOR_DATA_DIR, "control.port");
const TOR_CONTROL_COOKIE_FILE = join(TOR_DATA_DIR, "control_auth_cookie");

/** Environment variable names to set when Tor is active */
const PROXY_ENV_VARS = [
  "HTTP_PROXY",
  "HTTPS_PROXY",
  "http_proxy",
  "https_proxy",
  "ALL_PROXY",
  "all_proxy",
] as const;

const savedProxyEnv = new Map<string, string | undefined>();

interface TorState {
  enabled: boolean;
  torProcess: ChildProcess | null;
  torPid: number | null;
  currentIp: string | null;
}
type Notify = ExtensionUIContext["notify"];

export default function (pi: ExtensionAPI) {
  const state: TorState = {
    enabled: false,
    torProcess: null,
    torPid: null,
    currentIp: null,
  };

  let restartAttempts = 0;
  let cycleInProgress = false;
  let stopRequested = false;
  const MAX_RESTART_ATTEMPTS = 3;
  let startPromise: Promise<string | null> | null = null;
  function setProxyEnv(): void {
    for (const v of PROXY_ENV_VARS) {
      if (!savedProxyEnv.has(v)) savedProxyEnv.set(v, process.env[v]);
      process.env[v] = TOR_SOCKS_PROXY;
    }
  }

  function clearProxyEnv(): void {
    for (const v of PROXY_ENV_VARS) {
      if (savedProxyEnv.has(v)) {
        const original = savedProxyEnv.get(v);
        if (original === undefined) {
          delete process.env[v];
        } else {
          process.env[v] = original;
        }
        savedProxyEnv.delete(v);
      } else {
        delete process.env[v];
      }
    }
  }

  function persistEnabled(enabled: boolean): void {
    try {
      mkdirSync(TOR_DATA_DIR, { recursive: true });
      writeFileSync(TOR_STATE_FILE, enabled ? "1" : "0");
    } catch {}
  }

  function readPersistedEnabled(): boolean {
    try {
      return readFileSync(TOR_STATE_FILE, "utf8").trim() === "1";
    } catch {
      return false;
    }
  }

  let startingMarkerWritten = false;

  function writeStartingMarker(): void {
    try {
      mkdirSync(TOR_DATA_DIR, { recursive: true });
      writeFileSync(TOR_STARTING_FILE, String(Date.now()));
      startingMarkerWritten = true;
    } catch {}
  }

  function clearStartingMarker(): void {
    if (!startingMarkerWritten) return;
    startingMarkerWritten = false;
    try {
      rmSync(TOR_STARTING_FILE, { force: true });
    } catch {}
  }

  function startingInProgress(): boolean {
    try {
      const written = Number(readFileSync(TOR_STARTING_FILE, "utf8"));
      return Number.isFinite(written) && Date.now() - written < STARTING_TTL_MS;
    } catch {
      return false;
    }
  }

  function envIsSet(): boolean {
    return process.env.HTTP_PROXY === TOR_SOCKS_PROXY;
  }

  interface InstanceLease {
    pid: number;
    envSet: boolean;
    updatedAt: number;
  }

  function writeLease(): void {
    try {
      mkdirSync(LEASE_DIR, { recursive: true });
      writeFileSync(
        join(LEASE_DIR, `${process.pid}.json`),
        JSON.stringify({ pid: process.pid, envSet: envIsSet(), updatedAt: Date.now() })
      );
    } catch {}
  }

  function readLeases(): InstanceLease[] {
    const leases: InstanceLease[] = [];
    try {
      for (const file of readdirSync(LEASE_DIR)) {
        if (!file.endsWith(".json")) continue;
        try {
          const lease = JSON.parse(readFileSync(join(LEASE_DIR, file), "utf8")) as InstanceLease;
          if (lease && typeof lease.pid === "number" && typeof lease.envSet === "boolean" && typeof lease.updatedAt === "number") {
            leases.push(lease);
          }
        } catch {}
      }
    } catch {}
    return leases;
  }

  function anyLiveInstanceNeedsTor(): boolean {
    const now = Date.now();
    return readLeases().some((l) => l.envSet && now - l.updatedAt < LEASE_TTL_MS);
  }

  async function maybeKillTor(): Promise<void> {
    if (readPersistedEnabled()) return;
    if (startingInProgress()) return;
    if (!(await isTorListening())) return;
    if (anyLiveInstanceNeedsTor()) return;
    state.torPid = readTorPid();
    await killTorProcess();
  }

  async function syncEnvToMarker(): Promise<void> {
    const enabled = readPersistedEnabled();
    state.enabled = enabled;
    let listening = await isTorListening();
    if (enabled && !listening) {
      const torBin = findTorBinary();
      if (torBin) listening = (await startTor(torBin)) === null;
    }
    if (enabled && listening) {
      if (!envIsSet()) setProxyEnv();
    } else if (!enabled && envIsSet()) {
      clearProxyEnv();
    }
    writeLease();
    if (!enabled) await maybeKillTor();
    updateStatus(statusUi);
  }

  function updateStatus(ui: ExtensionUIContext | null): void {
    if (!ui) return;
    if (state.enabled) {
      const ip = state.currentIp ? ` (${state.currentIp})` : "";
      ui.setStatus(STATUS_KEY, `🔒 Tor${ip}`);
    } else {
      ui.setStatus(STATUS_KEY, "");
    }
  }

  let statusUi: ExtensionUIContext | null = null;

  function createInterval(ms: number, fn: () => Promise<void>) {
    let timer: ReturnType<typeof setInterval> | null = null;
    return {
      start() {
        if (timer) return;
        timer = setInterval(fn, ms);
      },
      stop() {
        if (timer) {
          clearInterval(timer);
          timer = null;
        }
      },
    };
  }

  const ipPolling = createInterval(20_000, async () => {
    const ip = await getTorIp();
    if (!ip) {
      if (state.currentIp) {
        state.currentIp = null;
        updateStatus(statusUi);
      }
      return;
    }
    if (ip === state.currentIp) return;
    state.currentIp = ip;
    updateStatus(statusUi);
  });

  const heartbeat = createInterval(HEARTBEAT_MS, async () => {
    writeLease();
    if (!readPersistedEnabled()) await maybeKillTor();
  });

  function sleep(ms: number): Promise<void> {
    return new Promise((resolve) => setTimeout(resolve, ms));
  }

  function pendingNote(applyNow: boolean): string {
    return applyNow ? "" : "\nApplies from next turn.";
  }

  /**
   * Check if Tor is listening on SOCKS port
   */
  async function isTorListening(): Promise<boolean> {
    return new Promise((resolve) => {
      const socket = new net.Socket();
      socket.setTimeout(1500);
      socket.on("connect", () => { socket.destroy(); resolve(true); });
      socket.on("timeout", () => { socket.destroy(); resolve(false); });
      socket.on("error", () => { socket.destroy(); resolve(false); });
      socket.connect(TOR_SOCKS_PORT, TOR_SOCKS_HOST);
    });
  }

  /**
   * Get platform-specific Tor download URL
   */
  function getTorDownloadUrl(): string | null {
    const platform = process.platform;
    const arch = process.arch;

    let torPlatform: string;
    let torArch: string;

    switch (platform) {
      case "linux":
        torPlatform = "linux";
        break;
      case "darwin":
        torPlatform = "macos";
        break;
      default:
        return null;
    }

    switch (arch) {
      case "x64":
        torArch = "x86_64";
        break;
      case "arm64":
        torArch = "aarch64";
        break;
      default:
        return null;
    }

    const version = "14.5.3";
    const alphaVersion = "16.0a7";

    const stableUrl = `https://archive.torproject.org/tor-package-archive/torbrowser/${version}/tor-expert-bundle-${torPlatform}-${torArch}-${version}.tar.gz`;
    const alphaUrl = `https://archive.torproject.org/tor-package-archive/torbrowser/${alphaVersion}/tor-expert-bundle-${torPlatform}-${torArch}-${alphaVersion}.tar.gz`;

    if (platform === "linux" && arch === "arm64") {
      return alphaUrl;
    }

    return stableUrl;
  }

  async function sha256File(path: string): Promise<string> {
    const hash = createHash("sha256");
    await pipeline(createReadStream(path), hash);
    return hash.digest("hex");
  }

  /**
   * Download and extract Tor binary
   */
  async function downloadTor(
    notify: Notify
  ): Promise<string | null> {
    const url = getTorDownloadUrl();
    if (!url) {
      notify(`Unsupported platform: ${process.platform}/${process.arch}`, "error");
      return null;
    }

    notify("Downloading Tor... (first time only, ~30MB)", "info");

    const tarPath = join(TOR_DIR, "tor.tar.gz");
    try {
      mkdirSync(TOR_DIR, { recursive: true });

      const response = await fetch(url, { signal: AbortSignal.timeout(120_000) });
      if (!response.ok) {
        throw new Error(`HTTP ${response.status}: ${response.statusText}`);
      }
      if (!response.body) {
        throw new Error("Empty response body");
      }

      const fileStream = createWriteStream(tarPath);

      await pipeline(Readable.fromWeb(response.body as any), fileStream);

      const fileName = url.split("/").pop() ?? "";
      const expectedSha = TOR_BUNDLE_SHA256[fileName];
      if (!expectedSha) {
        throw new Error(`No pinned SHA-256 for ${fileName}`);
      }
      const actualSha = await sha256File(tarPath);
      if (actualSha !== expectedSha) {
        throw new Error(`Checksum mismatch for ${fileName}: expected ${expectedSha}, got ${actualSha}`);
      }

      notify("Extracting Tor...", "info");

      await new Promise<void>((resolve, reject) => {
        const child = spawn("tar", ["-xzf", tarPath, "-C", TOR_DIR], {
          stdio: ["ignore", "ignore", "pipe"],
        });
        let stderr = "";
        child.stderr?.on("data", (d: Buffer) => { stderr += d.toString(); });
        child.on("close", (code) => {
          if (code === 0) resolve();
          else reject(new Error(`tar exited with code ${code}: ${stderr.trim()}`));
        });
        child.on("error", reject);
      });

      const torBin = findTorBinary();
      if (torBin) {
        chmodSync(torBin, 0o755);
        rmSync(tarPath);
        notify("Tor downloaded.", "info");
        return torBin;
      }

      notify("Tor binary not found after extraction", "error");
      rmSync(tarPath, { force: true });
      return null;
    } catch (err) {
      notify(`Download failed: ${err instanceof Error ? err.message : String(err)}`, "error");
      rmSync(tarPath, { force: true });
      return null;
    }
  }

  /**
   * Find existing Tor binary
   */
  function findTorBinary(): string | null {
    const locations = [
      join(TOR_DIR, "tor", "tor"),
      join(TOR_DIR, "debug", "tor"),
    ];

    for (const loc of locations) {
      if (existsSync(loc)) return loc;
    }

    return null;
  }

  function isTorProcess(pid: number): boolean {
    if (process.platform === "linux") {
      try {
        return readFileSync(`/proc/${pid}/comm`, "utf8").trim().toLowerCase() === "tor";
      } catch {
        return false;
      }
    }
    try {
      const out = execFileSync("ps", ["-p", String(pid), "-o", "comm="], { encoding: "utf8" });
      return out.trim().toLowerCase() === "tor";
    } catch {
      return false;
    }
  }

  function readTorPid(): number | null {
    try {
      const pid = Number(readFileSync(join(TOR_DATA_DIR, "tor.pid"), "utf8").trim());
      if (!Number.isInteger(pid) || pid <= 0) return null;
      return isTorProcess(pid) ? pid : null;
    } catch {
      return null;
    }
  }

  /**
   * Start Tor process and wait for bootstrap
   */
  function startTor(torBin: string): Promise<string | null> {
    if (startPromise) return startPromise;
    const promise = new Promise<string | null>((resolve) => {

      mkdirSync(TOR_DATA_DIR, { recursive: true });
      const torDir = dirname(torBin);

      const child = spawn(torBin, [
        "--SocksPort", `${TOR_SOCKS_HOST}:${TOR_SOCKS_PORT}`,
        "--ControlPort", "auto",
        "--ControlPortWriteToFile", TOR_CONTROL_PORT_FILE,
        "--CookieAuthentication", "1",
        "--DataDirectory", TOR_DATA_DIR,
        "--PidFile", join(TOR_DATA_DIR, "tor.pid"),
        "--Log", "notice stdout",
        "--DisableDebuggerAttachment", "0",
      ], {
        stdio: ["ignore", "pipe", "pipe"],
        env: {
          ...process.env,
          LD_LIBRARY_PATH: process.env.LD_LIBRARY_PATH
            ? `${process.env.LD_LIBRARY_PATH}:${torDir}`
            : torDir,
        },
      });

      let resolved = false;
      let stdoutBuffer = "";
      const timeout = setTimeout(() => {
        if (!resolved) {
          resolved = true;
          child.kill();
          resolve("Tor startup timed out (60s)");
        }
      }, 60000);

      child.stdout?.on("data", (data: Buffer) => {
        stdoutBuffer += data.toString();
        let newlineIdx: number;
        while ((newlineIdx = stdoutBuffer.indexOf("\n")) >= 0) {
          const line = stdoutBuffer.slice(0, newlineIdx).trim();
          stdoutBuffer = stdoutBuffer.slice(newlineIdx + 1);
          if (line.includes("Bootstrapped 100%") && !resolved) {
            resolved = true;
            clearTimeout(timeout);
            state.torProcess = child;
            state.torPid = child.pid ?? null;
            restartAttempts = 0;
            setupTorMonitor(torBin);
            resolve(null);
          }
        }
      });

      child.stderr?.on("data", (data: Buffer) => {
        const text = data.toString();
        if (text.includes("[err]")) {
          console.error("Tor error:", text);
        }
      });

      child.on("close", (code) => {
        if (!resolved) {
          resolved = true;
          clearTimeout(timeout);
          resolve(`Tor exited with code ${code}`);
        }
        if (state.torProcess === child) state.torProcess = null;
        if (state.torPid === child.pid) state.torPid = null;
      });

      child.on("error", (err) => {
        if (!resolved) {
          resolved = true;
          clearTimeout(timeout);
          resolve(`Failed to start Tor: ${err.message}`);
        }
      });
    }).finally(() => {
      startPromise = null;
    });
    startPromise = promise;
    return promise;
  }

  /**
   * Stop Tor process
   */
  async function killTorProcess(): Promise<void> {
    const child = state.torProcess;
    const pid = state.torPid;
    state.torProcess = null;
    state.torPid = null;

    if (child) {
      child.kill("SIGTERM");
    } else if (pid) {
      try { process.kill(pid, "SIGTERM"); } catch { return; }
    } else {
      return;
    }

    for (let i = 0; i < 20; i++) {
      await sleep(250);
      const exited = child ? child.exitCode !== null : !(await isTorListening());
      if (exited) return;
    }

    if (child) {
      child.kill("SIGKILL");
    } else if (pid) {
      try { process.kill(pid, "SIGKILL"); } catch {}
    }
  }

  async function stopTor(): Promise<void> {
    await killTorProcess();
    state.currentIp = null;
  }

  /**
   * Get IP through Tor
   */
  function curlThroughTor(url: string): Promise<string | null> {
    return new Promise((resolve) => {
      const child = spawn("curl", [
        "-s", "--max-time", "15",
        "--proxy", TOR_SOCKS_PROXY,
        url,
      ]);
      let output = "";
      child.stdout.on("data", (d: Buffer) => { output += d.toString(); });
      child.on("close", () => resolve(output.trim() || null));
      child.on("error", () => resolve(null));
    });
  }

  let leakReported = false;

  async function getTorIp(): Promise<string | null> {
    const check = await curlThroughTor("https://check.torproject.org/api/ip");
    if (check) {
      try {
        const parsed = JSON.parse(check) as { IsTor?: unknown; IP?: unknown };
        if (parsed.IsTor === true && typeof parsed.IP === "string" && parsed.IP) {
          leakReported = false;
          return parsed.IP;
        }
        if (parsed.IsTor === false) {
          console.error("Traffic is not exiting through Tor: check.torproject.org reports IsTor=false");
          if (!leakReported) {
            leakReported = true;
            statusUi?.notify("Traffic is not exiting through Tor — check your proxy configuration", "error");
          }
          return null;
        }
      } catch {}
    }
    return curlThroughTor("https://api.ipify.org");
  }

  /**
   * Request new Tor circuit (new identity)
   */
  function readControlPort(): number | null {
    try {
      const raw = readFileSync(TOR_CONTROL_PORT_FILE, "utf8").trim();
      const match = raw.match(/PORT=(?:.*:)?(\d{1,5})$/);
      const port = match ? Number(match[1]) : Number(raw);
      return Number.isInteger(port) && port > 0 && port <= 65535 ? port : null;
    } catch {
      return null;
    }
  }

  function readControlCookie(): Buffer | null {
    try {
      const cookie = readFileSync(TOR_CONTROL_COOKIE_FILE);
      return cookie.length === 32 ? cookie : null;
    } catch {
      return null;
    }
  }

  async function signalNewnym(): Promise<"ok" | "rate-limited" | "failed"> {
    const port = readControlPort();
    if (!port) return "failed";
    const cookie = readControlCookie();
    if (!cookie) return "failed";

    return new Promise((resolve) => {
      const socket = new net.Socket();
      let buffer = "";
      let stage = 0;
      let result: "ok" | "rate-limited" | "failed" = "failed";
      let settled = false;

      const settle = (value: "ok" | "rate-limited" | "failed") => {
        if (settled) return;
        settled = true;
        socket.destroy();
        resolve(value);
      };

      socket.setTimeout(8000);
      socket.on("timeout", () => settle(result));
      socket.on("error", () => settle(result));
      socket.on("close", () => settle(result));

      socket.on("connect", () => {
        socket.write(`AUTHENTICATE ${cookie.toString("hex")}\r\nSIGNAL NEWNYM\r\nQUIT\r\n`);
      });

      socket.on("data", (chunk: Buffer) => {
        buffer += chunk.toString();
        let idx: number;
        while ((idx = buffer.indexOf("\r\n")) >= 0) {
          const line = buffer.slice(0, idx);
          buffer = buffer.slice(idx + 2);
          if (stage === 0) {
            if (line.startsWith("250-")) continue;
            if (line.startsWith("250 ")) {
              stage = 1;
              continue;
            }
            settle("failed");
            return;
          }
          if (stage === 1) {
            if (line.startsWith("250-")) continue;
            if (line.startsWith("250")) {
              result = "ok";
              stage = 2;
              continue;
            }
            if (line.startsWith("551")) {
              result = "rate-limited";
              stage = 2;
              continue;
            }
            settle("failed");
            return;
          }
          if (stage === 2) {
            settle(result);
            return;
          }
        }
      });

      socket.connect(port, TOR_CONTROL_HOST);
    });
  }

  async function waitForNewIp(oldIp: string | null, timeoutMs: number): Promise<string | null> {
    const deadline = Date.now() + timeoutMs;
    let lastIp: string | null = null;
    while (Date.now() < deadline) {
      if (!state.enabled) break;
      const ip = await getTorIp();
      if (ip) lastIp = ip;
      if (ip && ip !== oldIp) return ip;
      await sleep(2000);
    }
    return lastIp;
  }

  async function renewTorCircuit(): Promise<boolean> {
    const signal = await signalNewnym();
    if (signal === "ok") return true;
    if (signal === "rate-limited") {
      await sleep(11_000);
      if ((await signalNewnym()) === "ok") return true;
    }

    const torBin = findTorBinary();
    if (!torBin) return false;
    if (!state.torProcess && !state.torPid) return false;

    cycleInProgress = true;
    try {
      await killTorProcess();
      await sleep(1000);
      return (await startTor(torBin)) === null;
    } finally {
      cycleInProgress = false;
    }
  }

  /**
   * Enable Tor mode
   */
  async function enableTor(ctx: ExtensionCommandContext): Promise<void> {
    stopRequested = false;
    const listening = await isTorListening();
    if (!listening) {
      let torBin = findTorBinary();
      if (!torBin) {
        torBin = await downloadTor(ctx.ui.notify);
      }
      if (!torBin) {
        ctx.ui.notify("Failed to get Tor binary", "error");
        return;
      }

      ctx.ui.notify("Starting Tor...", "info");
      writeStartingMarker();
      const failure = await startTor(torBin);
      if (failure) {
        clearStartingMarker();
        ctx.ui.notify(failure, "error");
        return;
      }
      if (stopRequested) {
        stopRequested = false;
        await disableTor(ctx);
        return;
      }
    } else {
      state.torPid = readTorPid();
    }

    state.enabled = true;
    persistEnabled(true);
    clearStartingMarker();
    if (ctx.isIdle() && !envIsSet()) setProxyEnv();
    writeLease();

    const ip = await getTorIp();
    if (stopRequested) {
      stopRequested = false;
      await disableTor(ctx);
      return;
    }
    state.currentIp = ip;

    updateStatus(ctx.ui);
    statusUi = ctx.ui;
    ipPolling.start();
    const ipMsg = ip ? `\nIP: ${ip}` : "";
    const pending = pendingNote(ctx.isIdle());
    ctx.ui.notify(`Tor enabled.${ipMsg}${pending}`, "info");
  }

  /**
   * Disable Tor mode
   */
  async function disableTor(ctx: ExtensionCommandContext): Promise<void> {
    clearStartingMarker();
    state.enabled = false;
    state.currentIp = null;
    persistEnabled(false);
    if (ctx.isIdle() && envIsSet()) clearProxyEnv();
    writeLease();
    await maybeKillTor();
    ipPolling.stop();
    updateStatus(ctx.ui);
    statusUi = null;
    const pending = pendingNote(ctx.isIdle());
    ctx.ui.notify(`Tor disabled.${pending}`, "info");
  }

  // Register commands
  pi.registerCommand("tor-start", {
    description: "Enable Tor mode (downloads on first run)",
    handler: async (_args, ctx) => {
      await enableTor(ctx);
    },
  });

  pi.registerCommand("tor-stop", {
    description: "Disable Tor mode",
    handler: async (_args, ctx) => {
      stopRequested = true;
      await disableTor(ctx);
    },
  });

  pi.registerCommand("tor-status", {
    description: "Show Tor status and current IP",
    handler: async (_args, ctx) => {
      const enabled = readPersistedEnabled();
      state.enabled = enabled;
      if (!enabled) {
        ctx.ui.notify("Tor: DISABLED", "info");
        updateStatus(ctx.ui);
        return;
      }

      const ip = await getTorIp();
      state.currentIp = ip;

      const pending = pendingNote(ctx.isIdle() || envIsSet());
      const ipStr = ip ? `\nIP: ${ip}` : "\nIP: unknown";
      ctx.ui.notify(`Tor: ENABLED\nProxy: ${TOR_SOCKS_PROXY}${ipStr}${pending}`, "info");
      updateStatus(ctx.ui);
    },
  });

  pi.registerCommand("tor-cycle", {
    description: "Get a new Tor circuit (new IP)",
    handler: async (_args, ctx) => {
      if (!state.enabled) {
        ctx.ui.notify("Tor not enabled. Use /tor-start first.", "error");
        return;
      }

      ctx.ui.notify("Cycling Tor circuit...", "info");

      const oldIp = state.currentIp;
      let newIp: string | null = null;
      let success = false;

      for (let attempt = 1; attempt <= MAX_CYCLE_ATTEMPTS; attempt++) {
        success = await renewTorCircuit();
        if (stopRequested) {
          stopRequested = false;
          await stopTor();
          return;
        }
        if (!success) break;
        newIp = await waitForNewIp(oldIp, attempt === 1 ? CYCLE_FIRST_WAIT_MS : CYCLE_RETRY_WAIT_MS);
        if (!state.enabled) return;
        if (newIp && newIp !== oldIp) break;
        if (attempt < MAX_CYCLE_ATTEMPTS) await sleep(CYCLE_RETRY_DELAY_MS);
      }

      if (!success) {
        ctx.ui.notify("Failed to cycle Tor circuit", "error");
        return;
      }

      state.currentIp = newIp;

      if (newIp && newIp !== oldIp) {
        ctx.ui.notify(`New IP: ${newIp} (was: ${oldIp || "unknown"})`, "info");
      } else if (newIp) {
        ctx.ui.notify(`IP: ${newIp} (same as before, may need more time)`, "info");
      } else {
        ctx.ui.notify("Circuit cycled, but failed to get new IP", "info");
      }

      updateStatus(ctx.ui);
    },
  });

  // Monitor Tor process and auto-restart if it crashes
  function setupTorMonitor(torBin: string) {
    if (state.torProcess) {
      state.torProcess.on("close", async (code) => {
        if (state.enabled && !cycleInProgress && code !== 0 && restartAttempts < MAX_RESTART_ATTEMPTS) {
          restartAttempts++;
          console.log(`Tor exited with code ${code}, restarting (attempt ${restartAttempts})...`);
          state.torProcess = null;
          await sleep(2000);
          await startTor(torBin);
        }
      });
    }
  }

  pi.on("session_start", async (_event, ctx) => {
    const shouldEnable = state.enabled || readPersistedEnabled();
    state.enabled = shouldEnable;

    if (shouldEnable) {
      let listening = await isTorListening();
      if (!listening) {
        const torBin = findTorBinary();
        if (torBin) listening = (await startTor(torBin)) === null;
      }
      if (listening) {
        if (!envIsSet()) setProxyEnv();
        state.torPid = readTorPid();
        const ip = await getTorIp();
        state.currentIp = ip;
        if (stopRequested) {
          stopRequested = false;
          state.enabled = false;
          persistEnabled(false);
          if (envIsSet()) clearProxyEnv();
        }
      }
    } else {
      if (envIsSet()) clearProxyEnv();
    }
    writeLease();
    await maybeKillTor();
    heartbeat.start();

    updateStatus(ctx.ui);
    statusUi = ctx.ui;
    if (state.enabled) {
      ipPolling.start();
      const ipMsg = state.currentIp ? ` (IP: ${state.currentIp})` : "";
      ctx.ui.notify(`Tor active${ipMsg}`, "info");
    }
  });

  pi.on("turn_start", async () => {
    await syncEnvToMarker();
  });

  pi.on("session_shutdown", async () => {
    if (envIsSet()) clearProxyEnv();
    writeLease();
    await maybeKillTor();
    ipPolling.stop();
    heartbeat.stop();
    statusUi = null;
  });
}
