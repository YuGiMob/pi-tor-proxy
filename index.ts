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

import type { ExtensionAPI, ExtensionCommandContext, ExtensionContext, ExtensionUIContext } from "@earendil-works/pi-coding-agent";
import { spawn, execFileSync, type ChildProcess } from "node:child_process";
import { createHash, randomUUID } from "node:crypto";
import { chmodSync, createReadStream, createWriteStream, existsSync, mkdirSync, readFileSync, readdirSync, renameSync, rmSync, statSync, writeFileSync } from "node:fs";
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
const TOR_SOCKS_AUTH_USER = `pi-${randomUUID().slice(0, 8)}`;
const TOR_SOCKS_AUTH_PASS = "x";
const TOR_SOCKS_PROXY = `socks5://${TOR_SOCKS_AUTH_USER}:${TOR_SOCKS_AUTH_PASS}@${TOR_SOCKS_HOST}:${TOR_SOCKS_PORT}`;
const TOR_SOCKS_PROXY_DNS = `socks5h://${TOR_SOCKS_AUTH_USER}:${TOR_SOCKS_AUTH_PASS}@${TOR_SOCKS_HOST}:${TOR_SOCKS_PORT}`;

/** Status key for footer display */
const STATUS_KEY = "tor";

/** Directory to store Tor binary */
const TOR_DIR = join(__dirname, ".tor");
const TOR_DATA_DIR = join(TOR_DIR, "data");
const TOR_STATE_FILE = join(TOR_DATA_DIR, "enabled");
const TOR_STARTING_FILE = join(TOR_DATA_DIR, "starting");
const LEASE_DIR = join(TOR_DIR, "leases");
const LEASE_TTL_MS = 90_000;
const STARTING_TTL_MS = 240_000;
const HEARTBEAT_MS = 30_000;
const MAX_CYCLE_ATTEMPTS = 3;
const CYCLE_FIRST_WAIT_MS = 35_000;
const CYCLE_RETRY_WAIT_MS = 20_000;
const CYCLE_RETRY_DELAY_MS = 10_000;
const NEWNYM_RATE_LIMIT_MS = 11_000;
const STARTUP_STALL_MS = 30_000;
const STARTUP_TIMEOUT_MS = 60_000;
const TOR_BUNDLE_SHA256: Record<string, string> = {
  "tor-expert-bundle-linux-x86_64-14.5.3.tar.gz": "34bac6a9cddfbd5cd8e74e546e00dcfa7aa988a19c3b5574ba7b52babe6c6e1a",
  "tor-expert-bundle-macos-x86_64-14.5.3.tar.gz": "28f1a7355abd17d3ad0cc0438caf0a5c563939115e6e22885ea470a8bda55a27",
  "tor-expert-bundle-macos-aarch64-14.5.3.tar.gz": "a57479977c07a270390b40bebff6a85f80de3007e0b637d63322e078f09c6ec9",
  "tor-expert-bundle-linux-aarch64-16.0a7.tar.gz": "1a51b37cc68f2df4d8952d3f343794f2f966c59d84fe580c56192377c00fcc1b",
};
const TOR_CONTROL_HOST = "127.0.0.1";
const TOR_CONTROL_PORT_FILE = join(TOR_DATA_DIR, "control.port");
const TOR_CONTROL_COOKIE_FILE = join(TOR_DATA_DIR, "control_auth_cookie");
const TOR_LOG_FILE = join(TOR_DATA_DIR, "tor.log");
const MAX_TOR_LOG_BYTES = 10 * 1024 * 1024;
const TOR_COUNTRY_FILE = join(TOR_DATA_DIR, "country");
const TOR_COUNTRY_CODES = new Set(
  "ad ae af ag ai al am an ao ap aq ar as at au aw ax az ba bb bd be bf bg bh bi bj bl bm bn bo bq br bs bt bv bw by bz ca cc cd cf cg ch ci ck cl cm cn co cr cs cu cv cw cx cy cz de dj dk dm do dz ec ee eg eh er es et eu fi fj fk fm fo fr ga gb gd ge gf gg gh gi gl gm gn gp gq gr gs gt gu gw gy hk hn hr ht hu id ie il im in io iq ir is it je jm jo jp ke kg kh ki km kn kp kr kw ky kz la lb lc li lk lr ls lt lu lv ly ma mc md me mf mg mh mk ml mm mn mo mp mq mr ms mt mu mv mw mx my mz na nc ne nf ng ni nl no np nr nu nz om pa pe pf pg ph pk pl pm pn pr ps pt pw py qa re ro rs ru rw sa sb sc sd se sg sh si sj sk sl sm sn so sr ss st sv sx sy sz tc td tf tg th tj tk tl tm tn to tr tt tv tw tz ua ug uk um us uy uz va vc ve vg vi vn vu wf ws ye yt za zm zw".split(" ")
);

const countryNameOverrides: Record<string, string> = {
  an: "Netherlands Antilles",
  ap: "Asia-Pacific",
  cs: "Serbia and Montenegro",
};
const regionDisplayNames = new Intl.DisplayNames(["en"], { type: "region" });
function countryName(cc: string): string {
  const overridden = countryNameOverrides[cc];
  if (overridden) return overridden;
  try {
    return regionDisplayNames.of(cc.toUpperCase()) ?? cc;
  } catch {
    return cc;
  }
}
function countryLabel(cc: string): string {
  return `{${cc}} (${countryName(cc)})`;
}
function countryCompletions(prefix: string): { value: string; label: string }[] | null {
  const query = prefix.trim().toLowerCase();
  const items = [...TOR_COUNTRY_CODES]
    .filter((cc) => cc.startsWith(query))
    .map((cc) => ({ value: cc, label: `${cc} — ${countryName(cc)}` }));
  if ("off".startsWith(query)) items.push({ value: "off", label: "off — clear the setting" });
  return items.length > 0 ? items : null;
}

/** Environment variable names to set when Tor is active */
const PROXY_ENV_VARS = [
  "HTTP_PROXY",
  "HTTPS_PROXY",
  "http_proxy",
  "https_proxy",
] as const;
const DNS_PROXY_ENV_VARS = ["ALL_PROXY", "all_proxy"] as const;
const NO_PROXY_VALUE = "127.0.0.1,localhost,::1";
const NO_PROXY_ENV_VARS = ["NO_PROXY", "no_proxy"] as const;
const ALL_PROXY_ENV_VARS = [...PROXY_ENV_VARS, ...DNS_PROXY_ENV_VARS, ...NO_PROXY_ENV_VARS] as const;

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
  function setProxyVar(v: string, value: string): void {
    if (!savedProxyEnv.has(v)) savedProxyEnv.set(v, process.env[v]);
    process.env[v] = value;
  }

  function setProxyEnv(): void {
    for (const v of PROXY_ENV_VARS) setProxyVar(v, TOR_SOCKS_PROXY);
    for (const v of DNS_PROXY_ENV_VARS) setProxyVar(v, TOR_SOCKS_PROXY_DNS);
    for (const v of NO_PROXY_ENV_VARS) setProxyVar(v, NO_PROXY_VALUE);
  }

  function clearProxyEnv(): void {
    for (const v of ALL_PROXY_ENV_VARS) {
      if (!savedProxyEnv.has(v)) continue;
      const original = savedProxyEnv.get(v);
      if (original === undefined) {
        delete process.env[v];
      } else {
        process.env[v] = original;
      }
      savedProxyEnv.delete(v);
    }
  }

  function writeFileBestEffort(path: string, content: string): boolean {
    try {
      mkdirSync(dirname(path), { recursive: true });
      writeFileSync(path, content);
      return true;
    } catch {
      return false;
    }
  }

  function readFileSafe(path: string): string | null {
    try {
      return readFileSync(path, "utf8");
    } catch {
      return null;
    }
  }

  function rotateTorLogIfLarge(): void {
    try {
      if (statSync(TOR_LOG_FILE).size < MAX_TOR_LOG_BYTES) return;
      rmSync(`${TOR_LOG_FILE}.1`, { force: true });
      renameSync(TOR_LOG_FILE, `${TOR_LOG_FILE}.1`);
    } catch {}
  }

  function persistEnabled(enabled: boolean): void {
    writeFileBestEffort(TOR_STATE_FILE, enabled ? "1" : "0");
  }

  function readPersistedEnabled(): boolean {
    return readFileSafe(TOR_STATE_FILE)?.trim() === "1";
  }

  let startingMarkerWritten = false;

  function writeStartingMarker(): void {
    startingMarkerWritten = writeFileBestEffort(TOR_STARTING_FILE, String(Date.now()));
  }

  function clearStartingMarker(): void {
    if (!startingMarkerWritten) return;
    startingMarkerWritten = false;
    try {
      rmSync(TOR_STARTING_FILE, { force: true });
    } catch {}
  }

  function startingInProgress(): boolean {
    const raw = readFileSafe(TOR_STARTING_FILE);
    if (!raw) return false;
    const written = Number(raw);
    return Number.isFinite(written) && Date.now() - written < STARTING_TTL_MS;
  }

  function envIsSet(): boolean {
    return process.env.HTTP_PROXY === TOR_SOCKS_PROXY;
  }

  interface CountryConfig {
    exitNodes: string | null;
    excludeExitNodes: string | null;
  }

  function readCountryConfig(): CountryConfig {
    const raw = readFileSafe(TOR_COUNTRY_FILE);
    if (!raw) return { exitNodes: null, excludeExitNodes: null };
    try {
      const parsed = JSON.parse(raw) as Partial<CountryConfig>;
      return {
        exitNodes: typeof parsed.exitNodes === "string" ? parsed.exitNodes : null,
        excludeExitNodes: typeof parsed.excludeExitNodes === "string" ? parsed.excludeExitNodes : null,
      };
    } catch {
      return { exitNodes: null, excludeExitNodes: null };
    }
  }

  function writeCountryConfig(config: CountryConfig): void {
    writeFileBestEffort(TOR_COUNTRY_FILE, JSON.stringify(config));
  }

  function countrySpawnArgs(config: CountryConfig): string[] {
    const args: string[] = [];
    if (config.exitNodes) args.push("--ExitNodes", `{${config.exitNodes}}`, "--StrictNodes", "1");
    if (config.excludeExitNodes) args.push("--ExcludeExitNodes", `{${config.excludeExitNodes}}`);
    return args;
  }

  function countrySummary(): string {
    const country = readCountryConfig();
    const parts: string[] = [];
    if (country.exitNodes) parts.push(`exit {${country.exitNodes}}`);
    if (country.excludeExitNodes) parts.push(`exclude {${country.excludeExitNodes}}`);
    return parts.length > 0 ? `\nCountries: ${parts.join(", ")}` : "";
  }

  interface InstanceLease {
    pid: number;
    envSet: boolean;
    updatedAt: number;
  }

  function readLeaseFile(name: string): InstanceLease | null {
    try {
      const lease = JSON.parse(readFileSync(join(LEASE_DIR, name), "utf8")) as InstanceLease;
      if (lease && typeof lease.pid === "number" && typeof lease.envSet === "boolean" && typeof lease.updatedAt === "number") return lease;
    } catch {}
    return null;
  }

  function writeLease(): void {
    try {
      mkdirSync(LEASE_DIR, { recursive: true });
      const now = Date.now();
      for (const file of readdirSync(LEASE_DIR)) {
        if (!file.endsWith(".json") || file === `${process.pid}.json`) continue;
        try {
          const raw = JSON.parse(readFileSync(join(LEASE_DIR, file), "utf8")) as { updatedAt?: unknown };
          if (typeof raw?.updatedAt === "number" && now - raw.updatedAt >= LEASE_TTL_MS) {
            rmSync(join(LEASE_DIR, file), { force: true });
          }
        } catch {}
      }
      writeFileSync(
        join(LEASE_DIR, `${process.pid}.json`),
        JSON.stringify({ pid: process.pid, envSet: envIsSet(), updatedAt: now })
      );
    } catch {}
  }

  function readLeases(): InstanceLease[] {
    const leases: InstanceLease[] = [];
    try {
      for (const file of readdirSync(LEASE_DIR)) {
        if (!file.endsWith(".json")) continue;
        const lease = readLeaseFile(file);
        if (lease) leases.push(lease);
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
    if (cycleInProgress) return;
    if (!(await isTorListening())) return;
    if (anyLiveInstanceNeedsTor()) return;
    await killTorProcess();
  }

  let startFailureReported = false;

  async function syncEnvToMarker(): Promise<void> {
    const enabled = readPersistedEnabled();
    state.enabled = enabled;
    const startFailure = enabled ? await ensureTorRunning() : null;
    if (enabled && startFailure === null) {
      if (!envIsSet()) setProxyEnv();
      startFailureReported = false;
    } else if (!enabled && envIsSet()) {
      clearProxyEnv();
    } else if (startFailure !== null && !startFailureReported) {
      state.enabled = false;
      startFailureReported = true;
      statusUi?.notify(startFailure, "error");
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
    let running = false;
    return {
      start() {
        if (timer) return;
        timer = setInterval(async () => {
          if (running) return;
          running = true;
          try {
            await fn();
          } catch (err) {
            console.error("Interval error:", err);
          }
          running = false;
        }, ms);
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
    if (!state.enabled) return;
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
  function removePartialDescriptorCache(): void {
    try {
      rmSync(join(TOR_DATA_DIR, "cached-microdescs.new"), { force: true });
    } catch {}
  }

  function prepareTorStart(): void {
    const country = readCountryConfig();
    if (!country.exitNodes && !country.excludeExitNodes) return;
    removePartialDescriptorCache();
  }

  function clearDescriptorCache(): void {
    for (const name of ["cached-microdescs.new", "cached-microdescs", "cached-microdesc-consensus", "cached-certs"]) {
      try {
        rmSync(join(TOR_DATA_DIR, name), { force: true });
      } catch {}
    }
  }

  function startTor(torBin: string): Promise<string | null> {
    if (startPromise) return startPromise;
    const promise = new Promise<string | null>((resolve) => {
      let child: ChildProcess;
      try {
        mkdirSync(TOR_DATA_DIR, { recursive: true });
        rotateTorLogIfLarge();
        prepareTorStart();
        const torDir = dirname(torBin);

        child = spawn(torBin, [
          "--SocksPort", `${TOR_SOCKS_HOST}:${TOR_SOCKS_PORT}`,
          "--ControlPort", "auto",
          "--ControlPortWriteToFile", TOR_CONTROL_PORT_FILE,
          "--CookieAuthentication", "1",
          "--DataDirectory", TOR_DATA_DIR,
          "--GeoIPFile", join(TOR_DATA_DIR, "geoip"),
          "--GeoIPv6File", join(TOR_DATA_DIR, "geoip6"),
          "--PidFile", join(TOR_DATA_DIR, "tor.pid"),
          "--Log", "notice stdout",
          "--Log", `notice file ${TOR_LOG_FILE}`,
          "--DisableDebuggerAttachment", "1",
          ...countrySpawnArgs(readCountryConfig()),
        ], {
          stdio: ["ignore", "pipe", "pipe"],
          env: {
            ...process.env,
            LD_LIBRARY_PATH: process.env.LD_LIBRARY_PATH
              ? `${process.env.LD_LIBRARY_PATH}:${torDir}`
              : torDir,
          },
        });
      } catch (err) {
        resolve(`Failed to start Tor: ${err instanceof Error ? err.message : String(err)}`);
        return;
      }

      let resolved = false;
      let stdoutBuffer = "";
      let sawProgress = false;
      const startedAt = Date.now();
      const terminateAndResolve = (message: string): void => {
        if (resolved) return;
        resolved = true;
        clearInterval(watchdog);
        child.kill("SIGTERM");
        const deadline = Date.now() + 5000;
        const poll = setInterval(() => {
          if (child.exitCode !== null || Date.now() >= deadline) {
            clearInterval(poll);
            if (child.exitCode === null) child.kill("SIGKILL");
            resolve(message);
          }
        }, 250);
      };
      const watchdog = setInterval(() => {
        if (resolved) return;
        const elapsed = Date.now() - startedAt;
        if (elapsed >= STARTUP_TIMEOUT_MS) {
          terminateAndResolve("Tor startup timed out (60s)");
        } else if (!sawProgress && elapsed >= STARTUP_STALL_MS) {
          terminateAndResolve("Tor startup stalled (no bootstrap progress)");
        }
      }, 1000);

      child.stdout?.on("data", (data: Buffer) => {
        stdoutBuffer += data.toString();
        let newlineIdx: number;
        while ((newlineIdx = stdoutBuffer.indexOf("\n")) >= 0) {
          const line = stdoutBuffer.slice(0, newlineIdx).trim();
          stdoutBuffer = stdoutBuffer.slice(newlineIdx + 1);
          if (line.includes("Bootstrapped")) sawProgress = true;
          if (line.includes("Bootstrapped 100%") && !resolved) {
            resolved = true;
            clearInterval(watchdog);
            stdoutBuffer = "";
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
          clearInterval(watchdog);
          resolve(`Tor exited with code ${code}`);
        }
        if (state.torProcess === child) state.torProcess = null;
        if (state.torPid === child.pid) state.torPid = null;
      });

      child.on("error", (err) => {
        if (!resolved) {
          resolved = true;
          clearInterval(watchdog);
          resolve(`Failed to start Tor: ${err.message}`);
        }
      });
    }).finally(() => {
      startPromise = null;
    });
    startPromise = promise;
    return promise;
  }

  async function startTorWithRetry(torBin: string): Promise<string | null> {
    const failure = await startTor(torBin);
    if (!failure) return null;
    if (await isTorListening()) return null;
    statusUi?.notify("Tor startup failed; clearing stale cache and retrying...", "warning");
    clearDescriptorCache();
    const retry = await startTor(torBin);
    if (!retry) return null;
    return (await isTorListening()) ? null : retry;
  }

  async function startOrAdopt(torBin: string): Promise<string | null> {
    writeStartingMarker();
    return startTorWithRetry(torBin);
  }

  async function ensureTorRunning(): Promise<string | null> {
    if (await isTorListening()) return null;
    if (startingInProgress()) return null;
    const torBin = findTorBinary();
    if (!torBin) return "Tor binary not found";
    try {
      return await startOrAdopt(torBin);
    } finally {
      clearStartingMarker();
    }
  }

  /**
   * Stop Tor process
   */
  async function killTorProcess(): Promise<void> {
    const child = state.torProcess;
    const pid = state.torPid ?? readTorPid();
    state.torProcess = null;
    state.torPid = null;

    if (child) {
      child.kill("SIGTERM");
    } else if (pid) {
      try { process.kill(pid, "SIGTERM"); } catch {}
    } else {
      return;
    }

    for (let i = 0; i < 20; i++) {
      await sleep(250);
      const exited = child ? child.exitCode !== null : !(await isTorListening());
      if (exited) break;
    }

    if (child) {
      child.kill("SIGKILL");
    } else if (pid) {
      try { process.kill(pid, "SIGKILL"); } catch {}
    }
    removePartialDescriptorCache();
  }

  let curlMissingReported = false;

  function reportCurlMissing(): void {
    if (curlMissingReported) return;
    curlMissingReported = true;
    console.error("curl not found: Tor exit IP verification unavailable");
    statusUi?.notify("curl not found — cannot verify Tor exit IP", "error");
  }

  function curlThroughTor(url: string): Promise<string | null> {
    return new Promise((resolve) => {
      const child = spawn("curl", [
        "-s", "--max-time", "15",
        "--proxy", TOR_SOCKS_PROXY_DNS,
        url,
      ]);
      let output = "";
      child.stdout.on("data", (d: Buffer) => { output += d.toString(); });
      child.on("close", () => resolve(output.trim() || null));
      child.on("error", (err) => {
        if ((err as NodeJS.ErrnoException).code === "ENOENT") reportCurlMissing();
        resolve(null);
      });
    });
  }

  let leakReported = false;

  async function getTorIp(): Promise<string | null> {
    const check = await curlThroughTor("https://check.torproject.org/api/ip");
    if (!check) return curlThroughTor("https://api.ipify.org");
    let parsed: { IsTor?: unknown; IP?: unknown };
    try {
      parsed = JSON.parse(check) as { IsTor?: unknown; IP?: unknown };
    } catch {
      return null;
    }
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
    }
    return null;
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

  interface ControlResponse {
    code: number;
    message: string;
  }

  interface NewnymSignal {
    status: "ok" | "rate-limited" | "failed";
    waitMs: number;
  }

  async function controlRequest(commands: string[]): Promise<ControlResponse[]> {
    const port = readControlPort();
    if (!port) return [];
    const cookie = readControlCookie();
    if (!cookie) return [];

    return new Promise((resolve) => {
      const socket = new net.Socket();
      let buffer = "";
      let settled = false;
      let expected = 0;
      const responses: ControlResponse[] = [];
      let currentLines: string[] = [];
      let authResponseSkipped = false;

      const settle = (value: ControlResponse[]) => {
        if (settled) return;
        settled = true;
        socket.destroy();
        resolve(value);
      };

      socket.setTimeout(8000);
      for (const event of ["timeout", "error", "close"] as const) {
        socket.on(event, () => settle(responses));
      }

      socket.on("connect", () => {
        socket.write(`AUTHENTICATE ${cookie.toString("hex")}\r\n`);
        for (const cmd of commands) socket.write(`${cmd}\r\n`);
        socket.write("QUIT\r\n");
        expected = commands.length + 1;
      });

      socket.on("data", (chunk: Buffer) => {
        buffer += chunk.toString();
        let idx: number;
        while ((idx = buffer.indexOf("\r\n")) >= 0) {
          const line = buffer.slice(0, idx);
          buffer = buffer.slice(idx + 2);
          const match = line.match(/^(\d{3})([ -])(.*)$/);
          if (!match) {
            settle(responses);
            return;
          }
          const code = Number(match[1]);
          currentLines.push(match[3]);
          if (match[2] === " ") {
            const message = currentLines.join("\n");
            currentLines = [];
            if (!authResponseSkipped) {
              authResponseSkipped = true;
              if (code !== 250) {
                settle([]);
                return;
              }
              continue;
            }
            responses.push({ code, message });
            if (responses.length >= expected) {
              settle(responses);
              return;
            }
          }
        }
      });

      socket.connect(port, TOR_CONTROL_HOST);
    });
  }

  function parseNewnymWaitMs(message: string): number {
    const match = message.match(/Try again in (\d+) seconds/);
    const seconds = match ? Number(match[1]) : 0;
    return seconds > 0 ? seconds * 1000 : NEWNYM_RATE_LIMIT_MS;
  }

  async function signalNewnym(): Promise<NewnymSignal> {
    const responses = await controlRequest(["SIGNAL NEWNYM"]);
    const signal = responses[0];
    if (!signal) return { status: "failed", waitMs: 0 };
    if (signal.code === 250) return { status: "ok", waitMs: 0 };
    if (signal.code === 551) return { status: "rate-limited", waitMs: parseNewnymWaitMs(signal.message) };
    return { status: "failed", waitMs: 0 };
  }

  function controlSucceeded(responses: ControlResponse[], commandCount: number): boolean {
    if (responses.length < commandCount) return false;
    return responses.slice(0, commandCount).every((r) => r.code === 250);
  }

  async function applyCountryConfig(config: CountryConfig): Promise<boolean> {
    const commands: string[] = [];
    if (config.exitNodes) {
      commands.push(`SETCONF ExitNodes={${config.exitNodes}}`, "SETCONF StrictNodes=1");
    } else {
      commands.push("SETCONF ExitNodes=", "SETCONF StrictNodes=0");
    }
    if (config.excludeExitNodes) {
      commands.push(`SETCONF ExcludeExitNodes={${config.excludeExitNodes}}`);
    } else {
      commands.push("SETCONF ExcludeExitNodes=");
    }
    return controlSucceeded(await controlRequest(commands), commands.length);
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
    if (signal.status === "ok") return true;
    if (signal.status === "rate-limited") {
      await sleep(signal.waitMs);
      if ((await signalNewnym()).status === "ok") return true;
    }

    const torBin = findTorBinary();
    if (!torBin) return false;
    if (!state.torProcess && !state.torPid) return false;

    cycleInProgress = true;
    try {
      await killTorProcess();
      await sleep(1000);
      return (await startTorWithRetry(torBin)) === null;
    } finally {
      cycleInProgress = false;
    }
  }

  async function handleStopRequested(ctx: ExtensionContext): Promise<boolean> {
    if (!stopRequested) return false;
    stopRequested = false;
    await disableTor(ctx, true);
    return true;
  }

  async function enableTor(ctx: ExtensionCommandContext): Promise<void> {
    stopRequested = false;
    const listening = await isTorListening();
    if (!listening) {
      writeStartingMarker();
      let torBin = findTorBinary();
      if (!torBin) {
        torBin = await downloadTor(ctx.ui.notify);
      }
      if (!torBin) {
        clearStartingMarker();
        ctx.ui.notify("Failed to get Tor binary", "error");
        return;
      }

      ctx.ui.notify("Starting Tor...", "info");
      const wasEnabled = readPersistedEnabled();
      state.enabled = true;
      persistEnabled(true);
      const failure = await startOrAdopt(torBin);
      if (failure) {
        state.enabled = false;
        if (!wasEnabled) persistEnabled(false);
        clearStartingMarker();
        ctx.ui.notify(failure, "error");
        return;
      }
      if (!state.torProcess && !state.torPid) state.torPid = readTorPid();
      if (await handleStopRequested(ctx)) return;
    } else {
      state.torPid = readTorPid();
    }

    state.enabled = true;
    persistEnabled(true);
    clearStartingMarker();
    if (ctx.isIdle() && !envIsSet()) setProxyEnv();
    writeLease();

    const ip = await getTorIp();
    if (await handleStopRequested(ctx)) return;
    state.currentIp = ip;

    updateStatus(ctx.ui);
    statusUi = ctx.ui;
    ipPolling.start();
    const ipMsg = ip ? `\nIP: ${ip}` : "";
    const pending = pendingNote(ctx.isIdle());
    ctx.ui.notify(`Tor enabled.${ipMsg}${pending}`, "info");
  }

  async function disableTor(ctx: ExtensionContext, silent = false): Promise<void> {
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
    if (!silent) {
      const pending = pendingNote(ctx.isIdle());
      ctx.ui.notify(`Tor disabled.${pending}`, "info");
    }
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
        ctx.ui.notify(`Tor: DISABLED${countrySummary()}`, "info");
        updateStatus(ctx.ui);
        return;
      }

      const ip = await getTorIp();
      state.currentIp = ip;

      const pending = pendingNote(ctx.isIdle() || envIsSet());
      const ipStr = ip ? `\nIP: ${ip}` : "\nIP: unknown";
      const countryStr = countrySummary();
      ctx.ui.notify(`Tor: ENABLED\nProxy: ${TOR_SOCKS_PROXY}${ipStr}${countryStr}${pending}`, "info");
      updateStatus(ctx.ui);
    },
  });

  async function cycleCircuit(ctx: ExtensionCommandContext): Promise<void> {
    const oldIp = state.currentIp;
    let newIp: string | null = null;
    let success = false;

    for (let attempt = 1; attempt <= MAX_CYCLE_ATTEMPTS; attempt++) {
      success = await renewTorCircuit();
      if (await handleStopRequested(ctx)) return;
      if (!success) break;
      newIp = await waitForNewIp(oldIp, attempt === 1 ? CYCLE_FIRST_WAIT_MS : CYCLE_RETRY_WAIT_MS);
      if (!state.enabled) return;
      if (newIp && newIp !== oldIp) break;
      if (attempt < MAX_CYCLE_ATTEMPTS) await sleep(CYCLE_RETRY_DELAY_MS);
    }

    state.currentIp = newIp;

    if (!success) {
      ctx.ui.notify("Failed to cycle Tor circuit", "error");
    } else if (newIp && newIp !== oldIp) {
      ctx.ui.notify(`New IP: ${newIp} (was: ${oldIp || "unknown"})`, "info");
    } else if (newIp) {
      ctx.ui.notify(`IP: ${newIp} (same as before, may need more time)`, "info");
    } else {
      ctx.ui.notify("Circuit cycled, but failed to get new IP", "info");
    }

    updateStatus(ctx.ui);
  }

  interface ParsedCountryArg {
    missing: boolean;
    invalid: string | null;
    clear: boolean;
    cc: string | null;
  }

  function parseCountryArg(args: string): ParsedCountryArg {
    const value = args.trim().toLowerCase();
    if (value === "") return { missing: true, invalid: null, clear: false, cc: null };
    if (value === "off") return { missing: false, invalid: null, clear: true, cc: null };
    if (/^[a-z]{2}$/.test(value)) {
      if (TOR_COUNTRY_CODES.has(value)) return { missing: false, invalid: null, clear: false, cc: value };
      return { missing: false, invalid: value, clear: false, cc: null };
    }
    return { missing: false, invalid: value, clear: false, cc: null };
  }

  async function setCountry(
    ctx: ExtensionCommandContext,
    field: "exitNodes" | "excludeExitNodes",
    label: string,
    args: string
  ): Promise<void> {
    const parsed = parseCountryArg(args);
    const config = readCountryConfig();
    const what = label === "exclude" ? "Excluded country" : "Exit country";
    const setting = parsed.cc ? `set to ${countryLabel(parsed.cc)}` : "cleared";

    if (parsed.missing) {
      const current = config[field];
      ctx.ui.notify(`Usage: /tor-${label} <cc|off>\nCurrent: ${current ? `{${current}}` : "none"}`, "info");
      return;
    }
    if (parsed.invalid) {
      ctx.ui.notify(`Invalid country code "${parsed.invalid}". Use a 2-letter ISO 3166-1 code or "off".`, "error");
      return;
    }

    config[field] = parsed.clear ? null : parsed.cc;
    writeCountryConfig(config);

    if (!state.enabled) {
      ctx.ui.notify(`${what} ${setting}. Applies when Tor starts.`, "info");
      return;
    }

    if (!(await applyCountryConfig(config))) {
      ctx.ui.notify(`${what} ${setting}, but the running Tor did not accept it.`, "error");
      return;
    }

    ctx.ui.notify(`${what} ${setting}. Cycling circuit...`, "info");
    await cycleCircuit(ctx);
  }

  pi.registerCommand("tor-cycle", {
    description: "Get a new Tor circuit (new IP)",
    handler: async (_args, ctx) => {
      if (!state.enabled) {
        ctx.ui.notify("Tor not enabled. Use /tor-start first.", "error");
        return;
      }
      ctx.ui.notify("Cycling Tor circuit...", "info");
      await cycleCircuit(ctx);
    },
  });

  pi.registerCommand("tor-country", {
    description: "Pin Tor exit nodes to a country (2-letter ISO code, e.g. us). Use 'off' to clear.",
    getArgumentCompletions: (prefix) => countryCompletions(prefix),
    handler: async (args, ctx) => {
      await setCountry(ctx, "exitNodes", "country", args);
    },
  });

  pi.registerCommand("tor-exclude", {
    description: "Never use Tor exit nodes in a country (2-letter ISO code, e.g. ru). Use 'off' to clear.",
    getArgumentCompletions: (prefix) => countryCompletions(prefix),
    handler: async (args, ctx) => {
      await setCountry(ctx, "excludeExitNodes", "exclude", args);
    },
  });

  function setupTorMonitor(torBin: string) {
    if (state.torProcess) {
      state.torProcess.on("close", async (code) => {
        if (state.enabled && !cycleInProgress && code !== 0 && restartAttempts < MAX_RESTART_ATTEMPTS) {
          restartAttempts++;
          console.log(`Tor exited with code ${code}, restarting (attempt ${restartAttempts})...`);
          state.torProcess = null;
          await sleep(2000);
          if (!state.enabled || cycleInProgress) return;
          await startTorWithRetry(torBin);
        }
      });
    }
  }

  pi.on("session_start", async (_event, ctx) => {
    const shouldEnable = state.enabled || readPersistedEnabled();
    state.enabled = shouldEnable;

    if (shouldEnable) {
      const startFailure = await ensureTorRunning();
      if (startFailure === null) {
        if (!envIsSet()) setProxyEnv();
        startFailureReported = false;
        state.torPid = readTorPid();
        const ip = await getTorIp();
        state.currentIp = ip;
        await handleStopRequested(ctx);
      } else {
        state.enabled = false;
        startFailureReported = true;
        ctx.ui.notify(startFailure, "error");
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
