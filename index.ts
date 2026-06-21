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

import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";
import { spawn, type ChildProcess } from "node:child_process";
import { existsSync, mkdirSync, chmodSync } from "node:fs";
import net from "node:net";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { createWriteStream } from "node:fs";
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

/** Environment variable names to set when Tor is active */
const PROXY_ENV_VARS = [
  "HTTP_PROXY",
  "HTTPS_PROXY",
  "http_proxy",
  "https_proxy",
  "ALL_PROXY",
  "all_proxy",
] as const;

interface TorState {
  enabled: boolean;
  torProcess: ChildProcess | null;
  bootstrapped: boolean;
  currentIp: string | null;
}

export default function (pi: ExtensionAPI) {
  const state: TorState = {
    enabled: false,
    torProcess: null,
    bootstrapped: false,
    currentIp: null,
  };

  function setProxyEnv(): void {
    for (const v of PROXY_ENV_VARS) {
      process.env[v] = TOR_SOCKS_PROXY;
    }
  }

  function clearProxyEnv(): void {
    for (const v of PROXY_ENV_VARS) {
      delete process.env[v];
    }
  }

  function updateStatus(ctx: { ui: { setStatus: (key: string, text: string) => void } }): void {
    if (state.enabled) {
      const ip = state.currentIp ? ` (${state.currentIp})` : "";
      ctx.ui.setStatus(STATUS_KEY, `🔒 Tor${ip}`);
    } else {
      ctx.ui.setStatus(STATUS_KEY, "");
    }
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

  /**
   * Download and extract Tor binary
   */
  async function downloadTor(
    notify: (msg: string, level: string) => void
  ): Promise<string | null> {
    const url = getTorDownloadUrl();
    if (!url) {
      notify(`Unsupported platform: ${process.platform}/${process.arch}`, "error");
      return null;
    }

    notify("Downloading Tor... (first time only, ~30MB)", "info");

    try {
      mkdirSync(TOR_DIR, { recursive: true });

      const response = await fetch(url);
      if (!response.ok) {
        throw new Error(`HTTP ${response.status}: ${response.statusText}`);
      }

      const tarPath = join(TOR_DIR, "tor.tar.gz");
      const fileStream = createWriteStream(tarPath);

      if (response.body) {
        await pipeline(Readable.fromWeb(response.body as any), fileStream);
      }

      notify("Extracting Tor...", "info");

      await new Promise<void>((resolve, reject) => {
        const child = spawn("tar", ["-xzf", tarPath, "-C", TOR_DIR]);
        child.on("close", (code) => {
          if (code === 0) resolve();
          else reject(new Error(`tar exited with code ${code}`));
        });
        child.on("error", reject);
      });

      const torBin = join(TOR_DIR, "tor", "tor");
      if (existsSync(torBin)) {
        chmodSync(torBin, 0o755);
        spawn("rm", [tarPath]);
        notify("Tor downloaded successfully!", "info");
        return torBin;
      }

      const debugBin = join(TOR_DIR, "debug", "tor");
      if (existsSync(debugBin)) {
        chmodSync(debugBin, 0o755);
        spawn("rm", [tarPath]);
        notify("Tor downloaded successfully!", "info");
        return debugBin;
      }

      notify("Tor binary not found after extraction", "error");
      return null;
    } catch (err) {
      notify(`Download failed: ${err instanceof Error ? err.message : String(err)}`, "error");
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

  /**
   * Start Tor process and wait for bootstrap
   */
  async function startTor(
    torBin: string,
    notify: (msg: string, level: string) => void
  ): Promise<boolean> {
    return new Promise((resolve) => {
      notify("Starting Tor...", "info");

      const dataDir = join(TOR_DIR, "data");
      mkdirSync(dataDir, { recursive: true });
      const torDir = dirname(torBin);

      const child = spawn(torBin, [
        "--SocksPort", `${TOR_SOCKS_HOST}:${TOR_SOCKS_PORT}`,
        "--DataDirectory", dataDir,
        "--Log", "notice stdout",
        "--DisableDebuggerAttachment", "0",
      ], {
        stdio: ["ignore", "pipe", "pipe"],
        env: {
          ...process.env,
          LD_LIBRARY_PATH: torDir,
        },
      });

      let resolved = false;
      const timeout = setTimeout(() => {
        if (!resolved) {
          resolved = true;
          child.kill();
          notify("Tor startup timed out (60s)", "error");
          resolve(false);
        }
      }, 60000);

      child.stdout?.on("data", (data: Buffer) => {
        const text = data.toString();
        if (text.includes("Bootstrapped 100%") && !resolved) {
          resolved = true;
          clearTimeout(timeout);
          state.torProcess = child;
          state.bootstrapped = true;
          resolve(true);
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
          notify(`Tor exited with code ${code}`, "error");
          resolve(false);
        }
        state.torProcess = null;
        state.bootstrapped = false;
      });

      child.on("error", (err) => {
        if (!resolved) {
          resolved = true;
          clearTimeout(timeout);
          notify(`Failed to start Tor: ${err.message}`, "error");
          resolve(false);
        }
      });
    });
  }

  /**
   * Stop Tor process
   */
  function stopTor(): void {
    if (state.torProcess) {
      state.torProcess.kill("SIGTERM");
      state.torProcess = null;
      state.bootstrapped = false;
      state.currentIp = null;
    }
  }

  /**
   * Get IP through Tor
   */
  async function getTorIp(): Promise<string | null> {
    return new Promise((resolve) => {
      const child = spawn("curl", [
        "-s", "--max-time", "15",
        "--proxy", TOR_SOCKS_PROXY,
        "https://api.ipify.org",
      ]);
      let output = "";
      child.stdout.on("data", (d: Buffer) => { output += d.toString(); });
      child.on("close", () => resolve(output.trim() || null));
      child.on("error", () => resolve(null));
    });
  }

  /**
   * Request new Tor circuit (new identity)
   */
  async function renewTorCircuit(): Promise<boolean> {
    if (state.torProcess) {
      const torBin = findTorBinary();
      if (!torBin) return false;

      state.torProcess.kill("SIGTERM");
      state.torProcess = null;
      state.bootstrapped = false;

      await new Promise(r => setTimeout(r, 1000));

      return startTor(torBin, () => {});
    }

    return false;
  }

  /**
   * Enable Tor mode
   */
  async function enableTor(ctx: {
    ui: {
      setStatus: (key: string, text: string) => void;
      notify: (msg: string, level: string) => void;
    };
  }): Promise<void> {
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

      const started = await startTor(torBin, ctx.ui.notify);
      if (!started) return;
    }

    state.enabled = true;
    setProxyEnv();

    const ip = await getTorIp();
    state.currentIp = ip;

    updateStatus(ctx);
    const ipMsg = ip ? `\nIP: ${ip}` : "";
    ctx.ui.notify(`Tor enabled${ipMsg}`, "info");
  }

  /**
   * Disable Tor mode
   */
  function disableTor(ctx: {
    ui: {
      setStatus: (key: string, text: string) => void;
      notify: (msg: string, level: string) => void;
    };
  }): void {
    state.enabled = false;
    state.currentIp = null;
    clearProxyEnv();
    stopTor();
    updateStatus(ctx);
    ctx.ui.notify("Tor disabled.", "info");
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
      disableTor(ctx);
    },
  });

  pi.registerCommand("tor-status", {
    description: "Show Tor status and current IP",
    handler: async (_args, ctx) => {
      if (!state.enabled) {
        ctx.ui.notify("Tor: DISABLED", "info");
        return;
      }

      const ip = await getTorIp();
      state.currentIp = ip;

      const ipStr = ip ? `\nIP: ${ip}` : "\nIP: unknown";
      ctx.ui.notify(`Tor: ENABLED\nProxy: ${TOR_SOCKS_PROXY}${ipStr}`, "info");
      updateStatus(ctx);
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
      const success = await renewTorCircuit();

      if (!success) {
        ctx.ui.notify("Failed to cycle Tor circuit", "error");
        return;
      }

      await new Promise(r => setTimeout(r, 3000));

      const newIp = await getTorIp();
      state.currentIp = newIp;

      if (newIp && newIp !== oldIp) {
        ctx.ui.notify(`New IP: ${newIp} (was: ${oldIp || "unknown"})`, "info");
      } else if (newIp) {
        ctx.ui.notify(`IP: ${newIp} (same as before, may need more time)`, "info");
      } else {
        ctx.ui.notify("Circuit cycled, but failed to get new IP", "info");
      }

      updateStatus(ctx);
    },
  });

  // Restore state on session start
  pi.on("session_start", async (_event, ctx) => {
    if (process.env["HTTP_PROXY"] === TOR_SOCKS_PROXY) {
      const listening = await isTorListening();
      if (listening) {
        state.enabled = true;
        const ip = await getTorIp();
        state.currentIp = ip;
      }
    }
    updateStatus(ctx);
    if (state.enabled) {
      const ipMsg = state.currentIp ? ` (IP: ${state.currentIp})` : "";
      ctx.ui.notify(`Tor active${ipMsg}`, "info");
    }
  });

  // Cleanup
  pi.on("session_shutdown", async () => {
    clearProxyEnv();
    stopTor();
  });
}
