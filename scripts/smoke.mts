import type { ExtensionAPI, ExtensionCommandContext, ExtensionUIContext } from "@earendil-works/pi-coding-agent";
import net from "node:net";
import { existsSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import extension from "../index.ts";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const root = join(__dirname, "..");
const TOR_BIN = join(root, ".tor", "tor", "tor");
const TOR_STATE_FILE = join(root, ".tor", "data", "enabled");
const TOR_COUNTRY_FILE = join(root, ".tor", "data", "country");
const SOCKS_PORT = 9050;

interface Notification {
  message: string;
  type: string;
}

interface CommandDef {
  description?: string;
  handler: (args: string, ctx: ExtensionCommandContext) => Promise<void> | void;
}

type EventDef = (event: unknown, ctx: ExtensionCommandContext) => Promise<unknown> | unknown;

interface MockPi {
  commands: Map<string, CommandDef>;
  events: Map<string, EventDef>;
  api: unknown;
}

interface MockCtx {
  ctx: ExtensionCommandContext;
  notifications: Notification[];
}

function createMockPi(): MockPi {
  const commands = new Map<string, CommandDef>();
  const events = new Map<string, EventDef>();
  return {
    commands,
    events,
    api: {
      registerCommand(name: string, def: CommandDef) {
        commands.set(name, def);
      },
      on(event: string, handler: EventDef) {
        events.set(event, handler);
      },
    },
  };
}

function createMockCtx(): MockCtx {
  const notifications: Notification[] = [];
  const ui = {
    notify(message: string, type: "info" | "warning" | "error" = "info") {
      notifications.push({ message, type });
    },
    setStatus() {},
  } as unknown as ExtensionUIContext;
  const ctx = {
    ui,
    isIdle: () => true,
  } as unknown as ExtensionCommandContext;
  return { ctx, notifications };
}

function readFileSafe(path: string): string | null {
  try {
    return readFileSync(path, "utf8");
  } catch {
    return null;
  }
}

function writeFileBestEffort(path: string, content: string): void {
  try {
    writeFileSync(path, content);
  } catch {}
}

function removeFileBestEffort(path: string): void {
  try {
    rmSync(path, { force: true });
  } catch {}
}

function assert(condition: boolean, message: string): void {
  if (!condition) throw new Error(`SMOKE FAILED: ${message}`);
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function withTimeout<T>(promise: Promise<T>, ms: number, label: string): Promise<T> {
  return Promise.race([
    promise,
    new Promise<never>((_, reject) => {
      setTimeout(() => reject(new Error(`SMOKE FAILED: timed out after ${ms}ms waiting for ${label}`)), ms);
    }),
  ]);
}

function isListening(port: number): Promise<boolean> {
  return new Promise((resolve) => {
    const socket = new net.Socket();
    socket.setTimeout(1500);
    socket.on("connect", () => {
      socket.destroy();
      resolve(true);
    });
    socket.on("timeout", () => {
      socket.destroy();
      resolve(false);
    });
    socket.on("error", () => {
      socket.destroy();
      resolve(false);
    });
    socket.connect(port, "127.0.0.1");
  });
}

async function main(): Promise<void> {
  if (!existsSync(TOR_BIN)) {
    console.error(
      "SMOKE FAILED: Tor binary not found. Start the extension once in pi and run /tor-start so the bundle is downloaded, then retry."
    );
    return;
  }

  const priorEnabled = readFileSafe(TOR_STATE_FILE)?.trim() === "1";
  const priorCountry = readFileSafe(TOR_COUNTRY_FILE);
  const priorHttpProxy = process.env.HTTP_PROXY;
  const priorAllProxy = process.env.ALL_PROXY;
  const priorNoProxy = process.env.NO_PROXY;

  const mock = createMockPi();
  extension(mock.api as ExtensionAPI);
  const { ctx, notifications } = createMockCtx();

  const command = (name: string): CommandDef => {
    const def = mock.commands.get(name);
    assert(!!def, `command /${name} not registered`);
    return def!;
  };
  const event = (name: string): EventDef => {
    const handler = mock.events.get(name);
    assert(!!handler, `event ${name} not registered`);
    return handler!;
  };

  const unexpectedErrors = (): Notification[] =>
    notifications.filter((n) => n.type === "error" && !n.message.includes("curl"));

  try {
    console.log("Starting Tor via /tor-start...");
    await withTimeout(Promise.resolve(command("tor-start").handler("", ctx)), 120_000, "tor-start");
    assert(await isListening(SOCKS_PORT), "SOCKS port not listening after tor-start");
    assert(unexpectedErrors().length === 0, `tor-start errors: ${unexpectedErrors().map((n) => n.message).join(" | ")}`);

    const httpProxy = process.env.HTTP_PROXY ?? "";
    assert(httpProxy.startsWith("socks5://pi-") && httpProxy.endsWith("@127.0.0.1:9050"), `unexpected HTTP_PROXY: ${httpProxy}`);
    const allProxy = process.env.ALL_PROXY ?? "";
    assert(allProxy.startsWith("socks5h://pi-") && allProxy.endsWith("@127.0.0.1:9050"), `unexpected ALL_PROXY: ${allProxy}`);
    const noProxy = process.env.NO_PROXY ?? "";
    assert(
      noProxy.includes("127.0.0.1") && noProxy.includes("localhost") && noProxy.includes("::1"),
      `unexpected NO_PROXY: ${noProxy}`
    );
    assert(readFileSafe(TOR_STATE_FILE)?.trim() === "1", "enabled marker not persisted");
    const enabledNotify = notifications.find((n) => n.message.startsWith("Tor enabled"));
    assert(!!enabledNotify, "no 'Tor enabled' notification");
    const ip = enabledNotify!.message.match(/IP: (\S+)/)?.[1];
    console.log(`Tor enabled. Exit IP: ${ip ?? "unknown"}`);

    console.log("Checking turn_start sync...");
    notifications.length = 0;
    await withTimeout(Promise.resolve(event("turn_start")(undefined, ctx)), 30_000, "turn_start");
    assert(process.env.HTTP_PROXY === httpProxy, "turn_start dropped proxy env");
    assert(process.env.NO_PROXY === noProxy, "turn_start dropped NO_PROXY");

    console.log("Checking /tor-status...");
    notifications.length = 0;
    await withTimeout(Promise.resolve(command("tor-status").handler("", ctx)), 60_000, "tor-status");
    assert(notifications.some((n) => n.message.startsWith("Tor: ENABLED")), "tor-status did not report ENABLED");

    if (process.argv.includes("--cycle")) {
      console.log("Cycling circuit via /tor-cycle...");
      notifications.length = 0;
      await withTimeout(Promise.resolve(command("tor-cycle").handler("", ctx)), 180_000, "tor-cycle");
      assert(unexpectedErrors().length === 0, `tor-cycle errors: ${unexpectedErrors().map((n) => n.message).join(" | ")}`);
      console.log("Circuit cycled.");

      console.log("Setting exit country via /tor-country...");
      notifications.length = 0;
      await withTimeout(Promise.resolve(command("tor-country").handler("de", ctx)), 180_000, "tor-country de");
      assert(unexpectedErrors().length === 0, `tor-country errors: ${unexpectedErrors().map((n) => n.message).join(" | ")}`);
      notifications.length = 0;
      await withTimeout(Promise.resolve(command("tor-status").handler("", ctx)), 60_000, "tor-status after country");
      assert(notifications.some((n) => n.message.includes("exit {de}")), "tor-status does not show exit country");

      console.log("Excluding a country via /tor-exclude...");
      notifications.length = 0;
      await withTimeout(Promise.resolve(command("tor-exclude").handler("ru", ctx)), 180_000, "tor-exclude ru");
      assert(unexpectedErrors().length === 0, `tor-exclude errors: ${unexpectedErrors().map((n) => n.message).join(" | ")}`);
      notifications.length = 0;
      await withTimeout(Promise.resolve(command("tor-status").handler("", ctx)), 60_000, "tor-status after exclude");
      assert(notifications.some((n) => n.message.includes("exclude {ru}")), "tor-status does not show excluded country");

      console.log("Clearing country config...");
      await withTimeout(Promise.resolve(command("tor-country").handler("off", ctx)), 180_000, "tor-country off");
      await withTimeout(Promise.resolve(command("tor-exclude").handler("off", ctx)), 180_000, "tor-exclude off");
      assert(unexpectedErrors().length === 0, `country clear errors: ${unexpectedErrors().map((n) => n.message).join(" | ")}`);
      console.log("Country config cleared.");

      console.log("Checking stale cache recovery on pinned start...");
      writeFileBestEffort(TOR_COUNTRY_FILE, JSON.stringify({ exitNodes: "de", excludeExitNodes: null }));
      await withTimeout(Promise.resolve(command("tor-stop").handler("", ctx)), 60_000, "tor-stop before cache test");
      writeFileSync(join(root, ".tor", "data", "cached-microdescs.new"), "partial");
      await withTimeout(Promise.resolve(command("tor-start").handler("", ctx)), 120_000, "tor-start after cache poison");
      assert(await isListening(SOCKS_PORT), "SOCKS port not listening after cache-recovery start");
      writeFileBestEffort(TOR_COUNTRY_FILE, JSON.stringify({ exitNodes: null, excludeExitNodes: null }));
      await withTimeout(Promise.resolve(command("tor-country").handler("off", ctx)), 180_000, "tor-country off after cache test");
      assert(unexpectedErrors().length === 0, `cache-recovery errors: ${unexpectedErrors().map((n) => n.message).join(" | ")}`);
      console.log("Stale cache recovery OK.");
    }

    console.log("Stopping Tor via /tor-stop...");
    notifications.length = 0;
    await withTimeout(Promise.resolve(command("tor-stop").handler("", ctx)), 60_000, "tor-stop");
    assert(process.env.HTTP_PROXY === priorHttpProxy, "HTTP_PROXY not restored after tor-stop");
    assert(process.env.ALL_PROXY === priorAllProxy, "ALL_PROXY not restored after tor-stop");
    assert(process.env.NO_PROXY === priorNoProxy, "NO_PROXY not restored after tor-stop");
    assert(readFileSafe(TOR_STATE_FILE)?.trim() === "0", "enabled marker not cleared");

    await event("session_shutdown")(undefined, ctx);
    const deadline = Date.now() + 15_000;
    let stopped = false;
    while (Date.now() < deadline) {
      if (!(await isListening(SOCKS_PORT))) {
        stopped = true;
        break;
      }
      await sleep(500);
    }
    if (stopped) {
      console.log("Tor stopped.");
    } else {
      console.log("WARN: Tor still running (other pi instances may still need it).");
    }

    if (priorEnabled) {
      writeFileBestEffort(TOR_STATE_FILE, "1");
      console.log("NOTE: restored prior enabled state; Tor will start again on the next pi session.");
    }
    console.log("SMOKE PASSED");
  } finally {
    try {
      await command("tor-stop").handler("", ctx);
    } catch {}
    try {
      await event("session_shutdown")(undefined, ctx);
    } catch {}
    if (priorEnabled) writeFileBestEffort(TOR_STATE_FILE, "1");
    if (priorCountry === null) {
      removeFileBestEffort(TOR_COUNTRY_FILE);
    } else {
      writeFileBestEffort(TOR_COUNTRY_FILE, priorCountry);
    }
  }
}

main().then(
  () => {
    setTimeout(() => process.exit(process.exitCode ?? 0), 100);
  },
  (err: unknown) => {
    console.error(err instanceof Error ? err.message : String(err));
    process.exitCode = 1;
    setTimeout(() => process.exit(1), 100);
  }
);
