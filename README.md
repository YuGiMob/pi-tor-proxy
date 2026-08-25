# pi-tor-proxy

A [pi-coding-agent](https://github.com/badlogic/pi-mono/tree/main/packages/coding-agent) extension that routes pi agent requests through the Tor network. It downloads and manages its own Tor binary, so nothing has to be installed on the system.

> Note: This extension only routes requests made by the pi agent (HTTP calls, tool executions, etc.) through Tor. It does not affect other applications or system-wide traffic on your machine.

When Tor mode is active:
- `HTTP_PROXY`, `HTTPS_PROXY`, and `ALL_PROXY` (plus lowercase variants) are set for HTTP/HTTPS requests; each pi instance authenticates to the SOCKS port with its own random username, so Tor gives every instance its own circuit and exit IP
- The footer shows your current exit IP: `🔒 Tor (IP: x.x.x.x)`, verified against `check.torproject.org` so a misconfigured proxy can't silently leak your real IP
- The extension has no runtime dependencies: it uses only Node.js built-ins and downloads Tor from the Tor Project

## Installation

From npm:

```bash
pi install npm:pi-tor-proxy
```

From a local checkout:

```bash
pi install /path/to/pi-tor-proxy
```

## Commands

| Command | Description |
|---------|-------------|
| `/tor-start` | Enable Tor mode (downloads Tor on first run) |
| `/tor-stop` | Disable Tor mode |
| `/tor-status` | Show Tor status and current exit IP |
| `/tor-cycle` | Get a new Tor circuit (new IP address) |

## How it works

1. The first `/tor-start` downloads the Tor expert bundle (~30MB) from `archive.torproject.org` and verifies its SHA-256 checksum against a pinned digest
2. The binary is stored in the extension's `.tor/` directory
3. The extension starts Tor and waits for it to finish bootstrapping (typically 10-15 seconds)
4. It sets proxy environment variables that most HTTP clients respect
5. The footer shows `🔒 Tor (IP: x.x.x.x)` when active

### Environment variables

When Tor mode is active, the extension sets:
- `HTTP_PROXY=socks5://pi-<id>:x@127.0.0.1:9050`
- `HTTPS_PROXY=socks5://pi-<id>:x@127.0.0.1:9050`
- `ALL_PROXY=socks5h://pi-<id>:x@127.0.0.1:9050`
- lowercase variants as well

`<id>` is a random identifier generated per pi instance. Tor's `IsolateSOCKSAuth` (on by default) never shares circuits between streams with different SOCKS authentication, so each pi instance gets its own circuit and exit IP. `/tor-cycle` sends a global NEWNYM signal that refreshes all circuits, so other instances are re-routed too — each onto its own separate circuit.

The `HTTP(S)_PROXY` values use `socks5://` because undici — the HTTP client used by pi and by Node-based tools — only recognizes that scheme; it forwards hostnames to the proxy, so DNS is still resolved through Tor. The `ALL_PROXY` values keep the `socks5h://` scheme so tools that fall back to `ALL_PROXY` also resolve DNS through Tor. Note that curl-family tools prefer the protocol-specific `HTTP(S)_PROXY` values, and those resolve DNS locally.

The variables take effect in the pi process's environment, so subprocesses spawned while Tor mode is active — tool executions, shell commands, Node scripts — are routed through Tor. pi's own in-process HTTP client reads proxy variables once at startup, so it is only routed when the variables were already set before pi was launched.

### Getting a new IP

`/tor-cycle` signals the running Tor to build a fresh circuit over its control port (falling back to a restart if the control port is unavailable). If the exit IP doesn't change, it automatically retries — Tor rate-limits NEWNYM to one effective signal every ~10 seconds.

### Multiple pi instances

Tor mode is shared across pi instances using the same extension installation: the desired state is stored in `.tor/data/enabled`, and each instance applies it to its own environment at turn boundaries. Stopping Tor in one instance lets the other instances finish their current turn through Tor before switching off; starting it takes effect from the next turn. The shared Tor process is only stopped once no instance is actively routing through it. Each instance authenticates with its own random SOCKS username, so their traffic travels over separate circuits with separate exit IPs.

## Supported platforms

| Platform | Architecture | Status |
|----------|--------------|--------|
| Linux | x86_64 (amd64) | Supported |
| Linux | aarch64 (arm64) | Supported |
| macOS | x86_64 (Intel) | Supported |
| macOS | arm64 (Apple Silicon) | Supported |
| Windows | any | Not supported |

## Development

```bash
cd pi-tor-proxy
npm install
```

Test with:

```bash
pi -e ./index.ts
```

## Credits

- [The Tor Project](https://www.torproject.org/) for the Tor software
- [pi-coding-agent](https://github.com/badlogic/pi-mono/tree/main/packages/coding-agent) for the extension API

## License

[MIT](LICENSE)
