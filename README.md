# pi-tor-proxy

A [pi-coding-agent](https://github.com/badlogic/pi-mono/tree/main/packages/coding-agent) extension that routes all requests through the Tor network. **Self-contained** - automatically downloads and manages a Tor binary with no system installation required.

When Tor mode is active:
- **Environment variables** (`HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY`) are set for HTTP/HTTPS requests
- **Status indicator** shows in the footer with your current exit IP: `🔒 Tor (IP: x.x.x.x)`
- **Zero dependencies** - uses only Node.js built-ins and downloads Tor directly from the Tor Project

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

## How It Works

1. First time you run `/tor-start`, it downloads the Tor expert bundle (~30MB) from `archive.torproject.org`
2. Tor binary is stored in the extension's `.tor/` directory
3. Starts Tor and waits for it to bootstrap (typically 10-15 seconds)
4. Sets proxy environment variables that most HTTP clients respect
5. Shows `🔒 Tor (IP: x.x.x.x)` in footer when active

### Environment Variables

When Tor mode is active, the extension sets:
- `HTTP_PROXY=socks5h://127.0.0.1:9050`
- `HTTPS_PROXY=socks5h://127.0.0.1:9050`
- `ALL_PROXY=socks5h://127.0.0.1:9050`
- (lowercase variants also set)

The `socks5h://` scheme means DNS requests are also routed through Tor.

### Getting a New IP

Use `/tor-cycle` to get a fresh Tor circuit with a new exit node. This restarts the Tor process to establish new circuits.

## Supported Platforms

| Platform | Architecture | Status |
|----------|--------------|--------|
| Linux | x86_64 (amd64) | ✅ Supported |
| Linux | aarch64 (arm64) | ✅ Supported |
| macOS | x86_64 (Intel) | ✅ Supported |
| macOS | arm64 (Apple Silicon) | ✅ Supported |
| Windows | any | ❌ Not supported |
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

- [The Tor Project](https://www.torproject.org/) - for the Tor software
- [pi-coding-agent](https://github.com/badlogic/pi-mono/tree/main/packages/coding-agent) - for the extension API

## License

[MIT](LICENSE)
