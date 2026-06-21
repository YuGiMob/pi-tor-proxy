# pi-tor-proxy

**Self-contained** Pi extension that routes all requests through Tor. No system installation required - Tor is downloaded automatically on first use.

## Installation

```bash
pi install /path/to/pi-tor-proxy
```

## Commands

| Command | Description |
|---------|-------------|
| `/tor-start` | Enable Tor mode (downloads on first run) |
| `/tor-stop` | Disable Tor mode |
| `/tor-status` | Show Tor status and current IP |
| `/tor-cycle` | Get a new Tor circuit (new IP) |

## How It Works

1. First time you run `/tor-start`, it downloads the Tor expert bundle (~30MB)
2. Tor binary is stored in the extension's `.tor/` directory
3. Starts Tor and waits for it to bootstrap
4. Sets proxy environment variables for all HTTP requests
5. Shows `🔒 Tor (IP: x.x.x.x)` in footer when active

No `sudo`, no `apt install`, no system changes required.

## Supported Platforms

- Linux x86_64
- Linux aarch64 (arm64)
- macOS x86_64 (Intel)
- macOS arm64 (Apple Silicon)

## Security Notes

- Tor provides anonymity, not encryption - use HTTPS for sensitive data
- DNS is routed through Tor via `socks5h://`
- Some services block Tor exit nodes

## License

[MIT](LICENSE)
