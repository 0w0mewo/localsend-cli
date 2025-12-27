## LocalSend for KOReader

A KOReader plugin that enables receiving files from other devices using the [LocalSend](https://localsend.org/) protocol. Send ebooks, documents, and other files directly to your e-reader from any device running LocalSend.

**[Download latest release](https://github.com/kaikozlov/localsend.koplugin/releases/latest)**

### Features

- **Receive files wirelessly** - Accept files from phones, tablets, and computers running LocalSend
- **File type filtering** - Accept only specific file types (epub, pdf, mobi, etc.) or allow all
- **PIN protection** - Optionally require a PIN code for incoming transfers
- **HTTPS support** - Secure file transfers with TLS encryption
- **Auto-start** - Optionally start the server automatically when KOReader launches
- **Transfer notifications** - Get notified when files are received
- **Custom device name** - Set a recognizable name for your device on the network

### Installation

1. Download the latest release for your device's architecture:
   - **armv7** - 32-bit ARM (e.g., Kindle Paperwhite 12)
   - **arm64** - 64-bit ARM
2. Extract `localsend.koplugin` to your KOReader plugins directory:
   - Kindle: `/mnt/us/koreader/plugins/`
   - Kobo: `/.adds/koreader/plugins/`
   - Other devices: Check your KOReader installation path
3. Restart KOReader

### Usage

1. Open KOReader and go to **Menu > Network > LocalSend**
2. Configure your settings:
   - **Save directory** - Where received files will be stored
   - **Device name** - How your device appears to senders (leave empty for random name)
   - **Allowed extensions** - Filter incoming files by type
   - **PIN code** - Optional security for transfers
3. Tap **Start server** to begin receiving files
4. On your phone/computer, open LocalSend and send files to your e-reader

### Settings

| Setting             | Description                                     |
| ------------------- | ----------------------------------------------- |
| Save directory      | Destination folder for received files           |
| Device name         | Display name on the network (e.g., "My Kindle") |
| Allowed extensions  | Comma-separated list of accepted file types     |
| PIN code            | Required PIN for incoming transfers (optional)  |
| Use HTTPS           | Enable TLS encryption (recommended)             |
| Start with KOReader | Auto-start server on launch                     |

### How It Works

This plugin uses a lightweight LocalSend CLI implementation as its backend. The CLI handles the LocalSend v2 protocol including:

- Multicast UDP device discovery
- HTTPS/HTTP file transfer server
- Certificate generation and management

The KOReader frontend provides the user interface, settings management, and integrates with KOReader's file browser and notification system.

### Building the Backend

The backend CLI is written in Go. To build for ARM devices:

```bash
# Full build (compile Go + package into release zips)
./arm_build.sh

# Package only (skip Go compilation, reuse existing binaries)
# Useful when you've only changed Lua code
./arm_build.sh --package
```

Or build manually:

```bash
# armv7 (32-bit)
GOOS=linux GOARCH=arm GOARM=7 CGO_ENABLED=0 go build -ldflags="-s -w" -o localsend

# arm64 (64-bit)
GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -ldflags="-s -w" -o localsend
```

### Compatibility

Tested on Kindle Paperwhite 12 (armv7). Should work on other devices supported by KOReader - just download the correct architecture (armv7 or arm64) for your device.

### Which architecture do I need?

| Architecture | Devices                                                                |
| ------------ | ---------------------------------------------------------------------- |
| **armv7**    | Kindle (firmware ≥5.16.3), Kobo (all models), reMarkable 2, PocketBook |
| **arm64**    | reMarkable Paper Pro                                                   |

> **Kindle users:** This plugin requires firmware 5.16.3 or newer (the same requirement as KOReader's `kindlehf` package). Older firmware uses a different floating-point ABI that isn't supported.

**Not sure?** Try armv7 first.

_Reported_ to work on:

armv7 devices:

- Kindle Paperwhite 12th Gen (PW6)
- Kindle Paperwhite 10th Gen (PW4)
- Kindle Oasis
- Kobo Clara Colour

### License

MIT License
