# Passkey Bridge

Use an existing phone passkey to sign in in a trusted remote Chrome session. A macOS companion performs the real FIDO hybrid transaction locally, where Bluetooth is available. The remote Linux machine does not need a Bluetooth adapter.

**Experimental, sign-in only.** Automated checks exercise protocol validation, real bridge sockets/stdio, cryptographic primitives, extension behavior and macOS imports. They do not prove Microsoft Authenticator compatibility or a successful Azure login. That final acceptance requires your Mac and phone. Registration and unsupported extensions are rejected.

## How it works

Remote Chrome's official `webAuthenticationProxy` API forwards the request to a loopback broker. An SSH stdio channel connects the broker to your Mac. The Mac checks the source origin/RP ID, requests local consent, displays a FIDO QR code and receives the phone's Bluetooth advertisement. The actual CTAP request travels through the standard hybrid TLS/Noise tunnel to the phone. The assertion and its matching clientDataJSON return to the original browser session.

Private passkey material remains on the phone. Existing Microsoft authentication-strength, device-compliance and Conditional Access policies remain effective. This software does not export passkeys or provide automatic phone approval.

The Mac is the hybrid client physically near the phone. The remote server is an explicitly trusted requester; this does not prove that the remote server is near the phone.

## Requirements

macOS with working Bluetooth Low Energy; Python 3.11+; an existing phone passkey; internet access on Mac and phone. Grant the normal macOS Bluetooth permission to the terminal/Python process when prompted. Do not disable platform protections. Microsoft currently documents Authenticator passkeys on Android 14+ and iOS 17+.

The remote host needs Python 3.11+, Chrome 115+ and SSH access. Its SSH host key must already be verified in the Mac's known_hosts; the bridge deliberately refuses unknown/changed host keys. It does not install a daemon or open a public listener.

## Install

Clone this repository on both machines, then install into the current user's tools:

```sh
git clone https://github.com/freQuensy23-coder/passkey-bridge.git
cd passkey-bridge
uv tool install .
```

`uv` is available at https://docs.astral.sh/uv/getting-started/installation/. Alternatively create a virtual environment and install with pip; the SSH relay command expects the executable at `~/.local/bin/passkey-bridge`, as produced by a normal uv tool installation. Keep that location available on the remote host.

## Connect

Install the remote browser extension as described below and copy its ID from chrome://extensions. On the remote host:

```sh
passkey-bridge serve --extension-id EXTENSION_ID
```

The command prints a loopback port, an extension token and a separate one-use companion pairing code. Pairing expires after ten minutes; the whole session ends after fifteen minutes by default. Session credentials exist only in memory/output, not in project files. Do not post codes or QR data publicly.

In the **remote** browser, open `chrome://extensions`, enable Developer mode and use **Load unpacked** with the directory printed by:

```sh
passkey-bridge extension-path
```

This grants an extension permission, not an account security-policy change. If extension installation is prohibited by your existing browser policy, stop there rather than changing that policy. Official branded Chrome 137+ no longer accepts `--load-extension` for command-line loading; use the extension UI or Chrome for Testing for automation. Do not reset an existing browser profile.

Open the extension's options, enter the printed port and **extension** token, and connect. On your Mac run the printed command, replacing SSH_HOST with your existing verified SSH alias or user@hostname:

```sh
passkey-bridge connect SSH_HOST --port PORT
```

Paste the **companion** pairing code at its hidden prompt. It travels to the server through SSH stdin, not a remote command argument. The optional --code argument is available for controlled one-shot use, but exposes that short-lived code to local process arguments and shell history; the hidden prompt is the default. Keep the Mac terminal open. Use --remote-executable /absolute/path/passkey-bridge if the remote installation is not at ~/.local/bin/passkey-bridge.

Start Microsoft sign-in in the remote browser and select the passkey method. The Mac shows the exact requesting origin and RP ID and asks permission. After approval, scan the Mac's QR code with the phone and complete the phone's normal user verification. For iOS use the system Camera; Microsoft's iOS Authenticator camera does not scan this WebAuthn QR format. No permanent Bluetooth pairing is required.

Disconnect in extension options or stop the terminal command to end the session. Canceling a browser request terminates its local authenticator subprocess, including its prompt, BLE scanner and network connection.

## Boundaries

Microsoft login origins are explicitly allowlisted by the companion. Requests must carry the real browser's remoteDesktopClientOverride with same-origin ancestors. Public-suffix-aware RP validation, bounded challenges, canonical base64url, supported extensions, matching RP hashes/credential IDs and required authenticator flags are checked. Unknown account policies remain authoritative; the bridge cannot make an otherwise disallowed server/device compliant.

Only pair a server and browser you trust. A trusted remote server can request sign-in assertions; inspect the origin and RP on the Mac and the phone before approving. An assertion can authorize a login on that remote server. The broker binds only to 127.0.0.1, pins the explicitly selected extension ID, and requires different random 256-bit tokens for extension and companion. Possession of the server/user account or a privileged local process is outside that isolation boundary. The phone tunnel uses its normal provider endpoints, not a custom bridge-operated tunnel.

See [protocol sources](docs/PROTOCOL.md), [security boundaries](SECURITY.md), [third-party provenance](THIRD_PARTY.md) and [verification scope](docs/VERIFICATION.md).

## Development

```sh
uv sync --dev
uv run pytest -q
node --test tests/extension.test.mjs
uv build
```

CI runs automatically on pushes and pull requests on Linux and macOS, with Python 3.11 and 3.13. Do not publish live QR codes, pairing tokens, assertions, browser profiles or account screenshots as test evidence.
