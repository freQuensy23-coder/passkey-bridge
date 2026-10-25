# Verification scope

## Executed on the development Linux host

The latest local implementation snapshot passed **159 Python tests, no skips**, with the dedicated Chrome for Testing integration enabled. Separately, the MV3 worker/options lifecycle suite passed **31 tests, no failures or skips**. These are software-fixture results; GitHub Actions is the authoritative record for the published commit.

[Automatic GitHub Actions for source revision 962f659](https://github.com/freQuensy23-coder/passkey-bridge/actions/runs/40219652594) passed on Linux and macOS with Python 3.11 and 3.13. Each matrix job passed 156 Python tests and 31 extension lifecycle tests, built the wheel/source distribution and checked packaged extension assets. The three browser cases are intentionally excluded from matrix jobs and all passed in the dedicated real-Chrome job. Both macOS jobs imported CoreBluetooth successfully; this is not hardware scanning evidence.

The real Chrome for Testing 156 integration loaded the actual unpacked extension, authenticated a real loopback broker, attached the real webAuthenticationProxy API, intercepted a page's navigator.credentials.get, preserved the browser-provided origin override, returned a real ECDSA-signed **software test fixture** assertion and detached. It uses an isolated disposable profile and a local test relying-party origin. It does not use a physical phone or sign in to Microsoft.

This integration exposed actual negative opaque Chrome request IDs; broker and companion regression tests now preserve those IDs exactly.

Backend tests exercise actual EID AES/HMAC authentication, P-256/Noise/AES-GCM roundtrips and tamper rejection, exact CTAP framing/client-data hashes, assertion checks, terminal consent, subprocess output isolation and SIGTERM cancellation cleanup. Tests explicitly named simulated replace the BLE scanner and provider TLS tunnel with in-process fixtures. They are not a claim of a live provider connection.

The real socket/stdio relay tests start an actual subprocess and WebSocket broker and verify request/result forwarding, denial, expiration, one-use pairing, cancellation and disconnect. SSH command construction enforces verified host keys and excludes shell/option injection; it does not change SSH configuration.

Python wheel and source distribution were built. The wheel includes extension assets, vendored source, provenance and third-party license. Linux and macOS/Python-version CI checks are defined for automatic execution on push and pull request.

## Not yet established

**Physical Microsoft Authenticator / Azure sign-in: NOT RUN.** It requires the user's nearby Mac and registered phone credential. No assertion of account-level login success is made.

**Physical macOS Bluetooth runtime: NOT RUN on the development host.** macOS CI validates package execution/imports and the software tests, not a real nearby phone. Do not call a CoreBluetooth import a BLE hardware test.

## Hardware acceptance

Run the documented companion from an interactive Mac terminal with Bluetooth enabled and its normal privacy permission. Start a session paired to the exact remote extension ID and verified SSH host. Request the existing Microsoft passkey in the remote browser, inspect/approve the origin and RP locally, scan the local QR and complete phone verification. Acceptance passes only after the original remote browser shows the correct signed-in account and a harmless Azure capability read succeeds.

Also cancel a real phone request, stop the companion, and verify the remote proxy detaches without retaining an active signing prompt. Do not publish live QR/session material or account screenshots as public evidence.
