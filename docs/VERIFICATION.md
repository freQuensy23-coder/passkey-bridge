# Verification scope

## Executed on the development Linux host

The latest local implementation snapshot passed **159 Python tests, no skips**, with the dedicated Chrome for Testing integration enabled. Separately, the MV3 worker/options lifecycle suite passed **31 tests, no failures or skips**. These are software-fixture results; GitHub Actions is the authoritative record for the published commit.

[Automatic GitHub Actions for source revision 962f659](https://github.com/freQuensy23-coder/passkey-bridge/actions/runs/40219652594) passed on Linux and macOS with Python 3.11 and 3.13. Each matrix job passed 156 Python tests and 31 extension lifecycle tests, built the wheel/source distribution and checked packaged extension assets. The three browser cases are intentionally excluded from matrix jobs and all passed in the dedicated real-Chrome job. Both macOS jobs imported CoreBluetooth successfully; this is not hardware scanning evidence.

The real Chrome for Testing 156 integration loaded the actual unpacked extension, authenticated a real loopback broker, attached the real webAuthenticationProxy API, intercepted a page's navigator.credentials.get, preserved the browser-provided origin override, returned a real ECDSA-signed **software test fixture** assertion and detached. It uses an isolated disposable profile and a local test relying-party origin. It does not use a physical phone or sign in to Microsoft.

This integration exposed actual negative opaque Chrome request IDs; broker and companion regression tests now preserve those IDs exactly.

Backend tests exercise actual EID AES/HMAC authentication, P-256/Noise/AES-GCM roundtrips and tamper rejection, exact CTAP framing/client-data hashes, assertion checks, terminal consent, subprocess output isolation and SIGTERM cancellation cleanup. Tests explicitly named simulated replace the BLE scanner and provider TLS tunnel with in-process fixtures. They are not a claim of a live provider connection.

The real socket/stdio relay tests start an actual subprocess and WebSocket broker and verify request/result forwarding, denial, expiration, one-use pairing, cancellation and disconnect. SSH command construction enforces verified host keys and excludes shell/option injection; it does not change SSH configuration.

Python wheel and source distribution were built. The wheel includes extension assets, vendored source, provenance and third-party license. Linux and macOS/Python-version CI checks are defined for automatic execution on push and pull request.

## Executed on the user's Mac (2026-10-25)

One real phone-passkey sign-in completed from macOS 26.6.2 (Apple Silicon, Python 3.13) through the SSH bridge to the isolated remote Chrome for Testing session. The companion received and authenticated the phone's BLE advertisement, established TLS and Noise, sent CTAP GetAssertion and validated the returned assertion. The extension recorded a signed helper response with the same ID as the original `login.microsoft.com` request. The original remote browser then loaded Outlook's mailbox with the expected user's name in the page title; the user also reported successful sign-in on the phone.

This run used the service-data discovery and advertisement-suffix fixes. It establishes that this specific physical path worked; the phone model and credential-provider app were not independently recorded. It does not establish interoperability for every phone/provider or an Azure/Foundry capability grant. Session codes, QR data, account identifiers and assertion contents are excluded from public evidence.

The updated source passed 160 Python tests on this Mac (three dedicated Chrome integration cases skipped), lint and wheel/source builds. The existing Chrome integration coverage described above is from the earlier revision, not a new browser-fixture run for this patch.

## Not yet established

**Azure/Foundry capability access: NOT RUN in this hardware test.** Outlook sign-in does not establish account entitlement to a separate service. Provider-specific Microsoft Authenticator compatibility also needs a run with the phone/provider explicitly identified.

## Hardware acceptance

Run the documented companion from an interactive Mac terminal with Bluetooth enabled and its normal privacy permission. Start a session paired to the exact remote extension ID and verified SSH host. Request the existing Microsoft passkey in the remote browser, inspect/approve the origin and RP locally, scan the local QR and complete phone verification. Acceptance passes only after the original remote browser shows the correct signed-in account and a harmless Azure capability read succeeds.

Also cancel a real phone request, stop the companion, and verify the remote proxy detaches without retaining an active signing prompt. Do not publish live QR/session material or account screenshots as public evidence.
