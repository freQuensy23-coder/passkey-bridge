# Protocol and source notes

## FIDO hybrid

CTAP hybrid combines QR bootstrapping, a Bluetooth advertisement proving that the local initiator can receive the phone's transmission, and an encrypted network tunnel carrying CTAP. It is not a stream of passkey private-key data over Bluetooth.

QR contains initiator session material. The phone uses the standard provider tunnel and transmits session-discovery information in its BLE advertisement. The initiator derives the handshake keys, performs Noise over TLS WebSocket and submits GetAssertion with SHA-256 of the actual clientDataJSON. The exact matching clientDataJSON must return alongside the assertion; generating a random hash as a demo cannot complete a website's login.

The laptop executes this protocol locally. The SSH bridge transports WebAuthn requests and results above it. Relaying only BLE advertisements into an unmodified remote Chrome is not a supported public Chrome extension interface and is not this implementation.

## Browser forwarding

Chrome's official Manifest V3 webAuthenticationProxy API is available from Chrome 115. Its requestDetailsJson contains request options, not a ready-made clientDataJSON. Chromium includes extensions.remoteDesktopClientOverride.origin and sameOriginWithAncestors so a trusted remote client can retain the original browser context.

The local companion validates that context and builds the client data once. The browser receives a serialized PublicKeyCredential via completeGetRequest. Registration is rejected. isUVPAA remains false because a nearby phone is not the remote machine's platform authenticator.

A regular localhost navigator.credentials.get cannot request credentials for an arbitrary Microsoft RP with Microsoft's origin. Browser-side remoteDesktopClientOverride usage has additional trust/allowlist restrictions. This project therefore uses a native local hybrid client and performs its own strict origin/RP checks, without changing browser security policies.

## Sources

- FIDO CTAP 2.3, hybrid transports: https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#sctn-hybrid
- Chrome webAuthenticationProxy: https://developer.chrome.com/docs/extensions/reference/api/webAuthenticationProxy
- Chromium JSON conversions: https://github.com/chromium/chromium/blob/main/components/webauthn/json/value_conversions.cc
- Chromium authenticator implementation: https://github.com/chromium/chromium/blob/main/content/browser/webauth/authenticator_common_impl.cc
- Microsoft Authenticator passkey sign-in: https://learn.microsoft.com/en-us/entra/identity/authentication/how-to-sign-in-passkey-authenticator
- Microsoft Authenticator passkey requirements: https://learn.microsoft.com/en-us/entra/identity/authentication/how-to-enable-authenticator-passkey
- Upstream Python hybrid reference: https://github.com/joostd/fido-hybrid-transport/tree/a890158370c17b44f2f3c67c59c90e2dba0bbf48
- Alternative Rust hybrid implementation: https://github.com/kanidm/webauthn-rs/tree/master/webauthn-authenticator-rs/src/cable

Compatibility with the user's actual Microsoft phone credential must be established by a real interactive acceptance run. Catalog/API support and a protocol implementation are not that evidence.
