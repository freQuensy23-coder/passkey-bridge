# Security boundaries

This experimental tool grants an explicitly paired remote browser access to a locally approved passkey assertion. Use only a server and browser you own or trust. A remote assertion authorizes the remote session, not the local companion.

The phone remains the passkey holder; the Mac is the real nearby hybrid initiator. Bluetooth proximity is between Mac and phone. The tool does not make a geographically remote server appear physically near the phone.

## Controls

- SSH encrypts remote transport and uses StrictHostKeyChecking=yes; no automatic host-key acceptance or verification bypass.
- The server listens only on IPv4 loopback. Distinct per-run random 256-bit tokens authorize extension and companion; the companion code is single-use and initially expires after ten minutes. The server session is time-limited.
- Browser origins cannot use the companion role. Only Chrome extension origins with the extension token can attach; there is no unauthenticated public WebAuthn signing endpoint.
- Local origin/RP allowlisting and explicit terminal consent occur before a radio transaction. The native transport must not use a localhost webpage to impersonate a relying party.
- Unsupported ceremonies/extensions/cross-origin contexts fail closed. Registration is disabled.
- A single in-flight request has a bounded lifetime. IDs are correlated, duplicate requests are refused, cancellations terminate the authenticator subprocess, and disconnected peers are detached.
- The tool does not persist passkey keys, Microsoft credentials, cookies or assertions, and does not include telemetry. Terminal QR output and connection codes are sensitive ephemeral session material.

A malicious process with access to the server account, browser extension privileges, local terminal or root can exceed this boundary. Session tokens are not protection against an already compromised endpoint.

## Limitations

Hybrid cryptography is reused from a research implementation with explicit upstream provenance. This project has not undergone an independent cryptographic security audit. Successful software tests do not establish Microsoft Authenticator interoperability or account-policy acceptance.

Normal macOS Bluetooth privacy consent and explicit installation of the remote extension can be required. If existing enterprise policy disallows either, the tool must stop; do not relax those policies to make a test pass.

An assertion's RP hash, flags and selected credential can be checked locally. The companion does not possess the relying party's stored public key and cannot independently establish the account-level assertion signature validity. The real relying party must verify it.

Do not submit private credentials, live QR/session material, signed assertions or private device identifiers in public issues. Describe a reproducible non-sensitive failure instead.
