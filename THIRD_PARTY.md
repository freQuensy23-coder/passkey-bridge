# Third-party provenance

The caBLE Noise implementation is reused, not claimed as original cryptographic work.

`src/passkey_bridge/vendor/cable_noise.py` is copied unchanged from `common/cable_noise.py` in [joostd/fido-hybrid-transport](https://github.com/joostd/fido-hybrid-transport/tree/a890158370c17b44f2f3c67c59c90e2dba0bbf48), commit `a890158370c17b44f2f3c67c59c90e2dba0bbf48`, under Apache License 2.0. The original license is included as `src/passkey_bridge/vendor/LICENSE.fido-hybrid-transport`. Upstream has no NOTICE file. Its existing source comments and attribution are retained.

The local hybrid backend adapts the upstream client's protocol flow and carries an explicit modification notice. It adds cancellable asyncio transport/consent, strict browser-origin/RP validation, bounded requests, no persistent phone linking and protocol tunnel-domain decoding. See [vendored provenance](src/passkey_bridge/vendor/PROVENANCE.md) for the precise adaptation scope.

Runtime libraries retain their own licenses: Yubico python-fido2 for RP validation, Bleak for the platform Bluetooth interface, cryptography for cryptographic primitives, websockets, cbor2 and PyQRCode. Dependency versions and distributions are recorded in uv.lock. Browser development dependencies are recorded in package-lock.json.

This project is experimental and has not undergone an independent cryptographic security audit. Upstream reference code and passing simulated tests do not establish phone/provider interoperability.
