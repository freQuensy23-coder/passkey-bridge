# Vendored hybrid transport

`cable_noise.py` is an unmodified copy of `common/cable_noise.py` from
https://github.com/joostd/fido-hybrid-transport at commit
`a890158370c17b44f2f3c67c59c90e2dba0bbf48`.

The upstream work is distributed under Apache License 2.0. Its license is
included verbatim as `LICENSE.fido-hybrid-transport`. Upstream does not include
a NOTICE file. Existing comments, documentation and attributions are preserved.

`../backend.py` adapts the QR encoding, HKDF purposes, authenticated EID discovery,
provider tunnel connection, KNpsk0 exchange and CTAP framing in upstream
`client/main.py`. It carries a modification notice. Changes include asynchronous
CoreBluetooth/Bleak scanning and WebSockets, continuous rejection of unrelated
advertisements, strict input and assertion validation, cancellable local consent,
bounded frames and deadlines, no raw secret logging, no persisted authenticator
linking, and FIDO-assigned/hashed tunnel domain decoding instead of upstream's
hardcoded domain for all IDs above 255. It supports QR-initiated tunnel mode only;
USB relay, BLE L2CAP and persistent state-assisted linking are not included.

Tunnel domain decoding follows the protocol algorithm also documented by
Chromium's `device/fido/cable/v2_handshake.cc`, function
`tunnelserver::DecodeDomain`:
https://chromium.googlesource.com/chromium/src/+/refs/heads/main/device/fido/cable/v2_handshake.cc

Protocol reference:
https://fidoalliance.org/specs/fido-v2.3-rd-20241003/fido-client-to-authenticator-protocol-v2.3-rd-20241003.html

Tests named `simulated` replace the BLE scanner and TLS tunnel with in-process
fixtures. They execute the actual Noise, EID authentication, CTAP request and
assertion-validation code, including a real generated fixture signature. They do
not establish compatibility with a physical phone or Microsoft Authenticator.
