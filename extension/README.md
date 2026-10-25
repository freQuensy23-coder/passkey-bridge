# Chrome extension

Requires Chrome 115+ and Manifest V3 `webAuthenticationProxy`. Install explicitly in the remote task browser; do not install into a shared everyday browser profile.

1. Open `chrome://extensions` in the intended Chrome or Chrome for Testing profile.
2. Enable Developer mode, choose **Load unpacked**, and select this `extension/` directory.
3. Copy the extension ID into the broker's explicit extension-origin allowlist before connecting.
4. Open the extension action or **Details → Extension options**. Enter the broker's loopback port and extension session token, then **Connect**.
5. Connect the paired local companion. **Refresh status** confirms authentication, helper availability and proxy attachment. Authentication alone does not attach the proxy.
6. Use **Disconnect and forget token** when finished. Normal browser authentication resumes after detachment. If proxy cleanup fails, disable the extension.

Official branded Chrome 137+ does not support `--load-extension`. Use the explicit Developer mode UI above or a dedicated Chrome for Testing build. Never change an existing shared browser session just to load this extension.

The WebSocket endpoint is fixed to `ws://127.0.0.1:PORT`. Chrome host match patterns do not include port restrictions, so the host permission is `http://127.0.0.1/*`; the worker validates the entered numeric port. The extension has no remote endpoint, content script, telemetry, cookie access or browser-session export.

Only the port and extension token are held in `chrome.storage.session`, never `storage.local`, `storage.sync`, page local storage or disk-backed extension settings. Disconnect or socket failure removes them. Browser restart, extension reload, update or disable also clears session storage. A suspended service worker can restore an existing session-memory connection, but must authenticate and wait for a helper again before attaching.

The bridge accepts one assertion at a time. Registration fails locally with `NotSupportedError`. Platform-authenticator availability is always false. Cancellation is forwarded only for the matching outstanding request. Helper loss, transport failure and authentication errors fail pending requests and detach the proxy. Remote exception messages are replaced with fixed safe messages; assertion JSON, including client data, is preserved exactly as provided by the authenticated broker.

Chrome can suspend an idle service worker, especially on Chrome 115. Do not assume an idle WebSocket guarantees continuous attachment. Refresh the connection status before use; reconnect if needed. Later Chrome versions improve WebSocket lifetime handling, but no background availability guarantee is made.

Automated lifecycle checks: `node --test tests/extension.test.mjs` from the repository root. These execute the real worker and options script using isolated Chrome/WebSocket API adapters; they do not prove a physical phone or account sign-in.
