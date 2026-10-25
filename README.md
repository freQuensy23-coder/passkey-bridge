# Passkey Bridge

Use an existing phone passkey to sign in in a trusted remote Chrome session. A macOS companion performs the real FIDO hybrid transaction locally, where Bluetooth is available. The remote Linux machine does not need a Bluetooth adapter.

**Status: experimental.** The implementation must pass the documented automated checks. A real Microsoft Authenticator phone-to-Azure sign-in still requires an interactive hardware acceptance run. Do not treat software tests as proof of that sign-in.

This is an explicitly paired remote-authentication client. It does not export private passkey material, disable Microsoft account policies, modify TLS trust, or replace phone user verification.
