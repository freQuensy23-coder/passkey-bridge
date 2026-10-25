import base64
import hashlib
import hmac
import ipaddress
import json
import math
import re
from urllib.parse import urlsplit

from fido2.rpid import verify_rp_id


DEFAULT_ALLOWED_ORIGINS = frozenset({
    "https://login.microsoft.com",
    "https://login.microsoftonline.com",
    "https://login.live.com",
})


class ValidationError(ValueError):
    pass


def encode_base64url(value):
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def decode_base64url(value, *, minimum=1, maximum=1024):
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9_-]+", value):
        raise ValidationError("Expected canonical unpadded base64url")
    if len(value) > (maximum * 4 + 2) // 3:
        raise ValidationError("Base64url value exceeds size limit")
    try:
        decoded = base64.b64decode(value + "=" * (-len(value) % 4), altchars=b"-_", validate=True)
    except ValueError as exc:
        raise ValidationError("Invalid base64url value") from exc
    if not minimum <= len(decoded) <= maximum or encode_base64url(decoded) != value:
        raise ValidationError("Invalid or noncanonical base64url value")
    return decoded


def _dns_name(value):
    if not isinstance(value, str) or len(value) > 253 or value != value.lower():
        return False
    labels = value.split(".")
    if len(labels) < 2 or any(not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label) for label in labels):
        return False
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return True
    return False


def _origin_host(origin):
    if not isinstance(origin, str) or any(ord(c) <= 32 or ord(c) >= 127 for c in origin):
        raise ValidationError("Origin must be a serialized HTTPS origin")
    try:
        parsed = urlsplit(origin)
        port = parsed.port
    except ValueError as exc:
        raise ValidationError("Invalid origin") from exc
    host = parsed.hostname
    if parsed.scheme != "https" or not isinstance(host, str) or not _dns_name(host) or parsed.username is not None or parsed.password is not None:
        raise ValidationError("Origin must use HTTPS and a DNS host")
    serialized = "https://" + host + (f":{port}" if port is not None and port != 443 else "")
    if origin != serialized or port == 0:
        raise ValidationError("Origin must be exactly serialized without path, credentials, query or fragment")
    return host


def validate_request(details, allowed_origins=None):
    if not isinstance(details, dict):
        raise ValidationError("Request must be an object")
    if "publicKey" in details or "pubKeyCredParams" in details or "user" in details:
        raise ValidationError("Only direct get-assertion request options are supported")
    if "crossOrigin" in details and details["crossOrigin"] is not False:
        raise ValidationError("Cross-origin requests are not supported")
    extensions = details.get("extensions")
    if not isinstance(extensions, dict):
        raise ValidationError("remoteDesktopClientOverride extension is required")
    if set(extensions) != {"remoteDesktopClientOverride"}:
        raise ValidationError("Unsupported or missing extension")
    override = extensions["remoteDesktopClientOverride"]
    if not isinstance(override, dict) or set(override) != {"origin", "sameOriginWithAncestors"}:
        raise ValidationError("Invalid remoteDesktopClientOverride extension")
    if override["sameOriginWithAncestors"] is not True:
        raise ValidationError("Cross-origin ancestry is not supported")
    origin = override["origin"]
    host = _origin_host(origin)
    allowed = DEFAULT_ALLOWED_ORIGINS if allowed_origins is None else allowed_origins
    if not isinstance(allowed, (set, frozenset, list, tuple)) or any(not isinstance(item, str) for item in allowed):
        raise ValidationError("Origin allowlist must be a collection of exact origins")
    if origin not in allowed:
        raise ValidationError("Origin is not in the exact local allowlist")
    if "origin" in details and details["origin"] != origin:
        raise ValidationError("Conflicting origin")
    rp_id = details.get("rpId", host)
    if not _dns_name(rp_id) or not verify_rp_id(rp_id, origin) or not verify_rp_id(rp_id, f"https://child.{rp_id}"):
        raise ValidationError("RP ID does not match the origin or is a public suffix")
    challenge = details.get("challenge")
    decode_base64url(challenge, minimum=16, maximum=1024)
    timeout = details.get("timeout", 120000)
    if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or (isinstance(timeout, float) and not math.isfinite(timeout)) or timeout <= 0:
        raise ValidationError("Timeout must be a finite positive number")
    timeout_ms = int(min(180000, max(15000, timeout)))
    uv = details.get("userVerification", "preferred")
    if uv not in ("required", "preferred", "discouraged"):
        raise ValidationError("Invalid userVerification requirement")
    credentials = details.get("allowCredentials", [])
    if not isinstance(credentials, list) or len(credentials) > 128:
        raise ValidationError("Invalid allowCredentials list")
    normalized_credentials = []
    for credential in credentials:
        if not isinstance(credential, dict) or credential.get("type") != "public-key" or set(credential) - {"type", "id", "transports"}:
            raise ValidationError("Invalid allowCredentials descriptor")
        raw_id = decode_base64url(credential.get("id"))
        transports = credential.get("transports", [])
        if not isinstance(transports, list) or any(t not in ("usb", "nfc", "ble", "internal", "hybrid", "smart-card") for t in transports):
            raise ValidationError("Unsupported credential transport")
        normalized_credentials.append({"type": "public-key", "id": raw_id})
    client_data_json = json.dumps({
        "type": "webauthn.get", "challenge": challenge, "origin": origin, "crossOrigin": False,
    }, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    return {
        "origin": origin, "rp_id": rp_id, "challenge": challenge, "timeout_ms": timeout_ms,
        "user_verification": uv, "allow_credentials": normalized_credentials,
        "extensions": {"remoteDesktopClientOverride": dict(override)}, "client_data_json": client_data_json,
    }


def validate_assertion(context, assertion):
    if not isinstance(assertion, dict):
        raise ValidationError("CTAP assertion must be a map")
    descriptor = assertion.get(1)
    allowed = context["allow_credentials"]
    if descriptor is None and len(allowed) == 1:
        descriptor = allowed[0]
    if not isinstance(descriptor, dict) or descriptor.get("type") != "public-key":
        raise ValidationError("Invalid assertion credential descriptor")
    credential_id = descriptor.get("id")
    if not isinstance(credential_id, bytes) or not 1 <= len(credential_id) <= 1024:
        raise ValidationError("Invalid assertion credential ID")
    if allowed and not any(hmac.compare_digest(credential_id, item["id"]) for item in allowed):
        raise ValidationError("Returned credential is not in allowCredentials")
    auth_data = assertion.get(2)
    if not isinstance(auth_data, bytes) or len(auth_data) != 37:
        raise ValidationError("Invalid authenticator data length or unsolicited authenticator extensions")
    if not hmac.compare_digest(auth_data[:32], hashlib.sha256(context["rp_id"].encode("utf-8")).digest()):
        raise ValidationError("Authenticator RP ID hash mismatch")
    flags = auth_data[32]
    if not flags & 1 or flags & 0xE2 or (flags & 0x10 and not flags & 0x08):
        raise ValidationError("Invalid authenticator flags or missing user presence")
    if context["user_verification"] == "required" and not flags & 4:
        raise ValidationError("Required user verification was not performed")
    signature = assertion.get(3)
    if not isinstance(signature, bytes) or not 1 <= len(signature) <= 4096:
        raise ValidationError("Invalid assertion signature")
    user = assertion.get(4)
    user_handle = None
    if user is not None:
        if not isinstance(user, dict) or not isinstance(user.get("id"), bytes) or not 1 <= len(user["id"]) <= 64:
            raise ValidationError("Invalid user handle")
        user_handle = encode_base64url(user["id"])
    if not allowed and user_handle is None:
        raise ValidationError("Discoverable credential response requires a user handle")
    return {
        "id": encode_base64url(credential_id), "rawId": encode_base64url(credential_id),
        "type": "public-key", "authenticatorAttachment": "cross-platform", "clientExtensionResults": {},
        "response": {
            "clientDataJSON": encode_base64url(context["client_data_json"]),
            "authenticatorData": encode_base64url(auth_data), "signature": encode_base64url(signature),
            "userHandle": user_handle,
        },
    }
