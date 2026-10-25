import base64
import copy
import hashlib
import json

import pytest

from passkey_bridge import protocol


def encoded(value):
    return base64.urlsafe_b64encode(value).decode().rstrip("=")


def request():
    return {
        "challenge": encoded(bytes(range(32))),
        "rpId": "login.microsoft.com",
        "timeout": 300000,
        "userVerification": "required",
        "allowCredentials": [{"type": "public-key", "id": encoded(b"credential-id")}],
        "extensions": {
            "remoteDesktopClientOverride": {
                "origin": "https://login.microsoft.com",
                "sameOriginWithAncestors": True,
            }
        },
    }


def assertion(flags=5, credential=b"credential-id"):
    return {
        1: {"type": "public-key", "id": credential},
        2: hashlib.sha256(b"login.microsoft.com").digest() + bytes([flags]) + bytes(4),
        3: b"test-fixture-not-a-real-signature",
        4: {"id": b"test-user"},
    }


def test_valid_request_preserves_inputs_and_builds_matching_client_data():
    details = request()
    before = copy.deepcopy(details)
    context = protocol.validate_request(details)
    assert details == before
    assert context["origin"] == "https://login.microsoft.com"
    assert context["rp_id"] == "login.microsoft.com"
    assert context["challenge"] == details["challenge"]
    assert context["timeout_ms"] == 180000
    assert context["user_verification"] == "required"
    assert context["allow_credentials"] == [{"type": "public-key", "id": b"credential-id"}]
    assert json.loads(context["client_data_json"]) == {
        "type": "webauthn.get",
        "challenge": details["challenge"],
        "origin": "https://login.microsoft.com",
        "crossOrigin": False,
    }


@pytest.mark.parametrize("origin", [
    "http://login.microsoft.com", "https://login.microsoft.com/", "https://login.microsoft.com.evil.test",
    "https://login.microsoft.com@evil.test", "https://login.microsoft.com:443", "https://LOGIN.microsoft.com",
    "https://login.microsoft.com?x=1", "https://login.microsoft.com#x", "https://login.microsoft.com\n",
])
def test_origin_allowlist_is_exact(origin):
    details = request()
    details["extensions"]["remoteDesktopClientOverride"]["origin"] = origin
    with pytest.raises(protocol.ValidationError):
        protocol.validate_request(details)


@pytest.mark.parametrize("override", [None, {}, {"origin": "https://login.microsoft.com"},
    {"origin": "https://login.microsoft.com", "sameOriginWithAncestors": False},
    {"origin": "https://login.microsoft.com", "sameOriginWithAncestors": 1},
    {"origin": "https://login.microsoft.com", "sameOriginWithAncestors": True, "extra": True}])
def test_missing_or_cross_origin_override_rejected(override):
    details = request()
    details["extensions"]["remoteDesktopClientOverride"] = override
    with pytest.raises(protocol.ValidationError):
        protocol.validate_request(details)


@pytest.mark.parametrize("rp", ["com", "co.uk", "evil.test", "microsoft.com.evil.test", ".microsoft.com", "microsoft.com.", "MICROSOFT.com", "https://microsoft.com", "login.microsoft.com:443", "", None])
def test_invalid_rp_rejected(rp):
    details = request()
    details["rpId"] = rp
    with pytest.raises(protocol.ValidationError):
        protocol.validate_request(details)


def test_dns_parent_allowed_and_public_suffix_blocked_with_custom_origin():
    details = request()
    details["rpId"] = "microsoft.com"
    assert protocol.validate_request(details)["rp_id"] == "microsoft.com"
    details["extensions"]["remoteDesktopClientOverride"]["origin"] = "https://co.uk"
    details["rpId"] = "co.uk"
    with pytest.raises(protocol.ValidationError):
        protocol.validate_request(details, {"https://co.uk"})


@pytest.mark.parametrize("challenge", ["", "abc=", "a+b/", "!" * 32, encoded(bytes(15)), encoded(bytes(1025)), "A" * 21 + "B", None, [], True])
def test_invalid_challenge_rejected(challenge):
    details = request()
    details["challenge"] = challenge
    with pytest.raises(protocol.ValidationError):
        protocol.validate_request(details)


@pytest.mark.parametrize("timeout,expected", [(1, 15000), (15000, 15000), (30000, 30000), (300000, 180000)])
def test_positive_timeouts_clamped(timeout, expected):
    details = request()
    details["timeout"] = timeout
    assert protocol.validate_request(details)["timeout_ms"] == expected


@pytest.mark.parametrize("timeout", [0, -1, True, "100", None, float("nan"), float("inf")])
def test_invalid_timeout_rejected(timeout):
    details = request()
    details["timeout"] = timeout
    with pytest.raises(protocol.ValidationError):
        protocol.validate_request(details)


@pytest.mark.parametrize("field,value", [
    ("userVerification", "bogus"), ("userVerification", None), ("allowCredentials", None),
    ("allowCredentials", [{"type": "password", "id": "YWJj"}]),
    ("allowCredentials", [{"type": "public-key", "id": "YWJj="}]),
    ("allowCredentials", [{"type": "public-key", "id": ""}]),
    ("allowCredentials", [{"type": "public-key", "id": "YWJj", "transports": ["bogus"]}]),
    ("crossOrigin", True),
])
def test_invalid_request_fields_rejected(field, value):
    details = request()
    details[field] = value
    with pytest.raises(protocol.ValidationError):
        protocol.validate_request(details)


def test_unknown_extensions_rejected_not_dropped():
    details = request()
    details["extensions"]["prf"] = {"eval": {}}
    with pytest.raises(protocol.ValidationError, match="extension"):
        protocol.validate_request(details)


def test_default_origin_set_and_rp_default():
    for origin in ("https://login.microsoft.com", "https://login.microsoftonline.com", "https://login.live.com"):
        details = request()
        del details["rpId"]
        details["extensions"]["remoteDesktopClientOverride"]["origin"] = origin
        assert protocol.validate_request(details)["rp_id"] == origin.removeprefix("https://")


def test_custom_origins_require_explicit_allowlist():
    details = request()
    details["rpId"] = "example.org"
    details["extensions"]["remoteDesktopClientOverride"]["origin"] = "https://auth.example.org"
    with pytest.raises(protocol.ValidationError):
        protocol.validate_request(details)
    assert protocol.validate_request(details, {"https://auth.example.org"})["rp_id"] == "example.org"


@pytest.mark.parametrize("timeout", [10 ** 1000, 1.5])
def test_large_and_fractional_positive_timeouts_clamped(timeout):
    details = request()
    details["timeout"] = timeout
    assert 15000 <= protocol.validate_request(details)["timeout_ms"] <= 180000


@pytest.mark.parametrize("rp,origin", [
    ("github.io", "https://user.github.io"),
    ("foo.ck", "https://login.foo.ck"),
    ("co.uk", "https://login.co.uk"),
])
def test_psl_private_suffixes_and_wildcards_rejected(rp, origin):
    details = request()
    details["rpId"] = rp
    details["extensions"]["remoteDesktopClientOverride"]["origin"] = origin
    with pytest.raises(protocol.ValidationError):
        protocol.validate_request(details, {origin})


def test_psl_exception_permits_registrable_parent():
    details = request()
    details["rpId"] = "www.ck"
    details["extensions"]["remoteDesktopClientOverride"]["origin"] = "https://login.www.ck"
    assert protocol.validate_request(details, {"https://login.www.ck"})["rp_id"] == "www.ck"


def test_optional_user_agent_does_not_change_client_data():
    details = request()
    expected = protocol.validate_request(details)["client_data_json"]
    details["userAgent"] = "test-browser-agent"
    assert protocol.validate_request(details)["client_data_json"] == expected


def test_string_allowlist_is_not_treated_as_a_substring_pattern():
    with pytest.raises(protocol.ValidationError):
        protocol.validate_request(request(), "prefix https://login.microsoft.com suffix")


def test_ctap_may_omit_descriptor_for_single_allowed_credential():
    context = protocol.validate_request(request())
    value = assertion()
    del value[1]
    assert protocol.validate_assertion(context, value)["id"] == encoded(b"credential-id")


def test_ctap_cannot_omit_descriptor_for_discoverable_credential():
    details = request()
    details["allowCredentials"] = []
    context = protocol.validate_request(details)
    value = assertion()
    del value[1]
    with pytest.raises(protocol.ValidationError):
        protocol.validate_assertion(context, value)


def test_discoverable_credential_with_user_handle_is_valid():
    details = request()
    details["allowCredentials"] = []
    context = protocol.validate_request(details)
    assert protocol.validate_assertion(context, assertion())["response"]["userHandle"] == encoded(b"test-user")


def test_response_preserves_exact_client_data_bytes():
    context = protocol.validate_request(request())
    result = protocol.validate_assertion(context, assertion())
    assert result["id"] == encoded(b"credential-id")
    assert result["rawId"] == result["id"]
    assert result["type"] == "public-key"
    assert result["authenticatorAttachment"] == "cross-platform"
    assert result["clientExtensionResults"] == {}
    assert result["response"]["clientDataJSON"] == encoded(context["client_data_json"])
    assert result["response"]["authenticatorData"] == encoded(assertion()[2])
    assert result["response"]["userHandle"] == encoded(b"test-user")


@pytest.mark.parametrize("flags", [0, 1, 4, 0x45, 0x15, 0x25])
def test_missing_up_uv_and_invalid_flags_rejected(flags):
    context = protocol.validate_request(request())
    with pytest.raises(protocol.ValidationError):
        protocol.validate_assertion(context, assertion(flags))


def test_wrong_rp_hash_and_credential_id_rejected():
    context = protocol.validate_request(request())
    value = assertion()
    value[2] = bytes(32) + value[2][32:]
    with pytest.raises(protocol.ValidationError):
        protocol.validate_assertion(context, value)
    with pytest.raises(protocol.ValidationError):
        protocol.validate_assertion(context, assertion(credential=b"not-allowed"))


@pytest.mark.parametrize("mutation", [
    lambda a: a.update({2: b"short"}),
    lambda a: a.update({2: a[2] + b"unexpected"}),
    lambda a: a.update({3: b""}),
    lambda a: a.update({1: {"type": "public-key", "id": b""}}),
    lambda a: a.update({4: {"id": b"x" * 65}}),
])
def test_malformed_assertions_rejected(mutation):
    context = protocol.validate_request(request())
    value = assertion()
    mutation(value)
    with pytest.raises(protocol.ValidationError):
        protocol.validate_assertion(context, value)


def test_preferred_uv_does_not_require_uv_and_absent_user_handle_is_null():
    details = request()
    details["userVerification"] = "preferred"
    context = protocol.validate_request(details)
    value = assertion(flags=1)
    del value[4]
    assert protocol.validate_assertion(context, value)["response"]["userHandle"] is None


def test_discoverable_credentials_require_user_handle():
    details = request()
    details["allowCredentials"] = []
    context = protocol.validate_request(details)
    value = assertion()
    del value[4]
    with pytest.raises(protocol.ValidationError):
        protocol.validate_assertion(context, value)
