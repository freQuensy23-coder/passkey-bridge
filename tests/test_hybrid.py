import asyncio
import hashlib
import hmac
from types import SimpleNamespace

import cbor2
import pytest
from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from passkey_bridge import backend, protocol
from passkey_bridge.vendor.cable_noise import (
    NoiseHandshake, PATTERN_KN_PSK0, keypair_from_private_bytes, pad_message, unpad_message,
)


def fixture_request():
    return {
        "challenge": protocol.encode_base64url(bytes(range(32))), "rpId": "login.microsoft.com",
        "userVerification": "required",
        "allowCredentials": [{"type": "public-key", "id": protocol.encode_base64url(b"fixture-credential")}],
        "extensions": {"remoteDesktopClientOverride": {
            "origin": "https://login.microsoft.com", "sameOriginWithAncestors": True,
        }},
    }


def derive(secret, purpose, salt=b"", length=64):
    return HKDF(algorithm=hashes.SHA256(), length=length, salt=salt, info=purpose.to_bytes(4, "little")).derive(secret)


def decode_qr(uri):
    digits = uri.removeprefix("FIDO:/")
    widths = {3: 1, 5: 2, 8: 3, 10: 4, 13: 5, 15: 6, 17: 7}
    return cbor2.loads(b"".join(int(digits[n:n + 17]).to_bytes(widths[len(digits[n:n + 17])], "little") for n in range(0, len(digits), 17)))


def advert(secret, eid):
    key = derive(secret, 1)
    encryptor = Cipher(algorithms.AES(key[:32]), modes.ECB()).encryptor()
    ciphertext = encryptor.update(eid) + encryptor.finalize()
    return ciphertext + hmac.new(key[32:], ciphertext, hashlib.sha256).digest()[:4]


@pytest.mark.parametrize("domain_id,domain", [(0, "cable.ua5v.com"), (1, "cable.auth.com"), (0x105, "cable.pyzci7hxyjsvc.org"), (266, "cable.wufkweyy3uaxb.com")])
def test_spec_tunnel_domain_vectors(domain_id, domain):
    assert backend._tunnel_domain(domain_id) == domain


@pytest.mark.parametrize("domain_id", [-1, 2, 255, 65536])
def test_unknown_assigned_domains_rejected(domain_id):
    with pytest.raises(backend.BackendError):
        backend._tunnel_domain(domain_id)


def test_ble_eid_authentication_rejects_tampering_and_reserved_bits():
    secret = bytes(range(16))
    eid = b"\x00" + bytes(range(10)) + b"abc" + b"\x00\x00"
    key = backend._derive(secret, 1)
    assert backend._decrypt_eid(key, advert(secret, eid)) == eid
    assert backend._decrypt_eid(key, b"short") is None
    modified = bytearray(advert(secret, eid))
    modified[-1] ^= 1
    assert backend._decrypt_eid(key, bytes(modified)) is None
    assert backend._decrypt_eid(key, advert(secret, b"\x01" + eid[1:])) is None
    assert backend._decrypt_eid(key, advert(secret, eid[:-2] + b"\x02\x00")) is None


def test_noise_real_crypto_roundtrip_and_tamper_detection():
    static = keypair_from_private_bytes(bytes.fromhex("00" * 31 + "01"))
    initiator = NoiseHandshake(pattern=PATTERN_KN_PSK0, role="initiator", local_static=static,
        local_ephemeral=keypair_from_private_bytes(bytes.fromhex("00" * 31 + "02")), psk=bytes(range(32)))
    responder = NoiseHandshake(pattern=PATTERN_KN_PSK0, role="responder", remote_static_public=static.public_bytes,
        local_ephemeral=keypair_from_private_bytes(bytes.fromhex("00" * 31 + "03")), psk=bytes(range(32)))
    assert responder.read_message(initiator.write_message()) == b""
    assert initiator.read_message(responder.write_message()) == b""
    client, phone = initiator.finish(), responder.finish()
    assert client.handshake_hash == phone.handshake_hash
    wire = client.send_cipher.encrypt_with_ad(b"", pad_message(b"\x01\x02fixture-ctap"))
    assert unpad_message(phone.receive_cipher.decrypt_with_ad(b"", wire)) == b"\x01\x02fixture-ctap"
    wire = bytearray(phone.send_cipher.encrypt_with_ad(b"", pad_message(b"\x01\x00fixture-assertion")))
    wire[1] ^= 1
    with pytest.raises(InvalidTag):
        client.receive_cipher.decrypt_with_ad(b"", bytes(wire))


class SimulatedHybridPhone:
    def __init__(self, context, qr, eid, *, block_response=False, status=0):
        self.context = context
        self.qr = qr
        self.eid = eid
        self.block_response = block_response
        self.status = status
        self.queue = asyncio.Queue()
        self.ready = asyncio.Event()
        self.closed = False
        self.shutdown = False
        self.ciphers = None
        self.credential_key = ec.derive_private_key(7, ec.SECP256R1())
        self.ctap_request = None

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        self.closed = True

    async def send(self, wire):
        if self.ciphers is None:
            key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), self.qr[0])
            from cryptography.hazmat.primitives import serialization
            peer = key.public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
            responder = NoiseHandshake(pattern=PATTERN_KN_PSK0, role="responder", remote_static_public=peer,
                local_ephemeral=keypair_from_private_bytes(bytes.fromhex("00" * 31 + "03")),
                psk=derive(self.qr[1], 3, self.eid, 32))
            assert responder.read_message(wire) == b""
            self.queue.put_nowait(responder.write_message())
            self.ciphers = responder.finish()
            info = cbor2.dumps({1: ["FIDO_2_1"], 4: {"uv": True}})
            self._queue(cbor2.dumps({1: info, 3: ["ctap"]}))
            return
        payload = unpad_message(self.ciphers.receive_cipher.decrypt_with_ad(b"", wire))
        if payload == b"\x00":
            self.shutdown = True
            return
        assert payload[:2] == b"\x01\x02"
        self.ctap_request = cbor2.loads(payload[2:])
        assert self.ctap_request[1] == self.context["rp_id"]
        assert self.ctap_request[2] == hashlib.sha256(self.context["client_data_json"]).digest()
        assert self.ctap_request[3] == self.context["allow_credentials"]
        assert self.ctap_request[5] == {"up": True, "uv": True}
        self.ready.set()
        if self.block_response:
            return
        auth_data = hashlib.sha256(self.context["rp_id"].encode()).digest() + b"\x05" + bytes(4)
        signature = self.credential_key.sign(auth_data + self.ctap_request[2], ec.ECDSA(hashes.SHA256()))
        self._queue(b"\x02" + cbor2.dumps({}))
        self._queue(b"\x01" + bytes([self.status]) + cbor2.dumps({
            1: {"type": "public-key", "id": b"fixture-credential"}, 2: auth_data, 3: signature,
        }))

    def _queue(self, payload):
        self.queue.put_nowait(self.ciphers.send_cipher.encrypt_with_ad(b"", pad_message(payload)))

    async def recv(self):
        return await self.queue.get()


def install_simulated_radio_and_tunnel(monkeypatch, *, block_response=False, status=0):
    state = {"scanning": False, "scanner_closed": False}
    context = protocol.validate_request(fixture_request())
    eid = b"\x00" + bytes(range(10)) + b"abc" + b"\x00\x00"
    def display(uri):
        state["qr"] = decode_qr(uri)
        assert state["qr"][4] is False
        assert state["qr"][5] == "ga"
    class Scanner:
        def __init__(self, **kwargs):
            assert "0000fff9-0000-1000-8000-00805f9b34fb" in kwargs["service_uuids"]
        async def __aenter__(self):
            state["scanning"] = True
            return self
        async def __aexit__(self, *args):
            state["scanner_closed"] = True
        async def start(self):
            await self.__aenter__()
        async def stop(self):
            await self.__aexit__()
        async def advertisement_data(self):
            for raw in (b"short", bytes(20), advert(state["qr"][1], eid)):
                yield None, SimpleNamespace(service_data={"0000fff9-0000-1000-8000-00805f9b34fb": raw})
    def connect(url, **kwargs):
        assert state["scanner_closed"]
        expected_id = derive(state["qr"][1], 2)[:16].hex()
        assert url == f"wss://cable.ua5v.com/cable/connect/616263/{expected_id}"
        assert kwargs["subprotocols"] == ["fido.cable"]
        assert kwargs["origin"] == "wss://cable.ua5v.com"
        assert kwargs["proxy"] is None
        assert kwargs.get("ssl") is not False
        assert kwargs["max_size"] <= 131072
        phone = SimulatedHybridPhone(context, state["qr"], eid, block_response=block_response, status=status)
        state["phone"] = phone
        return phone
    monkeypatch.setattr(backend, "_display_qr", display)
    monkeypatch.setattr(backend, "BleakScanner", Scanner)
    monkeypatch.setattr(backend, "connect", connect)
    return state


@pytest.mark.asyncio
async def test_simulated_phone_full_qr_ble_noise_ctap_path_with_real_signature(monkeypatch):
    state = install_simulated_radio_and_tunnel(monkeypatch)
    result = await backend.authenticate(fixture_request(), confirm=False)
    response = result["response"]
    auth_data = protocol.decode_base64url(response["authenticatorData"])
    client_data = protocol.decode_base64url(response["clientDataJSON"])
    signature = protocol.decode_base64url(response["signature"])
    state["phone"].credential_key.public_key().verify(signature, auth_data + hashlib.sha256(client_data).digest(), ec.ECDSA(hashes.SHA256()))
    with pytest.raises(InvalidSignature):
        state["phone"].credential_key.public_key().verify(signature, auth_data + bytes(32), ec.ECDSA(hashes.SHA256()))
    assert state["scanning"] and state["scanner_closed"]
    assert state["phone"].closed and state["phone"].shutdown


@pytest.mark.asyncio
async def test_simulated_cancellation_closes_tunnel_and_sends_shutdown(monkeypatch):
    state = install_simulated_radio_and_tunnel(monkeypatch, block_response=True)
    task = asyncio.create_task(backend.authenticate(fixture_request(), confirm=False))
    while "phone" not in state:
        await asyncio.sleep(0)
    await state["phone"].ready.wait()
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert state["phone"].closed
    assert state["phone"].shutdown
    assert state["scanner_closed"]


@pytest.mark.asyncio
async def test_simulated_ctap_error_is_not_a_success(monkeypatch):
    state = install_simulated_radio_and_tunnel(monkeypatch, status=0x2E)
    with pytest.raises(backend.BackendError, match="0x2e"):
        await backend.authenticate(fixture_request(), confirm=False)
    assert state["phone"].closed and state["phone"].shutdown


@pytest.mark.asyncio
async def test_cancel_during_ble_scan_exits_scanner(monkeypatch):
    started, stopped = asyncio.Event(), asyncio.Event()
    class Scanner:
        def __init__(self, **kwargs):
            pass
        async def __aenter__(self):
            started.set()
            return self
        async def __aexit__(self, *args):
            stopped.set()
        async def start(self):
            await self.__aenter__()
        async def stop(self):
            await self.__aexit__()
        async def advertisement_data(self):
            await asyncio.Future()
            yield None
    monkeypatch.setattr(backend, "BleakScanner", Scanner)
    task = asyncio.create_task(backend._scan_eid(bytes(64)))
    await started.wait()
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert stopped.is_set()


@pytest.mark.asyncio
async def test_ble_cleanup_failure_does_not_turn_cancellation_into_result(monkeypatch):
    started, stopped = asyncio.Event(), asyncio.Event()
    class Scanner:
        def __init__(self, **kwargs):
            pass
        async def start(self):
            started.set()
        async def stop(self):
            stopped.set()
            raise OSError("simulated radio shutdown error")
        async def advertisement_data(self):
            await asyncio.Future()
            yield None
    monkeypatch.setattr(backend, "BleakScanner", Scanner)
    task = asyncio.create_task(backend._scan_eid(bytes(64)))
    await started.wait()
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert stopped.is_set()


@pytest.mark.asyncio
async def test_cancel_during_ble_start_still_stops_scanner(monkeypatch):
    started, stopped = asyncio.Event(), asyncio.Event()
    class Scanner:
        def __init__(self, **kwargs):
            pass
        async def __aenter__(self):
            await self.start()
            return self
        async def __aexit__(self, *args):
            await self.stop()
        async def start(self):
            started.set()
            await asyncio.Future()
        async def stop(self):
            stopped.set()
    monkeypatch.setattr(backend, "BleakScanner", Scanner)
    task = asyncio.create_task(backend._scan_eid(bytes(64)))
    await started.wait()
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert stopped.is_set()
