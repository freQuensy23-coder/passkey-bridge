import asyncio
import contextlib
import errno
import hashlib
import hmac
import io
import json
import os
import secrets
import select
import signal
import sys
import time

import cbor2
import pyqrcode
from bleak import BleakScanner
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from websockets.asyncio.client import connect

from .protocol import ValidationError, validate_assertion, validate_request
from .vendor.cable_noise import NoiseHandshake, PATTERN_KN_PSK0, generate_keypair, pad_message, unpad_message


__modification_notice__ = "Hybrid client adapted from joostd/fido-hybrid-transport client/main.py at a890158370c17b44f2f3c67c59c90e2dba0bbf48; rewritten for cancellable asyncio, strict WebAuthn validation and no persisted linking. See vendor/PROVENANCE.md and vendor/LICENSE.fido-hybrid-transport."

SERVICE_UUIDS = (
    "0000fff9-0000-1000-8000-00805f9b34fb",
    "0000fde2-0000-1000-8000-00805f9b34fb",
)
MAX_FRAME_SIZE = 131072


class BackendError(ValueError):
    pass


def _progress(message):
    if os.environ.get("PASSKEY_BRIDGE_DEBUG") == "1":
        print(f"[{time.strftime('%H:%M:%S')}] {message}", file=sys.stderr, flush=True)


def _derive(secret, purpose, salt=b""):
    return HKDF(algorithm=hashes.SHA256(), length=64, salt=salt, info=purpose.to_bytes(4, "little")).derive(secret)


def _tunnel_domain(domain_id):
    if not isinstance(domain_id, int) or not 0 <= domain_id <= 65535:
        raise BackendError("Invalid tunnel domain ID")
    assigned = ("cable.ua5v.com", "cable.auth.com")
    if domain_id < len(assigned):
        return assigned[domain_id]
    if domain_id < 256:
        raise BackendError("Unknown assigned tunnel domain")
    digest = hashlib.sha256(b"caBLEv2 tunnel server domain" + domain_id.to_bytes(2, "little") + b"\x00").digest()
    value = int.from_bytes(digest[:8], "little")
    tld = ("com", "org", "net", "info")[value & 3]
    value >>= 2
    chars = []
    while value:
        chars.append("abcdefghijklmnopqrstuvwxyz234567"[value & 31])
        value >>= 5
    return "cable." + "".join(chars) + "." + tld


def _decrypt_eid(key, advert):
    if not isinstance(advert, bytes) or not 20 <= len(advert) <= MAX_FRAME_SIZE:
        return None
    # QR mode advertises only the tunnel transport. CTAP hybrid requires us to
    # authenticate the first 20 bytes and ignore an optional advertisement suffix.
    advert = advert[:20]
    if not hmac.compare_digest(hmac.new(key[32:], advert[:16], hashlib.sha256).digest()[:4], advert[16:]):
        return None
    decryptor = Cipher(algorithms.AES(key[:32]), modes.ECB()).decryptor()
    plaintext = decryptor.update(advert[:16]) + decryptor.finalize()
    if plaintext[0] != 0:
        return None
    try:
        _tunnel_domain(int.from_bytes(plaintext[14:16], "little"))
    except BackendError:
        return None
    return plaintext


def _qr_uri(static, secret):
    public = static.private_key.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.CompressedPoint)
    payload = cbor2.dumps({0: public, 1: secret, 2: 2, 3: int(time.time()), 4: False, 5: "ga"}, canonical=True)
    widths = (0, 3, 5, 8, 10, 13, 15, 17)
    digits = []
    for offset in range(0, len(payload), 7):
        chunk = payload[offset:offset + 7]
        digits.append(str(int.from_bytes(chunk, "little")).zfill(widths[len(chunk)]))
    return "FIDO:/" + "".join(digits)


def _display_qr(uri):
    qr = pyqrcode.create(uri, mode="alphanumeric", error="L")
    print("Scan with your nearby phone's system passkey QR scanner; approve on the phone.", file=sys.stderr, flush=True)
    print(qr.terminal(quiet_zone=4), file=sys.stderr, flush=True)


async def _scan_eid(key):
    try:
        # A hybrid advert can carry its UUID only in service_data. Bleak's UUID
        # filter checks the separate advertised-services list before delivering
        # service_data (including on CoreBluetooth), so filter after reception.
        scanner = BleakScanner()
        cancelled = False
        candidates = 0
        try:
            await scanner.start()
            _progress("Bluetooth scanner started; waiting for the phone")
            async for _, advertisement in scanner.advertisement_data():
                for uuid, raw in advertisement.service_data.items():
                    if uuid.lower() in SERVICE_UUIDS:
                        candidates += 1
                        eid = _decrypt_eid(key, raw)
                        if eid is not None:
                            _progress("Matching authenticated phone Bluetooth advertisement received")
                            return eid
        except asyncio.CancelledError:
            cancelled = True
            raise
        finally:
            _progress(f"Bluetooth scan finished; hybrid advertisements received: {candidates}")
            try:
                async with asyncio.timeout(2):
                    await scanner.stop()
            except Exception:
                if not cancelled:
                    raise
    except asyncio.CancelledError:
        raise
    except Exception as exc:
        raise BackendError(f"Bluetooth scan failed ({type(exc).__name__}); enable Bluetooth and grant this terminal Bluetooth access") from exc
    raise BackendError("Bluetooth scanner stopped before receiving a matching phone advertisement")


def _load_cbor(payload):
    if not isinstance(payload, bytes) or len(payload) > MAX_FRAME_SIZE:
        raise BackendError("Invalid CTAP payload size")
    stream = io.BytesIO(payload)
    try:
        value = cbor2.load(stream)
    except (ValueError, EOFError, cbor2.CBORDecodeError) as exc:
        raise BackendError("Invalid CTAP CBOR") from exc
    if stream.read(1):
        raise BackendError("Unexpected trailing CTAP CBOR data")
    return value


async def _receive(websocket):
    message = await websocket.recv()
    if not isinstance(message, bytes) or not 1 <= len(message) <= MAX_FRAME_SIZE:
        raise BackendError("Expected a bounded binary hybrid tunnel frame")
    return message


def _assertion_parameters(context, info):
    options = {"up": True}
    if context["user_verification"] == "required" or (
        context["user_verification"] == "preferred" and info.get(4, {}).get("uv") is True
    ):
        options["uv"] = True
    parameters = {
        1: context["rp_id"], 2: hashlib.sha256(context["client_data_json"]).digest(), 5: options,
    }
    if context["allow_credentials"]:
        parameters[3] = context["allow_credentials"]
    return parameters


async def _hybrid_assertion(context):
    static = generate_keypair()
    secret = secrets.token_bytes(16)
    _display_qr(_qr_uri(static, secret))
    eid = await _scan_eid(_derive(secret, 1))
    domain = _tunnel_domain(int.from_bytes(eid[14:16], "little"))
    tunnel_id = _derive(secret, 2)[:16]
    uri = f"wss://{domain}/cable/connect/{eid[11:14].hex()}/{tunnel_id.hex()}"
    handshake = NoiseHandshake(pattern=PATTERN_KN_PSK0, role="initiator", local_static=static,
        psk=_derive(secret, 3, eid)[:32])
    _progress("Connecting to the phone's hybrid TLS tunnel")
    async with connect(uri, subprotocols=["fido.cable"], origin=f"wss://{domain}", proxy=None,
        max_size=MAX_FRAME_SIZE, max_queue=4, open_timeout=10, close_timeout=2, ping_interval=20) as websocket:
        _progress("Hybrid TLS tunnel connected; starting Noise handshake")
        session = None
        try:
            await websocket.send(handshake.write_message())
            async with asyncio.timeout(10):
                reply = await _receive(websocket)
                if len(reply) != 81 or handshake.read_message(reply) != b"":
                    raise BackendError("Invalid hybrid Noise handshake response")
                session = handshake.finish()
                _progress("Hybrid Noise handshake completed")
                post_handshake = _load_cbor(unpad_message(session.receive_cipher.decrypt_with_ad(b"", await _receive(websocket))))
            if not isinstance(post_handshake, dict) or "ctap" not in post_handshake.get(3, ["ctap"]):
                raise BackendError("Phone does not support CTAP over hybrid")
            info = _load_cbor(post_handshake.get(1))
            if not isinstance(info, dict) or not isinstance(info.get(4, {}), dict):
                raise BackendError("Invalid cached authenticatorGetInfo")
            payload = b"\x01\x02" + cbor2.dumps(_assertion_parameters(context, info), canonical=True)
            await websocket.send(session.send_cipher.encrypt_with_ad(b"", pad_message(payload)))
            _progress("CTAP GetAssertion sent; waiting for phone approval")
            while True:
                frame = unpad_message(session.receive_cipher.decrypt_with_ad(b"", await _receive(websocket)))
                if not frame:
                    raise BackendError("Empty hybrid frame")
                if frame[0] == 2:
                    continue
                if frame[0] == 0:
                    raise BackendError("Phone ended the hybrid session")
                if frame[0] != 1 or len(frame) < 2:
                    raise BackendError("Unexpected hybrid frame type")
                if frame[1] != 0:
                    raise BackendError(f"Phone CTAP GetAssertion failed with status 0x{frame[1]:02x}")
                _progress("Phone assertion received")
                return _load_cbor(frame[2:])
        finally:
            if session is not None:
                with contextlib.suppress(Exception):
                    async with asyncio.timeout(1):
                        await websocket.send(session.send_cipher.encrypt_with_ad(b"", pad_message(b"\x00")))


def _open_terminal():
    try:
        return os.open("/dev/tty", os.O_RDWR | os.O_NONBLOCK | os.O_NOCTTY)
    except OSError as exc:
        raise BackendError("Local consent requires a controlling terminal (/dev/tty); run connect from an interactive terminal") from exc


async def _confirm(context):
    import termios

    terminal = _open_terminal()
    loop = asyncio.get_running_loop()
    answer = loop.create_future()
    pending = bytearray()
    reader_installed = False
    def ready():
        if answer.done():
            return
        try:
            chunk = os.read(terminal, 256)
        except BlockingIOError:
            return
        except OSError:
            answer.set_exception(BackendError("Local consent terminal closed"))
            return
        if not chunk:
            answer.set_exception(BackendError("Local consent terminal closed"))
            return
        pending.extend(chunk)
        if len(pending) > 256:
            answer.set_exception(BackendError("Local consent refused"))
        elif b"\n" in pending:
            answer.set_result(bytes(pending))
    try:
        termios.tcflush(terminal, termios.TCIFLUSH)
        try:
            loop.add_reader(terminal, ready)
            reader_installed = True
        except OSError as exc:
            if exc.errno != errno.EINVAL:
                raise
        print(f"\nPasskey sign-in\nOrigin: {context['origin']}\nRP ID: {context['rp_id']}\nType yes to allow this request: ",
            file=sys.stderr, end="", flush=True)
        if not reader_installed:
            while not answer.done():
                if select.select([terminal], [], [], 0)[0]:
                    ready()
                if not answer.done():
                    await asyncio.sleep(0.05)
        response = await answer
        if response != b"yes\n":
            raise BackendError("Local consent refused")
    finally:
        if reader_installed:
            loop.remove_reader(terminal)
        with contextlib.suppress(OSError, termios.error):
            termios.tcflush(terminal, termios.TCIFLUSH)
        os.close(terminal)


async def authenticate(request_details: dict, *, confirm=True) -> dict:
    context = validate_request(request_details)
    try:
        async with asyncio.timeout(context["timeout_ms"] / 1000):
            if confirm:
                await _confirm(context)
                _progress("Local consent accepted")
            assertion = await _hybrid_assertion(context)
            result = validate_assertion(context, assertion)
            _progress("Assertion validated; returning it to the remote browser")
            return result
    except TimeoutError as exc:
        raise BackendError("Passkey request timed out") from exc
    except (BackendError, ValidationError, asyncio.CancelledError):
        raise
    except Exception as exc:
        raise BackendError(f"Hybrid transport failed ({type(exc).__name__})") from exc


async def _run_request(details):
    loop = asyncio.get_running_loop()
    task = asyncio.current_task()
    installed = []
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, task.cancel)
            installed.append(sig)
        except (NotImplementedError, RuntimeError):
            pass
    try:
        return await authenticate(details)
    finally:
        for sig in installed:
            loop.remove_signal_handler(sig)


def _main():
    try:
        raw = sys.stdin.buffer.readline(MAX_FRAME_SIZE + 1)
        if len(raw) > MAX_FRAME_SIZE:
            raise BackendError("Request exceeds maximum frame size")
        try:
            details = json.loads(raw)
        except (ValueError, UnicodeError) as exc:
            raise BackendError("Invalid request JSON") from exc
        result = asyncio.run(_run_request(details))
        print(json.dumps(result, separators=(",", ":")), flush=True)
        return 0
    except (BackendError, ValidationError) as exc:
        print(str(exc), file=sys.stderr, flush=True)
        return 1
    except (KeyboardInterrupt, asyncio.CancelledError):
        print("Passkey request cancelled", file=sys.stderr, flush=True)
        return 130


if __name__ == "__main__":
    raise SystemExit(_main())
