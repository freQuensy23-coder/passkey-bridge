import asyncio
import fcntl
import hashlib
import json
import os
import pty
import select
import subprocess
import sys
import termios
import time

import pytest

from passkey_bridge import backend, protocol


def request():
    return {
        "challenge": protocol.encode_base64url(bytes(range(32))),
        "rpId": "login.microsoft.com",
        "userVerification": "required",
        "allowCredentials": [{"type": "public-key", "id": protocol.encode_base64url(b"test-credential")}],
        "extensions": {"remoteDesktopClientOverride": {
            "origin": "https://login.microsoft.com", "sameOriginWithAncestors": True,
        }},
    }


def fixture_assertion():
    return {
        1: {"type": "public-key", "id": b"test-credential"},
        2: hashlib.sha256(b"login.microsoft.com").digest() + b"\x05" + bytes(4),
        3: b"fixture-only-signature",
    }


@pytest.mark.asyncio
async def test_validation_precedes_consent_and_radio(monkeypatch):
    events = []
    async def confirm(context):
        events.append("consent")
    async def hybrid(context):
        events.append("radio")
    monkeypatch.setattr(backend, "_confirm", confirm)
    monkeypatch.setattr(backend, "_hybrid_assertion", hybrid)
    with pytest.raises(protocol.ValidationError):
        await backend.authenticate({})
    assert events == []


@pytest.mark.asyncio
async def test_explicit_consent_precedes_radio_and_exact_client_data_returned(monkeypatch):
    events = []
    async def confirm(context):
        assert context["origin"] == "https://login.microsoft.com"
        events.append("consent")
    async def hybrid(context):
        assert events == ["consent"]
        events.append("radio")
        return fixture_assertion()
    monkeypatch.setattr(backend, "_confirm", confirm)
    monkeypatch.setattr(backend, "_hybrid_assertion", hybrid)
    result = await backend.authenticate(request())
    assert events == ["consent", "radio"]
    expected = protocol.validate_request(request())["client_data_json"]
    assert result["response"]["clientDataJSON"] == protocol.encode_base64url(expected)


@pytest.mark.asyncio
async def test_consent_refusal_never_starts_radio(monkeypatch):
    async def confirm(context):
        raise backend.BackendError("Local consent refused")
    async def hybrid(context):
        pytest.fail("radio must not start")
    monkeypatch.setattr(backend, "_confirm", confirm)
    monkeypatch.setattr(backend, "_hybrid_assertion", hybrid)
    with pytest.raises(backend.BackendError, match="consent"):
        await backend.authenticate(request())


@pytest.mark.asyncio
async def test_cancellation_runs_transport_finally(monkeypatch):
    started = asyncio.Event()
    closed = asyncio.Event()
    async def hybrid(context):
        try:
            started.set()
            await asyncio.Future()
        finally:
            closed.set()
    monkeypatch.setattr(backend, "_hybrid_assertion", hybrid)
    task = asyncio.create_task(backend.authenticate(request(), confirm=False))
    await started.wait()
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert closed.is_set()


@pytest.mark.asyncio
async def test_timeout_covers_consent_and_transport(monkeypatch):
    context = protocol.validate_request(request())
    context["timeout_ms"] = 10
    closed = asyncio.Event()
    async def confirm(context):
        try:
            await asyncio.Future()
        finally:
            closed.set()
    monkeypatch.setattr(backend, "validate_request", lambda details: context)
    monkeypatch.setattr(backend, "_confirm", confirm)
    with pytest.raises(backend.BackendError, match="timed out"):
        await backend.authenticate(request())
    assert closed.is_set()


@pytest.mark.asyncio
async def test_terminal_consent_reader_removed_on_cancellation(monkeypatch):
    master, slave = pty.openpty()
    monkeypatch.setattr(backend, "_open_terminal", lambda: os.dup(slave))
    loop = asyncio.get_running_loop()
    original_remove = loop.remove_reader
    removed = []
    def remove(fd):
        removed.append(fd)
        return original_remove(fd)
    monkeypatch.setattr(loop, "remove_reader", remove)
    task = asyncio.create_task(backend._confirm(protocol.validate_request(request())))
    await asyncio.sleep(0)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert len(removed) == 1
    with pytest.raises(OSError):
        os.fstat(removed[0])
    os.close(master)
    os.close(slave)



@pytest.mark.asyncio
@pytest.mark.parametrize("answer,accepted", [(b"yes\n", True), (b"y\n", False), (b"no\n", False), (b"\n", False)])
async def test_terminal_consent_requires_explicit_yes(monkeypatch, answer, accepted):
    master, slave = pty.openpty()
    monkeypatch.setattr(backend, "_open_terminal", lambda: os.dup(slave))
    task = asyncio.create_task(backend._confirm(protocol.validate_request(request())))
    await asyncio.sleep(0)
    os.write(master, answer)
    try:
        if accepted:
            await asyncio.wait_for(task, 1)
        else:
            with pytest.raises(backend.BackendError, match="consent"):
                await asyncio.wait_for(task, 1)
    finally:
        os.close(master)
        os.close(slave)


@pytest.mark.asyncio
async def test_terminal_consent_flushes_stale_confirmation(monkeypatch):
    master, slave = pty.openpty()
    monkeypatch.setattr(backend, "_open_terminal", lambda: os.dup(slave))
    os.write(master, b"yes\n")
    task = asyncio.create_task(backend._confirm(protocol.validate_request(request())))
    await asyncio.sleep(0)
    assert not task.done()
    os.write(master, b"no\n")
    try:
        with pytest.raises(backend.BackendError, match="consent"):
            await asyncio.wait_for(task, 1)
    finally:
        os.close(master)
        os.close(slave)


def test_ctap_request_hashes_exact_client_data_and_passes_allowlist():
    context = protocol.validate_request(request())
    params = backend._assertion_parameters(context, {4: {"uv": True}})
    assert params == {
        1: "login.microsoft.com", 2: hashlib.sha256(context["client_data_json"]).digest(),
        3: [{"type": "public-key", "id": b"test-credential"}], 5: {"up": True, "uv": True},
    }


def test_backend_module_rejects_invalid_request_without_stdout_or_traceback():
    result = subprocess.run([sys.executable, "-m", "passkey_bridge.backend"], input=b"{}\n", capture_output=True, timeout=5)
    assert result.returncode == 1
    assert result.stdout == b""
    assert b"extension" in result.stderr
    assert b"Traceback" not in result.stderr


def test_backend_module_limits_input_frame():
    result = subprocess.run([sys.executable, "-m", "passkey_bridge.backend"], input=b"x" * 131073 + b"\n", capture_output=True, timeout=5)
    assert result.returncode == 1
    assert result.stdout == b""
    assert b"size" in result.stderr


def test_qr_is_only_written_to_stderr(capsys):
    backend._display_qr("FIDO:/00000000000000000")
    output = capsys.readouterr()
    assert output.out == ""
    assert output.err


@pytest.mark.asyncio
async def test_backend_rejects_invalid_assertion_from_transport(monkeypatch):
    async def hybrid(context):
        result = fixture_assertion()
        result[2] = bytes(37)
        return result
    monkeypatch.setattr(backend, "_hybrid_assertion", hybrid)
    with pytest.raises(protocol.ValidationError):
        await backend.authenticate(request(), confirm=False)


def _wait_for_output(fd, marker):
    output = bytearray()
    deadline = time.monotonic() + 5
    while marker not in output:
        remaining = deadline - time.monotonic()
        assert remaining > 0, bytes(output)
        readable, _, _ = select.select([fd], [], [], remaining)
        assert readable, bytes(output)
        chunk = os.read(fd, 4096)
        assert chunk, bytes(output)
        output.extend(chunk)
    return bytes(output)


@pytest.mark.parametrize("cancel_at", [None, "consent", "radio"])
@pytest.mark.parametrize("reject_terminal_reader", [False, True])
def test_simulated_backend_subprocess_success_and_sigterm_cleanup(cancel_at, reject_terminal_reader):
    master, slave = pty.openpty()
    source = """
import asyncio
import errno
import hashlib
import os
import sys
from passkey_bridge import backend

if sys.argv[2] == "reject_terminal_reader":
    original_add_reader = asyncio.SelectorEventLoop.add_reader
    def add_reader(self, fd, callback, *args):
        if os.isatty(fd):
            raise OSError(errno.EINVAL, "Invalid argument")
        return original_add_reader(self, fd, callback, *args)
    asyncio.SelectorEventLoop.add_reader = add_reader

async def simulated_radio(context):
    print("SIMULATED_RADIO_ACTIVE", file=sys.stderr, flush=True)
    try:
        if sys.argv[1] == "radio":
            await asyncio.Future()
        return {
            1: {"type": "public-key", "id": b"test-credential"},
            2: hashlib.sha256(context["rp_id"].encode()).digest() + b"\\x05" + bytes(4),
            3: b"fixture-only-signature",
        }
    finally:
        print("SIMULATED_RADIO_CLOSED", file=sys.stderr, flush=True)

backend._hybrid_assertion = simulated_radio
raise SystemExit(backend._main())
"""
    def controlling_terminal():
        os.setsid()
        fcntl.ioctl(slave, termios.TIOCSCTTY, 0)
    process = subprocess.Popen([sys.executable, "-c", source, cancel_at or "success",
        "reject_terminal_reader" if reject_terminal_reader else "native"],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        preexec_fn=controlling_terminal, pass_fds=(slave,))
    try:
        process.stdin.write(json.dumps(request()).encode() + b"\n")
        process.stdin.flush()
        observed = _wait_for_output(process.stderr.fileno(), b"Type yes to allow this request")
        assert b"Origin: https://login.microsoft.com" in observed
        assert b"RP ID: login.microsoft.com" in observed
        if cancel_at != "consent":
            os.write(master, b"yes\n")
            assert _wait_for_output(master, b"yes\r\n") == b"yes\r\n"
        if cancel_at == "radio":
            observed += _wait_for_output(process.stderr.fileno(), b"SIMULATED_RADIO_ACTIVE")
        if cancel_at:
            process.terminate()
        stdout, stderr = process.communicate(timeout=5)
        observed += stderr
        assert b"Traceback" not in observed
        if cancel_at:
            assert process.returncode == 130
            assert stdout == b""
            assert b"cancelled" in observed
        else:
            assert process.returncode == 0, observed
            credential = json.loads(stdout)
            assert credential["response"]["clientDataJSON"] == protocol.encode_base64url(protocol.validate_request(request())["client_data_json"])
        if cancel_at == "consent":
            assert b"SIMULATED_RADIO_ACTIVE" not in observed
        else:
            assert b"SIMULATED_RADIO_CLOSED" in observed
    finally:
        os.close(master)
        os.close(slave)
        if process.poll() is None:
            process.kill()
            process.communicate(timeout=5)
