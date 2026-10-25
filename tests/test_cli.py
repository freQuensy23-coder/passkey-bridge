import asyncio
import json
import os
import sys

import pytest
from websockets.asyncio.client import connect
from websockets.asyncio.server import serve

from passkey_bridge.broker import Broker
from passkey_bridge.cli import ssh_command


@pytest.mark.parametrize("host", ["-oProxyCommand=evil", "user@host;id", "host name", "$(id)", "", "user@host\n"])
def test_ssh_rejects_shell_and_option_injection(host):
    with pytest.raises(ValueError):
        ssh_command(host, 8765)


def test_ssh_requires_existing_host_key():
    command = ssh_command("user@example.org", 8765)
    assert command == ["ssh", "-T", "-o", "StrictHostKeyChecking=yes", "user@example.org",
                       "~/.local/bin/passkey-bridge relay --port 8765"]


@pytest.mark.asyncio
async def test_real_stdio_relay_network_roundtrip():
    broker = Broker("e" * 64, "b" * 64)
    async with serve(broker.handle, "127.0.0.1", 0) as server:
        port = server.sockets[0].getsockname()[1]
        process = await asyncio.create_subprocess_exec(
            sys.executable, "-m", "passkey_bridge.cli", "relay", "--port", str(port),
            stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE, env=os.environ.copy())
        try:
            process.stdin.write((json.dumps({"token": "b" * 64}) + "\n").encode())
            await process.stdin.drain()
            ready = json.loads(await asyncio.wait_for(process.stdout.readline(), 3))
            assert ready == {"type": "ready", "helper": True}
            async with connect(f"ws://127.0.0.1:{port}", origin="chrome-extension://" + "a" * 32) as ext:
                await ext.send(json.dumps({"type": "hello", "role": "extension", "token": "e" * 64}))
                assert json.loads(await ext.recv())["helper"] is True
                await ext.send(json.dumps({"type": "get", "id": 2, "details": {"challenge": "fixture"}}))
                forwarded = json.loads(await asyncio.wait_for(process.stdout.readline(), 3))
                assert forwarded["id"] == 2
                response = {"type": "result", "id": 2, "response": {"type": "public-key", "id": "fixture"}}
                process.stdin.write((json.dumps(response) + "\n").encode())
                await process.stdin.drain()
                assert json.loads(await asyncio.wait_for(ext.recv(), 3)) == response
                await broker.close()
            assert await asyncio.wait_for(process.wait(), 3) == 0
        finally:
            if process.returncode is None:
                process.kill()
                await process.wait()


@pytest.mark.asyncio
async def test_relay_bad_pairing_exits_without_echoing_secret():
    broker = Broker("e" * 64, "b" * 64)
    async with serve(broker.handle, "127.0.0.1", 0) as server:
        port = server.sockets[0].getsockname()[1]
        process = await asyncio.create_subprocess_exec(
            sys.executable, "-m", "passkey_bridge.cli", "relay", "--port", str(port),
            stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE)
        out, err = await asyncio.wait_for(process.communicate(json.dumps({"token": "wrong"}).encode() + b"\n"), 3)
        assert process.returncode != 0
        assert b"wrong" not in out + err
