import asyncio
import json

import pytest
from websockets.asyncio.client import connect
from websockets.asyncio.server import serve
from websockets.exceptions import ConnectionClosed

from passkey_bridge.broker import Broker


@pytest.fixture
async def running():
    broker = Broker("e" * 64, "h" * 64, request_timeout=0.15)
    async with serve(broker.handle, "127.0.0.1", 0, max_size=131072) as server:
        port = server.sockets[0].getsockname()[1]
        yield broker, f"ws://127.0.0.1:{port}"
    await broker.close()


async def peer(url, role, token):
    origin = "chrome-extension://" + "a" * 32 if role == "extension" else None
    ws = await connect(url, origin=origin)
    await ws.send(json.dumps({"type": "hello", "role": role, "token": token}))
    return ws


async def receive(ws):
    return json.loads(await asyncio.wait_for(ws.recv(), 2))


@pytest.mark.asyncio
async def test_authentication_rejects_wrong_token(running):
    _, url = running
    async with await peer(url, "extension", "wrong") as ws:
        with pytest.raises(ConnectionClosed):
            await ws.recv()


@pytest.mark.asyncio
async def test_web_origin_cannot_use_helper_token(running):
    _, url = running
    async with connect(url, origin="https://evil.example") as ws:
        await ws.send(json.dumps({"type": "hello", "role": "helper", "token": "h" * 64}))
        with pytest.raises(ConnectionClosed):
            await ws.recv()


@pytest.mark.asyncio
async def test_roundtrip_and_pairing_code_is_single_use(running):
    _, url = running
    async with await peer(url, "extension", "e" * 64) as ext:
        assert await receive(ext) == {"type": "ready", "helper": False}
        async with await peer(url, "helper", "h" * 64) as helper:
            assert await receive(helper) == {"type": "ready", "helper": True}
            assert await receive(ext) == {"type": "helper", "connected": True}
            request = {"type": "get", "id": 7, "details": {"challenge": "test fixture"}}
            await ext.send(json.dumps(request))
            assert await receive(helper) == request
            result = {"type": "result", "id": 7, "response": {"type": "public-key"}}
            await helper.send(json.dumps(result))
            assert await receive(ext) == result
            await ext.send(json.dumps(request))
            assert (await receive(ext))["type"] == "error"
        assert await receive(ext) == {"type": "helper", "connected": False}
        async with await peer(url, "helper", "h" * 64) as rejected:
            with pytest.raises(ConnectionClosed):
                await rejected.recv()


@pytest.mark.asyncio
async def test_timeout_cancels_helper(running):
    _, url = running
    async with await peer(url, "helper", "h" * 64) as helper:
        await receive(helper)
        async with await peer(url, "extension", "e" * 64) as ext:
            await receive(ext)
            await ext.send(json.dumps({"type": "get", "id": 1, "details": {}}))
            assert (await receive(helper))["type"] == "get"
            assert await receive(helper) == {"type": "cancel", "id": 1}
            assert (await receive(ext))["error"]["name"] == "NotAllowedError"


@pytest.mark.asyncio
async def test_cancel_discards_late_response(running):
    _, url = running
    async with await peer(url, "helper", "h" * 64) as helper:
        await receive(helper)
        async with await peer(url, "extension", "e" * 64) as ext:
            await receive(ext)
            await ext.send(json.dumps({"type": "get", "id": 5, "details": {}}))
            await receive(helper)
            await ext.send(json.dumps({"type": "cancel", "id": 5}))
            assert await receive(helper) == {"type": "cancel", "id": 5}
            await helper.send(json.dumps({"type": "result", "id": 5, "response": {}}))
            await ext.send(json.dumps({"type": "get", "id": 6, "details": {}}))
            assert (await receive(helper))["id"] == 6
            await helper.send(json.dumps({"type": "error", "id": 6, "error": {"name": "NotAllowedError", "message": "Declined"}}))
            assert (await receive(ext))["id"] == 6


@pytest.mark.asyncio
async def test_expired_pairing_rejected(running):
    broker, url = running
    broker.pairing_deadline = 0
    async with await peer(url, "helper", "h" * 64) as ws:
        with pytest.raises(ConnectionClosed):
            await ws.recv()


@pytest.mark.asyncio
async def test_second_helper_and_extension_do_not_replace_peers(running):
    _, url = running
    async with await peer(url, "helper", "h" * 64) as helper:
        await receive(helper)
        async with await peer(url, "extension", "e" * 64) as ext:
            await receive(ext)
            async with await peer(url, "extension", "e" * 64) as duplicate:
                with pytest.raises(ConnectionClosed):
                    await duplicate.recv()
            await ext.send(json.dumps({"type": "get", "id": 99, "details": {}}))
            assert (await receive(helper))["id"] == 99
