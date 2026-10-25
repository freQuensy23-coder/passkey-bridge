import json

import pytest
from websockets.asyncio.client import connect
from websockets.asyncio.server import serve
from websockets.exceptions import ConnectionClosed

from passkey_bridge.broker import Broker


@pytest.mark.asyncio
async def test_extension_identity_must_match_even_with_valid_token():
    broker = Broker("e" * 64, "b" * 64, extension_id="a" * 32)
    async with serve(broker.handle, "127.0.0.1", 0) as server:
        port = server.sockets[0].getsockname()[1]
        async with connect(f"ws://127.0.0.1:{port}", origin="chrome-extension://" + "c" * 32) as ws:
            await ws.send(json.dumps({"type": "hello", "role": "extension", "token": "e" * 64}))
            with pytest.raises(ConnectionClosed):
                await ws.recv()
        async with connect(f"ws://127.0.0.1:{port}", origin="chrome-extension://" + "a" * 32) as ws:
            await ws.send(json.dumps({"type": "hello", "role": "extension", "token": "e" * 64}))
            assert json.loads(await ws.recv()) == {"type": "ready", "helper": False}
    await broker.close()
