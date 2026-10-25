import asyncio
import json

import pytest
from websockets.asyncio.client import connect
from websockets.asyncio.server import serve

from passkey_bridge.broker import Broker
from passkey_bridge.cli import run_client_stream


@pytest.mark.asyncio
async def test_negative_opaque_browser_id_is_preserved_end_to_end():
    broker = Broker("e" * 64, "b" * 64)
    async with serve(broker.handle, "127.0.0.1", 0) as server:
        port = server.sockets[0].getsockname()[1]
        async with connect(f"ws://127.0.0.1:{port}") as helper:
            await helper.send(json.dumps({"type": "hello", "role": "helper", "token": "b" * 64}))
            await helper.recv()
            async with connect(f"ws://127.0.0.1:{port}", origin="chrome-extension://" + "a" * 32) as ext:
                await ext.send(json.dumps({"type": "hello", "role": "extension", "token": "e" * 64}))
                await ext.recv()
                await ext.send(json.dumps({"type": "get", "id": -1756824758, "details": {}}))
                request = json.loads(await asyncio.wait_for(helper.recv(), 1))
                assert request["id"] == -1756824758
                result = {"type": "error", "id": request["id"], "error": {"name": "NotAllowedError", "message": "Declined"}}
                await helper.send(json.dumps(result))
                assert json.loads(await ext.recv()) == result
    await broker.close()


@pytest.mark.asyncio
async def test_client_preserves_negative_browser_ids():
    reader = asyncio.StreamReader()
    returned = asyncio.Event()
    messages = []

    class Writer:
        def write(self, data):
            messages.append(json.loads(data))
            returned.set()

        async def drain(self):
            return None

    async def authenticate(details):
        return {"type": "public-key"}

    reader.feed_data(b'{"type":"ready","helper":true}\n')
    reader.feed_data(b'{"type":"get","id":-5,"details":{}}\n')
    task = asyncio.create_task(run_client_stream(reader, Writer(), authenticate=authenticate))
    try:
        await asyncio.wait_for(returned.wait(), 1)
        assert messages[0]["id"] == -5
    finally:
        reader.feed_eof()
        await task
