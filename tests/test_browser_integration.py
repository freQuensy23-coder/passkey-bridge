import asyncio
import base64
import hashlib
import json
import os
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from websockets.asyncio.client import connect
from websockets.asyncio.server import serve

from passkey_bridge.broker import Broker


def encode64(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


@pytest.mark.asyncio
@pytest.mark.skipif(not os.environ.get("CHROME_BIN"), reason="Explicit Chrome for Testing binary required")
async def test_real_chrome_proxy_with_software_assertion():
    broker = Broker("e" * 64, "b" * 64)
    observed = []
    request_ids = []
    original_handle_extension = broker.handle_extension

    async def record_extension_request(message):
        request_ids.append(message.get("id"))
        await original_handle_extension(message)

    broker.handle_extension = record_extension_request
    key = ec.generate_private_key(ec.SECP256R1())

    async with serve(broker.handle, "127.0.0.1", 0) as server:
        port = server.sockets[0].getsockname()[1]
        async with connect(f"ws://127.0.0.1:{port}") as helper:
            await helper.send(json.dumps({"type": "hello", "role": "helper", "token": "b" * 64}))
            assert json.loads(await helper.recv())["type"] == "ready"

            async def software_authenticator():
                request = json.loads(await helper.recv())
                assert request["type"] == "get"
                options = request["details"]
                override = options["extensions"]["remoteDesktopClientOverride"]
                assert override["sameOriginWithAncestors"] is True
                assert override["origin"].startswith("http://localhost:")
                assert options["rpId"] == "localhost"
                client = json.dumps({"type": "webauthn.get", "challenge": options["challenge"],
                                     "origin": override["origin"], "crossOrigin": False},
                                    separators=(",", ":")).encode()
                auth_data = hashlib.sha256(b"localhost").digest() + b"\x05\x00\x00\x00\x01"
                signed = auth_data + hashlib.sha256(client).digest()
                signature = key.sign(signed, ec.ECDSA(hashes.SHA256()))
                key.public_key().verify(signature, signed, ec.ECDSA(hashes.SHA256()))
                credential_id = encode64(b"software-test-credential")
                response = {"type": "public-key", "id": credential_id, "rawId": credential_id,
                            "authenticatorAttachment": "cross-platform", "clientExtensionResults": {},
                            "response": {"clientDataJSON": encode64(client),
                                         "authenticatorData": encode64(auth_data),
                                         "signature": encode64(signature)}}
                observed.append(request["id"])
                await helper.send(json.dumps({"type": "result", "id": request["id"], "response": response}))

            software = asyncio.create_task(software_authenticator())
            process = await asyncio.create_subprocess_exec(
                "node", "tests/browser-integration.mjs", env={**os.environ,
                "BRIDGE_PORT": str(port), "EXTENSION_TOKEN": "e" * 64},
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
            try:
                out, err = await asyncio.wait_for(process.communicate(), 60)
                assert process.returncode == 0, err.decode() + f"\nObserved browser request IDs: {request_ids}"
                result = json.loads(out)
                assert result["intercepted"] is True
                assert result["assertionReturned"] is True
                assert result["detached"] is True
                await asyncio.wait_for(software, 2)
                assert len(observed) == 1
            finally:
                if process.returncode is None:
                    process.kill()
                    await process.wait()
                software.cancel()
                await asyncio.gather(software, return_exceptions=True)
    await broker.close()
