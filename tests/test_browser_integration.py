import asyncio
import base64
import hashlib
import json
import os

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from websockets.asyncio.client import connect
from websockets.asyncio.server import serve

from passkey_bridge.broker import Broker
from passkey_bridge.protocol import validate_assertion


def encode64(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


@pytest.mark.asyncio
@pytest.mark.skipif(os.environ.get("PASSKEY_BROWSER_TEST") != "1", reason="Dedicated Chrome for Testing integration job")
@pytest.mark.parametrize("include_user_handle,reject_null_response", [(False, False), (True, False), (False, True)])
async def test_real_chrome_proxy_with_localhost_assertion_serializer_fixture(include_user_handle, reject_null_response):
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

            async def software_assertion(invalid_null=False):
                request = json.loads(await helper.recv())
                assert request["type"] == "get"
                options = request["details"]
                override = options["extensions"]["remoteDesktopClientOverride"]
                assert override["sameOriginWithAncestors"] is True
                assert override["origin"].startswith("http://localhost:")
                assert options["rpId"] == "localhost"
                credential_id = b"software-test-credential"
                assert len(options["allowCredentials"]) == 1
                assert options["allowCredentials"][0]["type"] == "public-key"
                assert options["allowCredentials"][0]["id"] == encode64(credential_id)
                client = json.dumps({"type": "webauthn.get", "challenge": options["challenge"],
                                     "origin": override["origin"], "crossOrigin": False},
                                    separators=(",", ":")).encode()
                localhost_serializer_fixture_context = {
                    "rp_id": options["rpId"], "user_verification": options["userVerification"],
                    "allow_credentials": [{"type": "public-key", "id": credential_id}],
                    "client_data_json": client,
                }
                auth_data = hashlib.sha256(b"localhost").digest() + b"\x05\x00\x00\x00\x01"
                signed = auth_data + hashlib.sha256(client).digest()
                signature = key.sign(signed, ec.ECDSA(hashes.SHA256()))
                key.public_key().verify(signature, signed, ec.ECDSA(hashes.SHA256()))
                ctap_assertion = {
                    1: {"type": "public-key", "id": credential_id},
                    2: auth_data, 3: signature,
                }
                if include_user_handle:
                    ctap_assertion[4] = {"id": b"software-test-user"}
                response = validate_assertion(localhost_serializer_fixture_context, ctap_assertion)
                assert response["response"]["clientDataJSON"] == encode64(client)
                if invalid_null:
                    response["response"]["userHandle"] = None
                observed.append(response)
                await helper.send(json.dumps({"type": "result", "id": request["id"], "response": response}))

            async def software_authenticator():
                if reject_null_response:
                    await software_assertion(invalid_null=True)
                await software_assertion()

            software = asyncio.create_task(software_authenticator())
            process = await asyncio.create_subprocess_exec(
                "node", "tests/browser-integration.mjs", env={**os.environ,
                "BRIDGE_PORT": str(port), "EXTENSION_TOKEN": "e" * 64,
                "INCLUDE_USER_HANDLE": "1" if include_user_handle else "0",
                "REJECT_NULL_RESPONSE": "1" if reject_null_response else "0"},
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
            try:
                await asyncio.wait_for(asyncio.shield(software), 45)
                out, err = await asyncio.wait_for(process.communicate(), 30)
                assert process.returncode == 0, err.decode() + f"\nObserved browser request IDs: {request_ids}"
                result = json.loads(out)
                assert result["intercepted"] is True
                assert result["assertionReturned"] is True
                assert result["detached"] is True
                assert result["rejectionResolved"] is reject_null_response
                await asyncio.wait_for(software, 2)
                assert len(observed) == (2 if reject_null_response else 1)
                if include_user_handle:
                    assert observed[-1]["response"]["userHandle"] == encode64(b"software-test-user")
                else:
                    assert "userHandle" not in observed[-1]["response"]
            finally:
                if process.returncode is None:
                    process.kill()
                    await process.wait()
                software.cancel()
                await asyncio.gather(software, return_exceptions=True)
    await broker.close()
