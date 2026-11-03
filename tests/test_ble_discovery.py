import asyncio
from types import SimpleNamespace

import pytest

from passkey_bridge import backend
from test_hybrid import advert


@pytest.mark.parametrize("suffix", [b"", b"\xa1\x00\x00", bytes(range(100))])
def test_tunnel_discovery_authenticates_eid_prefix_and_ignores_suffix(suffix):
    secret = bytes(range(16))
    eid = b"\x00" + bytes(range(10)) + b"abc" + b"\x00\x00"
    payload = advert(secret, eid)
    key = backend._derive(secret, 1)
    assert backend._decrypt_eid(key, payload + suffix) == eid
    tampered = bytes([payload[0] ^ 1]) + payload[1:] + suffix
    assert backend._decrypt_eid(key, tampered) is None


async def test_phone_service_data_without_advertised_service_list_is_discovered(monkeypatch, capsys):
    secret = bytes(range(16))
    eid = b"\x00" + bytes(range(10)) + b"abc" + b"\x00\x00"
    payload = advert(secret, eid)
    closed = []

    class Scanner:
        def __init__(self, **kwargs):
            self.service_filter = kwargs.get("service_uuids")

        async def start(self):
            pass

        async def stop(self):
            closed.append(True)

        async def advertisement_data(self):
            if self.service_filter:
                # This is Bleak's behavior when service_uuids is empty even
                # though the corresponding service_data key is present.
                await asyncio.Future()
            for uuid, raw in [
                ("0000180f-0000-1000-8000-00805f9b34fb", payload),
                (backend.SERVICE_UUIDS[0], bytes(20)),
                (backend.SERVICE_UUIDS[0], payload + b"\xa1\x00\x00"),
            ]:
                yield None, SimpleNamespace(service_uuids=[], service_data={uuid: raw})

    monkeypatch.setenv("PASSKEY_BRIDGE_DEBUG", "1")
    monkeypatch.setattr(backend, "BleakScanner", Scanner)
    assert await asyncio.wait_for(backend._scan_eid(backend._derive(secret, 1)), 0.5) == eid
    assert closed == [True]
    output = capsys.readouterr()
    assert output.out == ""
    assert "Matching authenticated phone Bluetooth advertisement received" in output.err
    assert "hybrid advertisements received: 2" in output.err
    assert payload.hex() not in output.err and secret.hex() not in output.err
