import asyncio
import hmac
import json
import re
import time

from websockets.exceptions import ConnectionClosed


class Broker:
    def __init__(self, extension_token, helper_token, *, pairing_ttl=600, request_timeout=180,
                 extension_id=None):
        if extension_id is not None and not re.fullmatch(r"[a-p]{32}", extension_id):
            raise ValueError("Invalid extension ID")
        self.extension_id = extension_id
        self.extension_token = extension_token
        self.helper_token = helper_token
        self.pairing_deadline = time.monotonic() + pairing_ttl
        self.request_timeout = request_timeout
        self.extension = None
        self.helper = None
        self.helper_claimed = False
        self.pending = None
        self.deadline_task = None
        self.seen_ids = set()

    async def send(self, connection, message):
        if connection is not None:
            try:
                await connection.send(json.dumps(message, separators=(",", ":")))
            except ConnectionClosed:
                pass

    async def error(self, request_id, name, message):
        await self.send(self.extension, {"type": "error", "id": request_id,
                                       "error": {"name": name, "message": message}})

    async def clear_pending(self, *, cancel_helper=False):
        pending, self.pending = self.pending, None
        task, self.deadline_task = self.deadline_task, None
        if task is not None and task is not asyncio.current_task():
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)
        if pending is not None and cancel_helper:
            await self.send(self.helper, {"type": "cancel", "id": pending})
        return pending

    async def expire(self, request_id, timeout):
        await asyncio.sleep(timeout)
        if self.pending == request_id:
            await self.clear_pending(cancel_helper=True)
            await self.error(request_id, "NotAllowedError", "Authentication timed out")

    async def handle_extension(self, data):
        kind, request_id = data.get("type"), data.get("id")
        if type(request_id) is not int or not -(2**53 - 1) <= request_id <= 2**53 - 1:
            raise ValueError("Invalid request ID")
        if kind == "cancel":
            if request_id == self.pending:
                await self.clear_pending(cancel_helper=True)
            return
        if kind != "get" or not isinstance(data.get("details"), dict):
            raise ValueError("Unsupported request")
        if request_id in self.seen_ids:
            await self.error(request_id, "InvalidStateError", "Request already handled")
            return
        if len(self.seen_ids) >= 128:
            raise ValueError("Session request limit reached")
        self.seen_ids.add(request_id)
        if self.helper is None:
            await self.error(request_id, "NotAllowedError", "Local companion is disconnected")
            return
        if self.pending is not None:
            await self.error(request_id, "NotAllowedError", "Another authentication is active")
            return
        timeout_ms = data["details"].get("timeout", 180000)
        if type(timeout_ms) not in (int, float) or not 0 < timeout_ms <= 3600000:
            await self.error(request_id, "NotAllowedError", "Invalid timeout")
            return
        timeout = min(self.request_timeout, timeout_ms / 1000)
        self.pending = request_id
        self.deadline_task = asyncio.create_task(self.expire(request_id, timeout))
        await self.send(self.helper, {"type": "get", "id": request_id, "details": data["details"]})

    async def handle_helper(self, data):
        request_id, kind = data.get("id"), data.get("type")
        if type(request_id) is not int or request_id != self.pending:
            return
        if kind == "result" and isinstance(data.get("response"), dict):
            outgoing = {"type": "result", "id": request_id, "response": data["response"]}
        elif kind == "error" and isinstance(data.get("error"), dict):
            error = data["error"]
            name = error.get("name", "NotAllowedError")
            if name not in {"NotAllowedError", "SecurityError", "NotSupportedError", "AbortError", "UnknownError"}:
                name = "NotAllowedError"
            message = error.get("message", "Authentication failed")
            if not isinstance(message, str):
                message = "Authentication failed"
            outgoing = {"type": "error", "id": request_id, "error": {"name": name, "message": message[:200]}}
        else:
            raise ValueError("Invalid companion response")
        await self.clear_pending()
        await self.send(self.extension, outgoing)

    async def handle(self, connection):
        role = None
        registered = False
        try:
            raw = await asyncio.wait_for(connection.recv(), 5)
            if not isinstance(raw, str):
                raise ValueError("Text frames required")
            hello = json.loads(raw)
            if not isinstance(hello, dict) or hello.get("type") != "hello":
                raise ValueError("Handshake required")
            role, token = hello.get("role"), hello.get("token")
            if not isinstance(token, str) or len(token) != 64:
                raise ValueError("Invalid pairing")
            origin = connection.request.headers.get("Origin")
            if role == "extension":
                if not origin or not re.fullmatch(r"chrome-extension://[a-p]{32}", origin):
                    raise ValueError("Extension origin required")
                if self.extension_id is not None and origin != "chrome-extension://" + self.extension_id:
                    raise ValueError("Unpaired extension identity")
                if not hmac.compare_digest(token, self.extension_token) or self.extension is not None:
                    raise ValueError("Invalid extension pairing")
                self.extension = connection
            elif role == "helper":
                if origin is not None or self.helper_claimed or time.monotonic() >= self.pairing_deadline:
                    raise ValueError("Invalid companion pairing")
                if not hmac.compare_digest(token, self.helper_token):
                    raise ValueError("Invalid companion pairing")
                self.helper_claimed = True
                self.helper = connection
            else:
                raise ValueError("Invalid role")
            registered = True
            await self.send(connection, {"type": "ready", "helper": self.helper is not None})
            if role == "helper":
                await self.send(self.extension, {"type": "helper", "connected": True})
            async for raw in connection:
                if not isinstance(raw, str):
                    raise ValueError("Text frames required")
                data = json.loads(raw)
                if not isinstance(data, dict):
                    raise ValueError("Object required")
                if role == "extension":
                    await self.handle_extension(data)
                else:
                    await self.handle_helper(data)
        except (ValueError, TypeError, TimeoutError, KeyError):
            await connection.close(code=1008, reason="Invalid or expired bridge session")
        except ConnectionClosed:
            pass
        finally:
            if registered and role == "extension" and self.extension is connection:
                self.extension = None
                await self.clear_pending(cancel_helper=True)
            elif registered and role == "helper" and self.helper is connection:
                self.helper = None
                pending = await self.clear_pending()
                if pending is not None:
                    await self.error(pending, "NotAllowedError", "Local companion disconnected")
                await self.send(self.extension, {"type": "helper", "connected": False})

    async def close(self):
        await self.clear_pending(cancel_helper=True)
        await asyncio.gather(*(c.close() for c in (self.extension, self.helper) if c is not None))
