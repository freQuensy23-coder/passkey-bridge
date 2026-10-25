import argparse
import asyncio
import getpass
import json
import re
import secrets
import sys
from contextlib import suppress
from pathlib import Path

from websockets.asyncio.client import connect
from websockets.asyncio.server import serve
from websockets.exceptions import ConnectionClosed

from .broker import Broker

MAX_FRAME = 131072


def ssh_command(host, port, remote_executable="~/.local/bin/passkey-bridge"):
    if not isinstance(host, str) or not re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_.@:-]{0,252}", host):
        raise ValueError("Use an SSH host alias or user@hostname without shell options")
    if type(port) is not int or not 1 <= port <= 65535:
        raise ValueError("Invalid port")
    if not isinstance(remote_executable, str) or not re.fullmatch(
            r"(?:(?:~/|/)[A-Za-z0-9_.][A-Za-z0-9_./-]*|[A-Za-z0-9_][A-Za-z0-9_.-]*)", remote_executable):
        raise ValueError("Use a remote executable name or path without shell syntax")
    return ["ssh", "-T", "-o", "StrictHostKeyChecking=yes", host,
            f"{remote_executable} relay --port {port}"]


def encode(message):
    data = json.dumps(message, separators=(",", ":")).encode() + b"\n"
    if len(data) > MAX_FRAME:
        raise ValueError("Bridge frame is too large")
    return data


async def stop_process(process):
    if process.returncode is None:
        with suppress(ProcessLookupError):
            process.terminate()
        try:
            await asyncio.wait_for(process.wait(), 2)
        except TimeoutError:
            with suppress(ProcessLookupError):
                process.kill()
            await process.wait()


async def backend_request(details):
    process = await asyncio.create_subprocess_exec(
        sys.executable, "-m", "passkey_bridge.backend", stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE)
    try:
        stdout, _ = await asyncio.wait_for(process.communicate(encode(details)), 190)
        if process.returncode != 0:
            raise RuntimeError("Local authenticator declined or failed; see local terminal")
        if len(stdout) > MAX_FRAME:
            raise ValueError("Authenticator response too large")
        result = json.loads(stdout)
        if not isinstance(result, dict):
            raise ValueError("Invalid authenticator response")
        return result
    finally:
        await stop_process(process)


async def run_client_stream(reader, writer, *, authenticate=backend_request):
    active = None
    active_id = None
    paired = False

    async def send(message):
        writer.write(encode(message))
        await writer.drain()

    async def perform(request_id, details):
        try:
            response = await authenticate(details)
            await send({"type": "result", "id": request_id, "response": response})
        except asyncio.CancelledError:
            raise
        except Exception:
            await send({"type": "error", "id": request_id,
                        "error": {"name": "NotAllowedError", "message": "Local authentication declined or failed"}})

    try:
        while line := await reader.readline():
            if len(line) > MAX_FRAME:
                raise ValueError("Bridge frame too large")
            message = json.loads(line)
            if not isinstance(message, dict):
                raise ValueError("Invalid bridge frame")
            if message.get("type") == "ready":
                if paired or message.get("helper") is not True:
                    raise ValueError("Invalid pairing acknowledgement")
                paired = True
                print("Paired. Waiting for an approved sign-in request.", file=sys.stderr)
                continue
            if not paired:
                raise ValueError("Pairing acknowledgement required")
            request_id = message.get("id")
            if type(request_id) is not int or not -(2**53 - 1) <= request_id <= 2**53 - 1:
                raise ValueError("Invalid request ID")
            if message.get("type") == "cancel":
                if active is not None and request_id == active_id:
                    active.cancel()
                    await asyncio.gather(active, return_exceptions=True)
                    active = None
                    active_id = None
                    print("Authentication canceled.", file=sys.stderr)
            elif message.get("type") == "get" and isinstance(message.get("details"), dict):
                if active is not None and not active.done():
                    raise ValueError("Concurrent sign-in refused")
                active_id = request_id
                active = asyncio.create_task(perform(request_id, message["details"]))
            else:
                raise ValueError("Unsupported bridge frame")
    finally:
        if active is not None:
            active.cancel()
            await asyncio.gather(active, return_exceptions=True)


async def client(args):
    command = ssh_command(args.host, args.port, args.remote_executable)
    token = args.code if args.code is not None else getpass.getpass("Pairing code: ")
    if not re.fullmatch(r"[0-9a-f]{64}", token):
        raise ValueError("Invalid pairing code")
    process = await asyncio.create_subprocess_exec(
        *command, stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE, limit=MAX_FRAME)
    try:
        process.stdin.write(encode({"token": token}))
        await process.stdin.drain()
        await run_client_stream(process.stdout, process.stdin)
        code = await process.wait()
        if code != 0:
            raise RuntimeError("SSH relay failed; verify the host key and remote installation")
    finally:
        await stop_process(process)


async def relay(args):
    loop = asyncio.get_running_loop()
    reader = asyncio.StreamReader(limit=MAX_FRAME)
    protocol = asyncio.StreamReaderProtocol(reader)
    transport, _ = await loop.connect_read_pipe(lambda: protocol, sys.stdin.buffer)
    try:
        line = await asyncio.wait_for(reader.readline(), 15)
        if len(line) > MAX_FRAME:
            raise ValueError("Bridge frame too large")
        hello = json.loads(line)
        token = hello.get("token") if isinstance(hello, dict) else None
        if not isinstance(token, str) or not re.fullmatch(r"[0-9a-f]{64}", token):
            raise ValueError("Invalid pairing code")
        async with connect(f"ws://127.0.0.1:{args.port}", max_size=MAX_FRAME,
                           compression=None, proxy=None) as connection:
            await connection.send(json.dumps({"type": "hello", "role": "helper", "token": token}))
            first = await asyncio.wait_for(connection.recv(), 5)
            ready = json.loads(first)
            if ready != {"type": "ready", "helper": True}:
                raise ValueError("Pairing failed")
            sys.stdout.buffer.write(encode(ready))
            sys.stdout.buffer.flush()

            async def upload():
                while line := await reader.readline():
                    if len(line) > MAX_FRAME:
                        raise ValueError("Bridge frame too large")
                    message = json.loads(line)
                    await connection.send(json.dumps(message))

            async def download():
                async for raw in connection:
                    message = json.loads(raw)
                    sys.stdout.buffer.write(encode(message))
                    sys.stdout.buffer.flush()

            tasks = [asyncio.create_task(upload()), asyncio.create_task(download())]
            try:
                done, _ = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
                for task in done:
                    task.result()
            finally:
                for task in tasks:
                    task.cancel()
                await asyncio.gather(*tasks, return_exceptions=True)
    finally:
        transport.close()


async def server(args):
    extension_token, helper_token = secrets.token_hex(32), secrets.token_hex(32)
    broker = Broker(extension_token, helper_token, extension_id=args.extension_id)
    async with serve(broker.handle, "127.0.0.1", args.port, max_size=MAX_FRAME,
                     compression=None) as listener:
        port = listener.sockets[0].getsockname()[1]
        print(f"Bridge listening on 127.0.0.1:{port}")
        print(f"Extension port: {port}")
        print(f"Extension session token: {extension_token}")
        print(f"On your Mac: passkey-bridge connect SSH_HOST --port {port}")
        print(f"One-use pairing code (expires in 10 minutes): {helper_token}")
        print(f"Session ends after {args.duration} seconds. Only pair your own trusted server.", flush=True)
        try:
            await asyncio.sleep(args.duration)
        finally:
            await broker.close()


def main():
    parser = argparse.ArgumentParser(description="Pair a trusted remote browser with your local phone passkey")
    subparsers = parser.add_subparsers(dest="command", required=True)
    serve_parser = subparsers.add_parser("serve")
    serve_parser.add_argument("--port", type=int, default=0)
    serve_parser.add_argument("--extension-id", required=True)
    serve_parser.add_argument("--duration", type=int, default=900)
    connect_parser = subparsers.add_parser("connect")
    connect_parser.add_argument("host")
    connect_parser.add_argument("--port", type=int, required=True)
    connect_parser.add_argument("--code", help="One-use code; omit for a hidden prompt")
    connect_parser.add_argument("--remote-executable", default="~/.local/bin/passkey-bridge")
    relay_parser = subparsers.add_parser("relay")
    relay_parser.add_argument("--port", type=int, required=True)
    subparsers.add_parser("extension-path")
    args = parser.parse_args()
    if args.command == "extension-path":
        packaged = Path(__file__).resolve().parent / "extension"
        source = Path(__file__).resolve().parents[2] / "extension"
        print(packaged if packaged.is_dir() else source)
        return 0
    if not 0 <= args.port <= 65535 or (args.command != "serve" and args.port == 0):
        parser.error("Invalid port")
    if args.command == "serve" and not 15 <= args.duration <= 3600:
        parser.error("Session duration must be 15 to 3600 seconds")
    try:
        asyncio.run({"serve": server, "connect": client, "relay": relay}[args.command](args))
        return 0
    except KeyboardInterrupt:
        return 0
    except (ValueError, RuntimeError, OSError, ConnectionClosed, TimeoutError):
        print("Bridge stopped: pairing, transport, or local authentication failed.", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
