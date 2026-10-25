import asyncio
import errno
import os
import pty

import pytest

from passkey_bridge import backend


@pytest.mark.parametrize("answer,accepted", [(b"yes\n", True), (b"no\n", False), (b"yes \n", False)])
async def test_consent_handles_terminal_rejected_by_kqueue(monkeypatch, answer, accepted):
    master, slave = pty.openpty()
    opened = []
    loop = asyncio.get_running_loop()

    def open_terminal():
        terminal = os.dup(slave)
        opened.append(terminal)
        return terminal

    def unsupported_reader(fd, callback):
        assert fd == opened[0]
        raise OSError(errno.EINVAL, "Invalid argument")

    monkeypatch.setattr(backend, "_open_terminal", open_terminal)
    monkeypatch.setattr(loop, "add_reader", unsupported_reader)
    task = asyncio.create_task(backend._confirm({"origin": "https://example.com", "rp_id": "example.com"}))
    try:
        await asyncio.sleep(0)
        assert not task.done()
        os.write(master, answer)
        if accepted:
            await asyncio.wait_for(task, 1)
        else:
            with pytest.raises(backend.BackendError, match="consent"):
                await asyncio.wait_for(task, 1)
        with pytest.raises(OSError):
            os.fstat(opened[0])
    finally:
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)
        os.close(master)
        os.close(slave)


async def test_consent_cancelled_while_terminal_rejected_by_kqueue(monkeypatch):
    master, slave = pty.openpty()
    terminal = os.dup(slave)
    loop = asyncio.get_running_loop()

    def unsupported_reader(fd, callback):
        raise OSError(errno.EINVAL, "Invalid argument")

    monkeypatch.setattr(backend, "_open_terminal", lambda: terminal)
    monkeypatch.setattr(loop, "add_reader", unsupported_reader)
    task = asyncio.create_task(backend._confirm({"origin": "https://example.com", "rp_id": "example.com"}))
    try:
        await asyncio.sleep(0)
        assert not task.done()
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await asyncio.wait_for(task, 1)
        with pytest.raises(OSError):
            os.fstat(terminal)
    finally:
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)
        os.close(master)
        os.close(slave)


async def test_consent_fallback_flushes_stale_yes_and_times_out(monkeypatch):
    master, slave = pty.openpty()
    terminal = os.dup(slave)
    loop = asyncio.get_running_loop()

    def unsupported_reader(fd, callback):
        raise OSError(errno.EINVAL, "Invalid argument")

    monkeypatch.setattr(backend, "_open_terminal", lambda: terminal)
    monkeypatch.setattr(loop, "add_reader", unsupported_reader)
    os.write(master, b"yes\n")
    task = asyncio.create_task(backend._confirm({"origin": "https://example.com", "rp_id": "example.com"}))
    try:
        with pytest.raises(TimeoutError):
            await asyncio.wait_for(task, 0.1)
        with pytest.raises(OSError):
            os.fstat(terminal)
    finally:
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)
        os.close(master)
        os.close(slave)


async def test_consent_does_not_hide_other_reader_errors(monkeypatch, capsys):
    master, slave = pty.openpty()
    terminal = os.dup(slave)
    loop = asyncio.get_running_loop()

    def broken_reader(fd, callback):
        raise OSError(errno.EBADF, "Bad file descriptor")

    monkeypatch.setattr(backend, "_open_terminal", lambda: terminal)
    monkeypatch.setattr(loop, "add_reader", broken_reader)
    try:
        with pytest.raises(OSError) as exc:
            await backend._confirm({"origin": "https://example.com", "rp_id": "example.com"})
        assert exc.value.errno == errno.EBADF
        assert "Type yes" not in capsys.readouterr().err
        with pytest.raises(OSError):
            os.fstat(terminal)
    finally:
        os.close(master)
        os.close(slave)
