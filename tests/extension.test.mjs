import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { test } from 'node:test';
import vm from 'node:vm';

const root = new URL('../extension/', import.meta.url);
const copy = value => JSON.parse(JSON.stringify(value));
const tick = async () => {
  for (let index = 0; index < 16; index += 1) await Promise.resolve();
  await new Promise(resolve => setImmediate(resolve));
};

function event() {
  const listeners = [];
  return {
    addListener(listener) { listeners.push(listener); },
    emit(...args) { return listeners.map(listener => listener(...args)); }
  };
}

async function harness({ saved, delayedAttach = false, attachError, attachResult, delayedDetach = false, detachError, socketError, sendError, completionError } = {}) {
  const calls = { attach: 0, detach: 0, get: [], create: [], uvpaa: [], logs: [] };
  const storage = saved ? { bridgeConnection: copy(saved) } : {};
  const timers = new Map();
  const attachResolvers = [];
  const detachResolvers = [];
  let timerId = 0;
  const proxy = {
    onGetRequest: event(), onCreateRequest: event(), onRequestCanceled: event(), onIsUvpaaRequest: event(),
    async attach() {
      calls.attach += 1;
      if (delayedAttach) await new Promise(resolve => attachResolvers.push(resolve));
      if (attachError) throw new Error(attachError);
      return attachResult;
    },
    async detach() {
      calls.detach += 1;
      if (delayedDetach && calls.detach > 1) await new Promise(resolve => detachResolvers.push(resolve));
      if (detachError && calls.detach > 1) throw new Error(detachError);
    },
    async completeGetRequest(details) {
      calls.get.push(copy(details));
      if (typeof completionError === 'function') return await completionError(details, calls.get.length);
      if (completionError) throw new Error(completionError);
    },
    async completeCreateRequest(details) { calls.create.push(copy(details)); },
    async completeIsUvpaaRequest(details) { calls.uvpaa.push(copy(details)); }
  };
  const chrome = {
    webAuthenticationProxy: proxy,
    storage: {
      session: {
        async get() { return copy(storage); },
        async set(values) { Object.assign(storage, copy(values)); },
        async remove(key) { delete storage[key]; }
      },
      local: new Proxy({}, { get() { throw new Error('persistent storage forbidden'); } }),
      sync: new Proxy({}, { get() { throw new Error('sync storage forbidden'); } })
    },
    runtime: { id: 'test-extension', onMessage: event(), getURL: path => `chrome-extension://test-extension/${path}` }
  };
  const sockets = [];
  class Socket {
    static OPEN = 1;
    static CONNECTING = 0;
    constructor(url) {
      if (socketError) throw new Error(socketError);
      this.url = url;
      this.readyState = 0;
      this.sent = [];
      this.closed = false;
      this.listeners = {};
      sockets.push(this);
    }
    addEventListener(name, listener) { (this.listeners[name] ??= []).push(listener); }
    emit(name, value = {}) {
      this[`on${name}`]?.(value);
      for (const listener of this.listeners[name] ?? []) listener(value);
    }
    open() { this.readyState = 1; this.emit('open'); }
    send(data) {
      if (this.readyState !== 1) throw new Error('socket not open');
      if (sendError) throw new Error(sendError);
      this.sent.push(JSON.parse(data));
    }
    receive(data) { this.emit('message', { data: typeof data === 'string' ? data : JSON.stringify(data) }); }
    close() { this.closed = true; this.readyState = 3; this.emit('close'); }
  }
  const source = await readFile(new URL('worker.js', root), 'utf8');
  vm.runInNewContext(source, {
    chrome, WebSocket: Socket, TextEncoder,
    setTimeout(callback, delay) { const id = ++timerId; timers.set(id, { callback, delay }); return id; },
    clearTimeout(id) { timers.delete(id); },
    console: new Proxy({}, { get: () => (...args) => calls.logs.push(args) })
  }, { filename: 'worker.js' });
  await tick();
  async function message(value, sender = { id: chrome.runtime.id, url: chrome.runtime.getURL('options.html') }) {
    return await new Promise((resolve, reject) => {
      const results = chrome.runtime.onMessage.emit(value, sender, result => resolve(copy(result)));
      if (!results.some(result => result === true)) reject(new Error('message not handled asynchronously'));
    });
  }
  async function connect(port = 48123, token = 'ephemeral-test-token') {
    const response = await message({ type: 'connect', port, token });
    assert.equal(response.ok, true);
    await tick();
    return sockets.at(-1);
  }
  async function ready() {
    const socket = await connect();
    socket.open();
    socket.receive({ type: 'ready', helper: true });
    await tick();
    return socket;
  }
  return { calls, storage, proxy, sockets, timers, message, connect, ready,
    resolveAttach: () => attachResolvers.shift()?.(), resolveDetach: () => detachResolvers.shift()?.() };
}

const details = { challenge: 'unchanged-challenge', rpId: 'login.example.com', extensions: { remoteDesktopClientOverride: { origin: 'https://login.example.com', sameOriginWithAncestors: true } } };
const credential = { id: 'credential-id', rawId: 'credential-id', type: 'public-key', response: { clientDataJSON: 'unchanged-client-data', authenticatorData: 'unchanged-auth-data', signature: 'unchanged-signature', userHandle: null }, clientExtensionResults: {} };
const get = (h, id = 17, value = details) => h.proxy.onGetRequest.emit({ requestId: id, requestDetailsJson: JSON.stringify(value) });

test('manifest declares Chrome 115 MV3, narrow loopback permission, and local UI', async () => {
  const manifest = JSON.parse(await readFile(new URL('manifest.json', root), 'utf8'));
  assert.equal(manifest.manifest_version, 3);
  assert.equal(manifest.minimum_chrome_version, '115');
  assert.deepEqual(manifest.permissions.sort(), ['storage', 'webAuthenticationProxy']);
  assert.deepEqual(manifest.host_permissions, ['http://127.0.0.1/*']);
  assert.equal(manifest.background.service_worker, 'worker.js');
  assert.equal(manifest.options_ui.page, 'options.html');
  assert.equal(manifest.action.default_popup, 'options.html');
  assert.equal(manifest.content_scripts, undefined);
  assert.equal(manifest.externally_connectable, undefined);
});

test('authenticates with exact hello and waits for an authenticated helper before attaching', async () => {
  const h = await harness();
  const socket = await h.connect();
  assert.equal(socket.url, 'ws://127.0.0.1:48123');
  assert.equal(h.calls.attach, 0);
  socket.open();
  assert.deepEqual(socket.sent, [{ type: 'hello', role: 'extension', token: 'ephemeral-test-token' }]);
  assert.equal(h.calls.attach, 0);
  socket.receive({ type: 'ready', helper: false });
  await tick();
  assert.equal(h.calls.attach, 0);
  socket.receive({ type: 'helper', connected: true });
  await tick();
  assert.equal(h.calls.attach, 1);
  const response = await h.message({ type: 'status' });
  assert.equal(response.status.attached, true);
  assert.equal(response.status.helper, true);
  assert.equal(JSON.stringify(response).includes('ephemeral-test-token'), false);
});

test('maps original assertion JSON without altering client data and ignores replayed results', async () => {
  const h = await harness();
  const socket = await h.ready();
  get(h);
  assert.deepEqual(socket.sent.at(-1), { type: 'get', id: 17, details });
  socket.receive({ type: 'result', id: 18, response: credential });
  assert.equal(h.calls.get.length, 0);
  socket.receive({ type: 'result', id: 17, response: credential });
  await tick();
  assert.deepEqual(h.calls.get, [{ requestId: 17, responseJson: JSON.stringify(credential) }]);
  socket.receive({ type: 'result', id: 17, response: credential });
  await tick();
  assert.equal(h.calls.get.length, 1);
});

test('sanitizes remote errors instead of leaking messages or arbitrary exception names', async () => {
  const h = await harness();
  const socket = await h.ready();
  get(h);
  socket.receive({ type: 'error', id: 17, error: { name: 'NotAllowedError', message: 'secret-token credential private payload' } });
  await tick();
  assert.equal(h.calls.get[0].error.name, 'NotAllowedError');
  assert.equal(JSON.stringify(h.calls).includes('secret-token'), false);
  get(h, 18);
  socket.receive({ type: 'error', id: 18, error: { name: 'private-token', message: 'private-token' } });
  await tick();
  assert.equal(h.calls.get[1].error.name, 'UnknownError');
  assert.equal(JSON.stringify(h.calls).includes('private-token'), false);
});

test('rejects registration locally and answers platform authenticator availability false', async () => {
  const h = await harness();
  const socket = await h.ready();
  h.proxy.onCreateRequest.emit({ requestId: 31, requestDetailsJson: '{}' });
  h.proxy.onIsUvpaaRequest.emit({ requestId: 32 });
  await tick();
  assert.equal(h.calls.create[0].requestId, 31);
  assert.equal(h.calls.create[0].error.name, 'NotSupportedError');
  assert.deepEqual(h.calls.uvpaa, [{ requestId: 32, isUvpaa: false }]);
  assert.deepEqual(socket.sent.map(value => value.type), ['hello']);
});

test('bounds requests to one and only cancels the exact active ID', async () => {
  const h = await harness();
  const socket = await h.ready();
  get(h);
  get(h, 18);
  await tick();
  assert.equal(socket.sent.filter(value => value.type === 'get').length, 1);
  assert.equal(h.calls.get[0].requestId, 18);
  assert.equal(h.calls.get[0].error.name, 'NotAllowedError');
  h.proxy.onRequestCanceled.emit(99);
  assert.equal(socket.sent.some(value => value.type === 'cancel'), false);
  h.proxy.onRequestCanceled.emit(17);
  assert.deepEqual(socket.sent.at(-1), { type: 'cancel', id: 17 });
  socket.receive({ type: 'result', id: 17, response: credential });
  await tick();
  assert.equal(h.calls.get.length, 1);
  get(h, 19);
  assert.deepEqual(socket.sent.at(-1), { type: 'get', id: 19, details });
});

test('disconnect fails pending work, detaches, clears session token, and ignores old socket events', async () => {
  const h = await harness();
  const socket = await h.ready();
  get(h);
  const baseline = h.calls.detach;
  const response = await h.message({ type: 'disconnect' });
  await tick();
  assert.equal(response.ok, true);
  assert.equal(response.status.attached, false);
  assert.equal(socket.closed, true);
  assert.equal(h.calls.detach, baseline + 1);
  assert.deepEqual(h.storage, {});
  assert.equal(h.calls.get[0].error.name, 'AbortError');
  socket.receive({ type: 'result', id: 17, response: credential });
  socket.receive({ type: 'helper', connected: true });
  await tick();
  assert.equal(h.calls.get.length, 1);
  assert.equal(h.calls.attach, 1);
});

test('socket close or error fails pending work and detaches without exposing close reasons', async () => {
  for (const kind of ['close', 'error']) {
    const h = await harness();
    const socket = await h.ready();
    get(h);
    const baseline = h.calls.detach;
    socket.emit(kind, { reason: 'secret-token' });
    await tick();
    assert.equal(h.calls.detach, baseline + 1);
    assert.equal(h.calls.get[0].error.name, 'AbortError');
    assert.equal((await h.message({ type: 'status' })).status.attached, false);
    assert.equal(JSON.stringify(h.calls).includes('secret-token'), false);
  }
});

test('helper loss fails pending requests and detaches until helper returns', async () => {
  const h = await harness();
  const socket = await h.ready();
  get(h);
  const baseline = h.calls.detach;
  socket.receive({ type: 'helper', connected: false });
  await tick();
  assert.equal(h.calls.detach, baseline + 1);
  assert.equal(h.calls.get[0].error.name, 'AbortError');
  get(h, 18);
  await tick();
  assert.equal(h.calls.get[1].error.name, 'NotAllowedError');
  socket.receive({ type: 'helper', connected: true });
  await tick();
  assert.equal(h.calls.attach, 2);
});

test('a delayed attach is detached after socket closure instead of resurrecting the proxy', async () => {
  const h = await harness({ delayedAttach: true });
  const socket = await h.ready();
  const baseline = h.calls.detach;
  socket.close();
  h.resolveAttach();
  await tick();
  assert.equal(h.calls.detach, baseline + 1);
  assert.equal((await h.message({ type: 'status' })).status.attached, false);
});

test('helper loss during attach forces stale attachment cleanup before reattachment', async () => {
  const h = await harness({ delayedAttach: true });
  const socket = await h.ready();
  const baseline = h.calls.detach;
  socket.receive({ type: 'helper', connected: false });
  socket.receive({ type: 'helper', connected: true });
  h.resolveAttach();
  await tick();
  assert.equal(h.calls.detach, baseline + 1);
  assert.equal(h.calls.attach, 2);
  h.resolveAttach();
  await tick();
  assert.equal((await h.message({ type: 'status' })).status.attached, true);
});

test('replacement connection cannot be detached or completed by stale socket events', async () => {
  const h = await harness();
  const first = await h.ready();
  const second = await h.connect(48124, 'replacement-token');
  second.open();
  second.receive({ type: 'ready', helper: true });
  await tick();
  get(h, 88);
  const baseline = h.calls.detach;
  first.emit('close');
  first.receive({ type: 'result', id: 88, response: credential });
  await tick();
  assert.equal(h.calls.detach, baseline);
  assert.equal(h.calls.get.length, 0);
  second.receive({ type: 'result', id: 88, response: credential });
  await tick();
  assert.equal(h.calls.get.length, 1);
});

test('rejects unauthenticated helper frames, rejected auth, malformed frames, and duplicate ready', async () => {
  for (const frames of [
    [{ type: 'helper', connected: true }],
    [{ type: 'error', error: { name: 'SecurityError', message: 'private-token' } }],
    ['not-json'],
    [{ type: 'ready', helper: 'true' }],
    [{ type: 'ready', helper: false }, { type: 'ready', helper: true }]
  ]) {
    const h = await harness();
    const socket = await h.connect();
    socket.open();
    for (const frame of frames) socket.receive(frame);
    await tick();
    assert.equal(h.calls.attach, 0);
    assert.equal(socket.closed, true);
    assert.equal((await h.message({ type: 'status' })).status.attached, false);
  }
});

test('rejects malformed request JSON and malformed result without forwarding it', async () => {
  const h = await harness();
  const socket = await h.ready();
  h.proxy.onGetRequest.emit({ requestId: 9, requestDetailsJson: 'not-json' });
  await tick();
  assert.equal(h.calls.get[0].error.name, 'DataError');
  assert.equal(socket.sent.length, 1);
  get(h);
  socket.receive({ type: 'result', id: 17, response: null });
  await tick();
  assert.equal(h.calls.get[1].error.name, 'AbortError');
  assert.equal(socket.closed, true);
});

test('only stores ephemeral connection settings and restores worker sessions after a startup detach', async () => {
  const h = await harness({ saved: { port: 48123, token: 'restored-token' } });
  assert.equal(h.calls.detach, 1);
  assert.equal(h.sockets.length, 1);
  const socket = h.sockets[0];
  socket.open();
  assert.deepEqual(socket.sent[0], { type: 'hello', role: 'extension', token: 'restored-token' });
  assert.equal(h.calls.attach, 0);
  socket.receive({ type: 'ready', helper: true });
  await tick();
  assert.equal(h.calls.attach, 1);
  await h.message({ type: 'disconnect' });
  assert.deepEqual(h.storage, {});
  await h.connect();
  assert.deepEqual(h.storage, { bridgeConnection: { port: 48123, token: 'ephemeral-test-token' } });
  assert.deepEqual(h.calls.logs, []);
});

test('rejects invalid port or token and non-options senders without storing secrets', async () => {
  const h = await harness();
  for (const port of [0, 65536, -1, 1.5, '48123/path', ' 48123', '48123']) {
    assert.equal((await h.message({ type: 'connect', port, token: 'test' })).ok, false);
  }
  for (const token of ['', 'line\nbreak', 'x'.repeat(1025), null]) {
    assert.equal((await h.message({ type: 'connect', port: 48123, token })).ok, false);
  }
  assert.equal((await h.message({ type: 'connect', port: 48123, token: 'test' }, { id: 'test-extension', url: 'https://untrusted.example/' })).ok, false);
  assert.equal(h.sockets.length, 0);
  assert.deepEqual(h.storage, {});
});

test('handshake and pending watchdogs terminate abandoned work', async () => {
  const h = await harness();
  const socket = await h.connect();
  socket.open();
  assert.equal(h.timers.size > 0, true);
  for (const timer of [...h.timers.values()]) timer.callback();
  await tick();
  assert.equal(socket.closed, true);
  const active = await h.ready();
  get(h);
  assert.equal(h.timers.size > 0, true);
  for (const timer of [...h.timers.values()]) timer.callback();
  await tick();
  assert.equal(h.calls.get[0].error.name, 'NotAllowedError');
  assert.deepEqual(active.sent.at(-1), { type: 'cancel', id: 17 });
});

test('attach failures never claim an active proxy or reveal native API errors', async () => {
  for (const failure of [{ attachError: 'private-token' }, { attachResult: 'private-token' }]) {
    const h = await harness(failure);
    const socket = await h.ready();
    const status = await h.message({ type: 'status' });
    assert.equal(status.status.attached, false);
    assert.equal(socket.closed, true);
    assert.equal(JSON.stringify(status).includes('private-token'), false);
    assert.deepEqual(h.calls.logs, []);
  }
});

test('WebSocket construction failure clears the saved token and returns only a fixed error', async () => {
  const h = await harness({ socketError: 'private-token' });
  const response = await h.message({ type: 'connect', port: 48123, token: 'private-token' });
  await tick();
  assert.equal(response.ok, false);
  assert.deepEqual(h.storage, {});
  assert.equal(JSON.stringify(response).includes('private-token'), false);
});

test('detach failure blocks future attachment with an actionable safe status', async () => {
  const h = await harness({ detachError: 'private-token' });
  const socket = await h.ready();
  get(h);
  const response = await h.message({ type: 'disconnect' });
  await tick();
  assert.equal(response.ok, false);
  assert.match(response.status.message, /Disable this extension/);
  assert.equal(JSON.stringify(response).includes('private-token'), false);
  assert.equal(socket.closed, true);
  assert.equal(h.calls.get[0].error.name, 'AbortError');
  const reconnect = await h.message({ type: 'connect', port: 48123, token: 'test-token' });
  assert.equal(reconnect.ok, false);
  assert.equal(h.calls.attach, 1);
});

test('delayed detachment completes before attaching a replacement connection', async () => {
  const h = await harness({ delayedDetach: true });
  await h.ready();
  const socket = await h.connect(48124, 'replacement-token');
  socket.open();
  socket.receive({ type: 'ready', helper: true });
  await tick();
  assert.equal(h.calls.attach, 1);
  assert.equal((await h.message({ type: 'status' })).status.attached, false);
  h.resolveDetach();
  await tick();
  assert.equal(h.calls.attach, 2);
  assert.equal((await h.message({ type: 'status' })).status.attached, true);
});

test('failed sends close the session and do not leak token or native exception text', async () => {
  const h = await harness({ sendError: 'private-token' });
  const socket = await h.connect();
  socket.open();
  await tick();
  assert.equal(socket.closed, true);
  assert.deepEqual(h.storage, {});
  assert.equal(h.calls.attach, 0);
  assert.equal(JSON.stringify(await h.message({ type: 'status' })).includes('private-token'), false);
});

test('a rejected assertion completes the live Chrome request with a safe error', async () => {
  const h = await harness({ completionError: value => {
    if (value.responseJson) throw new Error('private-token');
  } });
  const socket = await h.ready();
  get(h);
  socket.receive({ type: 'result', id: 17, response: credential });
  await tick();
  assert.equal(h.calls.get.length, 2);
  assert.equal(h.calls.get[1].requestId, 17);
  assert.equal(h.calls.get[1].error.name, 'UnknownError');
  assert.equal((await h.message({ type: 'status' })).status.pending, false);
  assert.equal(h.timers.size, 0);
  assert.equal(socket.closed, false);
  assert.equal(JSON.stringify(h.calls).includes('private-token'), false);
  get(h, 18);
  assert.deepEqual(socket.sent.at(-1), { type: 'get', id: 18, details });
});

test('cancellation during response rejection preserves a newer request with the same ID', async () => {
  let rejectResponse;
  const h = await harness({ completionError: () => new Promise((resolve, reject) => { rejectResponse = reject; }) });
  const socket = await h.ready();
  get(h);
  socket.receive({ type: 'result', id: 17, response: credential });
  await tick();
  assert.equal((await h.message({ type: 'status' })).status.pending, true);
  assert.equal(h.timers.size, 1);
  h.proxy.onRequestCanceled.emit(17);
  assert.deepEqual(socket.sent.at(-1), { type: 'cancel', id: 17 });
  get(h);
  rejectResponse(new Error('request was canceled'));
  await tick();
  assert.equal(h.calls.get.length, 1);
  assert.equal((await h.message({ type: 'status' })).status.pending, true);
  assert.equal(h.timers.size, 1);
  assert.equal(socket.closed, false);
});

test('a rejected fallback detaches once and clears pending work without unhandled rejections', async () => {
  const h = await harness({ completionError: 'private-token' });
  const socket = await h.ready();
  const baseline = h.calls.detach;
  get(h);
  socket.receive({ type: 'result', id: 17, response: credential });
  await tick();
  assert.equal(h.calls.get.length, 2);
  assert.equal(h.calls.get[1].error.name, 'UnknownError');
  assert.equal(h.calls.detach, baseline + 1);
  assert.equal(socket.closed, true);
  const status = await h.message({ type: 'status' });
  assert.equal(status.status.pending, false);
  assert.equal(status.status.attached, false);
  assert.equal(h.timers.size, 0);
  assert.equal(JSON.stringify(status).includes('private-token'), false);
  assert.deepEqual(h.calls.logs, []);
});

test('cancellation during fallback rejection cannot detach a replacement session', async () => {
  let rejectFallback;
  const h = await harness({ completionError: value => {
    if (value.responseJson) throw new Error('invalid response');
    return new Promise((resolve, reject) => { rejectFallback = reject; });
  } });
  const first = await h.ready();
  get(h);
  first.receive({ type: 'result', id: 17, response: credential });
  await tick();
  assert.equal(h.calls.get.length, 2);
  h.proxy.onRequestCanceled.emit(17);
  const second = await h.ready();
  get(h);
  const baseline = h.calls.detach;
  rejectFallback(new Error('canceled fallback'));
  await tick();
  assert.equal(second.closed, false);
  assert.equal(h.calls.detach, baseline);
  assert.equal((await h.message({ type: 'status' })).status.pending, true);
  assert.equal(h.timers.size, 1);
});

test('a stalled completion keeps its watchdog and detaches at the deadline', async () => {
  const h = await harness({ completionError: () => new Promise(() => {}) });
  const socket = await h.ready();
  const baseline = h.calls.detach;
  get(h);
  socket.receive({ type: 'result', id: 17, response: credential });
  await tick();
  assert.equal(h.timers.size, 1);
  for (const timer of [...h.timers.values()]) timer.callback();
  await tick();
  assert.equal(h.calls.get.length, 1);
  assert.equal(h.calls.detach, baseline + 1);
  assert.equal(socket.closed, true);
  assert.equal((await h.message({ type: 'status' })).status.pending, false);
  assert.equal(h.timers.size, 0);
});

test('a stalled timeout error completion has a bounded cleanup deadline', async () => {
  const h = await harness({ completionError: () => new Promise(() => {}) });
  const socket = await h.ready();
  const baseline = h.calls.detach;
  get(h);
  const [timerId, timer] = [...h.timers.entries()][0];
  h.timers.delete(timerId);
  timer.callback();
  await tick();
  assert.equal(h.calls.get[0].error.name, 'NotAllowedError');
  assert.equal(h.timers.size, 1);
  const cleanup = [...h.timers.values()][0];
  assert.ok(cleanup.delay <= 5000);
  cleanup.callback();
  await tick();
  assert.equal(h.calls.detach, baseline + 1);
  assert.equal(socket.closed, true);
  assert.equal((await h.message({ type: 'status' })).status.pending, false);
  assert.equal(h.timers.size, 0);
});

test('duplicate results cannot race an in-flight Chrome completion', async () => {
  let resolveResponse;
  const h = await harness({ completionError: () => new Promise(resolve => { resolveResponse = resolve; }) });
  const socket = await h.ready();
  get(h);
  socket.receive({ type: 'result', id: 17, response: credential });
  socket.receive({ type: 'result', id: 17, response: credential });
  await tick();
  assert.equal(h.calls.get.length, 1);
  assert.equal((await h.message({ type: 'status' })).status.pending, true);
  resolveResponse();
  await tick();
  assert.equal((await h.message({ type: 'status' })).status.pending, false);
  assert.equal(h.timers.size, 0);
});

test('oversized frames fail closed and oversized requests never reach the broker', async () => {
  const h = await harness();
  const socket = await h.ready();
  get(h, 17, { challenge: 'x'.repeat(131072) });
  await tick();
  assert.equal(h.calls.get[0].error.name, 'DataError');
  assert.equal(socket.sent.length, 1);
  get(h, 18);
  socket.receive('x'.repeat(131073));
  await tick();
  assert.equal(socket.closed, true);
  assert.equal(h.calls.get[1].error.name, 'AbortError');
});

test('options clears token inputs and session settings on disconnect, with no persistent storage', async () => {
  const html = await readFile(new URL('options.html', root), 'utf8');
  assert.match(html, /type="password"/);
  assert.match(html, /autocomplete="off"/);
  assert.match(html, /src="options.js"/);
  const listeners = new Map();
  const elements = new Map(['connection', 'port', 'token', 'disconnect', 'status', 'refresh'].map(id => [id, {
    value: id === 'port' ? '48123' : '', textContent: '', disabled: false,
    addEventListener(type, handler) { listeners.set(`${id}:${type}`, handler); }
  }]));
  const messages = [];
  vm.runInNewContext(await readFile(new URL('options.js', root), 'utf8'), {
    document: { getElementById: id => elements.get(id) },
    chrome: { runtime: { async sendMessage(value) {
      messages.push(copy(value));
      return { ok: true, status: { state: value.type === 'disconnect' ? 'disconnected' : 'waiting', message: 'Safe status', port: 48123, attached: false } };
    } } }
  });
  await tick();
  assert.deepEqual(messages[0], { type: 'status' });
  elements.get('token').value = 'ui-test-secret';
  await listeners.get('connection:submit')({ preventDefault() {} });
  assert.deepEqual(messages.at(-1), { type: 'connect', port: 48123, token: 'ui-test-secret' });
  assert.equal(elements.get('token').value, '');
  elements.get('token').value = 'another-secret';
  await listeners.get('disconnect:click')();
  assert.deepEqual(messages.at(-1), { type: 'disconnect' });
  assert.equal(elements.get('token').value, '');
  assert.match(elements.get('status').textContent, /Safe status/);
});
