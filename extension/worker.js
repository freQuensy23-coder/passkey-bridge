'use strict';

const connectionKey = 'bridgeConnection';
const proxy = chrome.webAuthenticationProxy;
const pending = new Map();
const errorMessages = {
  AbortError: 'The passkey bridge connection was interrupted.',
  NotAllowedError: 'The passkey request was not allowed or could not be completed.',
  NotSupportedError: 'Passkey registration is not supported by this bridge.',
  SecurityError: 'The passkey request failed a security check.',
  InvalidStateError: 'The passkey request cannot be completed in the current state.',
  ConstraintError: 'The passkey request requirements could not be satisfied.',
  DataError: 'The passkey request contains invalid data.',
  TimeoutError: 'The passkey request timed out.',
  UnknownError: 'The passkey request could not be completed.'
};
let session = null;
let attached = false;
let attachedVersion = -1;
let version = 0;
let state = 'disconnected';
let statusMessage = 'Disconnected. Normal browser authentication is in use.';
let storageQueue = Promise.resolve();
let proxyQueue = Promise.resolve();
let controlQueue = Promise.resolve();
let proxyBlocked = false;

function exception(name) {
  const safeName = Object.hasOwn(errorMessages, name) ? name : 'UnknownError';
  return { name: safeName, message: errorMessages[safeName] };
}

function quiet(operation) {
  try {
    Promise.resolve(operation()).catch(() => {});
  } catch {}
}

function persist(operation) {
  const result = storageQueue.then(operation);
  storageQueue = result.catch(() => {});
  return result;
}

function eligible() {
  return Boolean(session?.authenticated && session.helper && session.socket.readyState === WebSocket.OPEN);
}

function status() {
  return {
    state,
    message: statusMessage,
    port: session?.port ?? null,
    authenticated: Boolean(session?.authenticated),
    helper: Boolean(session?.helper),
    attached: attached && eligible() && attachedVersion === version,
    pending: pending.size > 0
  };
}

function complete(id, result) {
  const request = pending.get(id);
  if (!request) return;
  clearTimeout(request.timer);
  pending.delete(id);
  quiet(() => proxy.completeGetRequest({ requestId: id, ...result }));
}

function failPending() {
  for (const id of pending.keys()) complete(id, { error: exception('AbortError') });
}

function endSession(target, message = 'Disconnected. Normal browser authentication is in use.') {
  if (!target || session !== target) return;
  session = null;
  version += 1;
  clearTimeout(target.timer);
  target.token = null;
  failPending();
  state = 'disconnected';
  statusMessage = message;
  quiet(() => target.socket.close());
  quiet(() => persist(() => chrome.storage.session.remove(connectionKey)));
  reconcile();
}

async function detach() {
  const result = await proxy.detach();
  if (typeof result === 'string' && result) throw new Error('Proxy detach failed');
  attached = false;
  attachedVersion = -1;
}

function reconcile() {
  proxyQueue = proxyQueue.then(async () => {
    if (proxyBlocked) return;
    if (attached && (!eligible() || attachedVersion !== version)) await detach();
    if (!attached && eligible()) {
      const target = session;
      const targetVersion = version;
      let result;
      try {
        result = await proxy.attach();
        if (typeof result === 'string' && result) throw new Error('Proxy attach failed');
      } catch {
        endSession(target, 'Could not attach the passkey proxy. Check for another proxy extension.');
        return;
      }
      attached = true;
      attachedVersion = targetVersion;
      if (session !== target || version !== targetVersion || !eligible()) {
        await detach();
        reconcile();
        return;
      }
      state = 'attached';
      statusMessage = 'Connected. Passkey assertions require approval on your local companion.';
    }
  }).catch(() => {
    proxyBlocked = true;
    endSession(session, 'Proxy cleanup failed. Disable this extension to restore normal authentication.');
    state = 'error';
    statusMessage = 'Proxy cleanup failed. Disable this extension to restore normal authentication.';
  });
  return proxyQueue;
}

function send(target, message) {
  if (session !== target || target.socket.readyState !== WebSocket.OPEN) return false;
  try {
    const payload = JSON.stringify(message);
    if (new TextEncoder().encode(payload).length > 131072) return false;
    target.socket.send(payload);
    return true;
  } catch {
    endSession(target, 'The broker connection failed. Reconnect with a current session token.');
    return false;
  }
}

function object(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function credential(value) {
  return object(value) && value.type === 'public-key' && typeof value.id === 'string' &&
    typeof value.rawId === 'string' && object(value.response) &&
    ['clientDataJSON', 'authenticatorData', 'signature'].every(key => typeof value.response[key] === 'string');
}

function receive(target, data) {
  if (session !== target) return;
  let message;
  try {
    if (typeof data !== 'string' || new TextEncoder().encode(data).length > 131072) throw new Error('Invalid frame');
    message = JSON.parse(data);
    if (!object(message)) throw new Error('Invalid frame');
    if (!target.authenticated) {
      if (message.type !== 'ready' || typeof message.helper !== 'boolean') throw new Error('Authentication rejected');
      target.authenticated = true;
      target.helper = message.helper;
      target.token = null;
      clearTimeout(target.timer);
      state = message.helper ? 'attaching' : 'waiting';
      statusMessage = message.helper ? 'Attaching the passkey proxy.' : 'Authenticated. Waiting for your local companion.';
      reconcile();
      return;
    }
    if (message.type === 'helper') {
      if (typeof message.connected !== 'boolean') throw new Error('Invalid helper state');
      if (target.helper === message.connected) return;
      target.helper = message.connected;
      version += 1;
      if (!message.connected) failPending();
      state = message.connected ? 'attaching' : 'waiting';
      statusMessage = message.connected ? 'Attaching the passkey proxy.' : 'Companion disconnected. Normal browser authentication is in use.';
      reconcile();
      return;
    }
    if (!['result', 'error'].includes(message.type) || !Number.isSafeInteger(message.id)) throw new Error('Invalid response');
    if (!pending.has(message.id)) return;
    if (message.type === 'result') {
      if (!credential(message.response)) throw new Error('Invalid assertion');
      complete(message.id, { responseJson: JSON.stringify(message.response) });
    } else {
      if (!object(message.error) || typeof message.error.name !== 'string' || typeof message.error.message !== 'string') throw new Error('Invalid error');
      complete(message.id, { error: exception(message.error.name) });
    }
  } catch {
    endSession(target, 'The broker rejected authentication or sent an invalid message. Reconnect with a current session token.');
  }
}

function validConnection(value) {
  return object(value) && Number.isInteger(value.port) && value.port >= 1 && value.port <= 65535 &&
    typeof value.token === 'string' && value.token.length >= 1 && value.token.length <= 1024 && /^[\x21-\x7e]+$/.test(value.token);
}

async function connect(value) {
  if (!validConnection(value)) return { ok: false, message: 'Enter a valid numeric port and session token.', status: status() };
  if (proxyBlocked) return { ok: false, message: statusMessage, status: status() };
  endSession(session);
  await persist(() => chrome.storage.session.set({ [connectionKey]: { port: value.port, token: value.token } }));
  let socket;
  try {
    socket = new WebSocket(`ws://127.0.0.1:${value.port}`);
  } catch {
    await persist(() => chrome.storage.session.remove(connectionKey));
    state = 'disconnected';
    statusMessage = 'Could not open the loopback broker connection.';
    return { ok: false, message: statusMessage, status: status() };
  }
  const target = { socket, port: value.port, token: value.token, authenticated: false, helper: false, timer: null };
  session = target;
  version += 1;
  state = 'connecting';
  statusMessage = 'Connecting to the loopback broker.';
  target.timer = setTimeout(() => endSession(target, 'Broker authentication timed out. Reconnect with a current session token.'), 10000);
  socket.addEventListener('open', () => {
    if (session !== target) return;
    state = 'authenticating';
    statusMessage = 'Authenticating with the loopback broker.';
    if (!send(target, { type: 'hello', role: 'extension', token: target.token })) endSession(target);
    target.token = null;
  });
  socket.addEventListener('message', event => receive(target, event.data));
  socket.addEventListener('close', () => endSession(target));
  socket.addEventListener('error', () => endSession(target, 'The loopback broker is unavailable. Check its port and reconnect.'));
  return { ok: true, status: status() };
}

proxy.onGetRequest.addListener(request => {
  const id = request.requestId;
  if (pending.has(id)) return;
  if (!eligible() || !attached || attachedVersion !== version || pending.size >= 1) {
    quiet(() => proxy.completeGetRequest({ requestId: id, error: exception('NotAllowedError') }));
    return;
  }
  let details;
  try {
    details = JSON.parse(request.requestDetailsJson);
    if (!object(details)) throw new Error('Invalid request');
  } catch {
    quiet(() => proxy.completeGetRequest({ requestId: id, error: exception('DataError') }));
    return;
  }
  const target = session;
  const timer = setTimeout(() => {
    if (!pending.has(id)) return;
    send(target, { type: 'cancel', id });
    complete(id, { error: exception('NotAllowedError') });
  }, 180000);
  pending.set(id, { timer });
  if (!send(target, { type: 'get', id, details })) complete(id, { error: exception('DataError') });
});

proxy.onCreateRequest.addListener(request => {
  quiet(() => proxy.completeCreateRequest({ requestId: request.requestId, error: exception('NotSupportedError') }));
});

proxy.onIsUvpaaRequest.addListener(request => {
  quiet(() => proxy.completeIsUvpaaRequest({ requestId: request.requestId, isUvpaa: false }));
});

proxy.onRequestCanceled.addListener(id => {
  const request = pending.get(id);
  if (!request) return;
  clearTimeout(request.timer);
  pending.delete(id);
  if (session) send(session, { type: 'cancel', id });
});

chrome.runtime.onMessage.addListener((message, sender, respond) => {
  if (sender.id !== chrome.runtime.id || sender.url !== chrome.runtime.getURL('options.html')) {
    respond({ ok: false, message: 'Only the extension connection page may control the bridge.' });
    return true;
  }
  controlQueue = controlQueue.then(async () => {
    if (!object(message)) return { ok: false, message: 'Invalid command.', status: status() };
    if (message.type === 'status') return { ok: true, status: status() };
    if (message.type === 'connect') return await connect(message);
    if (message.type === 'disconnect') {
      endSession(session);
      await persist(() => chrome.storage.session.remove(connectionKey));
      await reconcile();
      return { ok: !proxyBlocked, status: status() };
    }
    return { ok: false, message: 'Invalid command.', status: status() };
  }).catch(() => {
    endSession(session, 'The bridge could not complete the operation. Reconnect to try again.');
    return { ok: false, message: 'The bridge could not complete the operation.', status: status() };
  });
  controlQueue.then(respond);
  return true;
});

controlQueue = (async () => {
  try {
    await detach();
    const saved = (await chrome.storage.session.get(connectionKey))[connectionKey];
    if (validConnection(saved)) await connect(saved);
    else if (saved !== undefined) await persist(() => chrome.storage.session.remove(connectionKey));
  } catch {
    proxyBlocked = true;
    state = 'error';
    statusMessage = 'Could not initialize the proxy. Disable this extension to restore normal authentication.';
  }
})();
