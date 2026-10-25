import assert from 'node:assert/strict';
import { mkdtemp, rm } from 'node:fs/promises';
import { createServer } from 'node:http';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { createRequire } from 'node:module';

const require = createRequire(process.env.PLAYWRIGHT_MODULE || import.meta.url);
const { chromium } = require('playwright-core');
const profile = await mkdtemp(join(process.env.TMPDIR || tmpdir(), 'passkey-browser-'));
const extensionPath = resolve('extension');
const http = createServer((request, response) => {
  response.writeHead(200, { 'Content-Type': 'text/html' });
  response.end('<!doctype html><title>WebAuthn bridge test fixture</title>');
});
await new Promise(resolve => http.listen(0, '127.0.0.1', resolve));
let context;
try {
  context = await chromium.launchPersistentContext(profile, {
    executablePath: process.env.CHROME_BIN,
    headless: true,
    args: [`--disable-extensions-except=${extensionPath}`, `--load-extension=${extensionPath}`]
  });
  const worker = context.serviceWorkers()[0] || await context.waitForEvent('serviceworker');
  const extensionId = new URL(worker.url()).hostname;
  const available = await worker.evaluate(() => Boolean(chrome.webAuthenticationProxy?.attach));
  assert.equal(available, true, 'Real Chrome webAuthenticationProxy API is available');
  const options = await context.newPage();
  await options.goto(`chrome-extension://${extensionId}/options.html`);
  await options.locator('#port').fill(process.env.BRIDGE_PORT);
  await options.locator('#token').fill(process.env.EXTENSION_TOKEN);
  await options.locator('button[type=submit]').click();
  await options.waitForFunction(async () => {
    const result = await chrome.runtime.sendMessage({ type: 'status' });
    return result.status.attached;
  });
  const page = await context.newPage();
  await page.goto(`http://localhost:${http.address().port}`);
  const result = await page.evaluate(async () => {
    const challenge = new Uint8Array(32).fill(19);
    const credential = await navigator.credentials.get({ publicKey: {
      rpId: 'localhost', challenge, userVerification: 'required', timeout: 15000
    }});
    return credential.toJSON();
  });
  assert.equal(result.type, 'public-key');
  assert.ok(result.response.signature);
  assert.equal(JSON.parse(Buffer.from(result.response.clientDataJSON, 'base64url')).origin,
    `http://localhost:${http.address().port}`);
  await options.locator('#disconnect').click();
  await options.waitForFunction(async () => {
    const result = await chrome.runtime.sendMessage({ type: 'status' });
    return !result.status.attached && result.status.state === 'disconnected';
  });
  process.stdout.write(JSON.stringify({ browser: context.browser().version(), intercepted: true,
    assertionReturned: true, detached: true }) + '\n');
} finally {
  if (context) await context.close();
  await new Promise(resolve => http.close(resolve));
  await rm(profile, { recursive: true, force: true });
}
