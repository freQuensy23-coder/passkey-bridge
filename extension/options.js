'use strict';

const form = document.getElementById('connection');
const portInput = document.getElementById('port');
const tokenInput = document.getElementById('token');
const statusOutput = document.getElementById('status');
const disconnectButton = document.getElementById('disconnect');
const refreshButton = document.getElementById('refresh');

async function command(message) {
  try {
    const response = await chrome.runtime.sendMessage(message);
    const current = response?.status;
    statusOutput.textContent = response?.ok
      ? current?.message ?? 'Status unavailable.'
      : response?.message ?? current?.message ?? 'The operation failed.';
    if (current?.port && !portInput.value) portInput.value = String(current.port);
  } catch {
    statusOutput.textContent = 'The extension worker is unavailable. Reload the extension and try again.';
  }
}

form.addEventListener('submit', async event => {
  event.preventDefault();
  const token = tokenInput.value;
  tokenInput.value = '';
  await command({ type: 'connect', port: Number(portInput.value), token });
});

disconnectButton.addEventListener('click', async () => {
  tokenInput.value = '';
  await command({ type: 'disconnect' });
});

refreshButton.addEventListener('click', async () => {
  await command({ type: 'status' });
});

void command({ type: 'status' });
