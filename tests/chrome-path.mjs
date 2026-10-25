import { getInstalledBrowsers } from '@puppeteer/browsers';
import { join } from 'node:path';

const installed = await getInstalledBrowsers({ cacheDir: join(process.env.RUNNER_TEMP, 'passkey-chrome') });
const chrome = installed.find(browser => browser.browser === 'chrome');
if (!chrome) throw new Error('Chrome for Testing installation not found');
console.log(`CHROME_BIN=${chrome.executablePath}`);
