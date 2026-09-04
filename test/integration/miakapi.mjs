import { createRequire } from 'node:module';
import { pathToFileURL } from 'node:url';
import path from 'node:path';
import process from 'node:process';

const [miakapiRepository, relayUrl, pageUrl] = process.argv.slice(2);
if (!miakapiRepository || !relayUrl || !pageUrl) {
  throw new Error(
    'Usage: node miakapi.mjs <miakapi-repository> <relay-url> <integration-page-url>',
  );
}

const moduleUrl = pathToFileURL(path.join(miakapiRepository, 'dist/index.js')).href;
const { createCoordinator, EventDirection } = await import(moduleUrl);
const requireFromMiakAPI = createRequire(path.join(miakapiRepository, 'package.json'));
const { chromium } = requireFromMiakAPI('playwright');

const delay = (milliseconds) => new Promise((resolve) => setTimeout(resolve, milliseconds));

async function eventually(read, accepts, label, timeoutMs = 7_000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const value = await read();
    if (accepts(value)) return value;
    await delay(25);
  }
  throw new Error(`Timed out waiting for ${label}`);
}

let coordinatorFailures = 0;
const coordinator = createCoordinator({
  name: 'integration',
  accessTokenProvider: {
    async getAccessToken() {
      return {
        relayUrl,
        token: 'integration-coordinator-token',
        expiresAtMs: Date.now() + 10 * 60_000,
      };
    },
  },
  logger: {
    write(record) {
      if (record.level === 'error') coordinatorFailures += 1;
    },
  },
});

coordinator.configure({
  state: { 'integration.temperature': 20 },
  stateAccess: [{ userId: 'integration-user', patterns: ['integration.*'] }],
  events: [{
    topic: 'integration.changed',
    directions: EventDirection.acceptFromUsers | EventDirection.publishToUsers,
  }],
  eventAccess: [{
    userId: 'integration-user',
    publish: ['integration.changed'],
    subscribe: ['integration.changed'],
  }],
  functions: {
    async 'integration.set'(call) {
      return { accepted: true, arguments: call.arguments };
    },
  },
});

let browser;
let page;
let browserClientStopped = false;
let coordinatorStopped = false;

try {
  const ready = await coordinator.start();
  if (ready.generation !== 1 || coordinator.status !== 'ready') {
    throw new Error('Coordinator did not reach generation 1 readiness');
  }

  browser = await chromium.launch({ headless: true });
  const context = await browser.newContext({ ignoreHTTPSErrors: true });
  page = await context.newPage();
  let websocketCount = 0;
  let pageErrorCount = 0;
  page.on('websocket', () => { websocketCount += 1; });
  page.on('pageerror', () => { pageErrorCount += 1; });
  await page.goto(pageUrl, { waitUntil: 'load' });

  const browserReady = await page.evaluate(
    () => globalThis.miakappIntegration.start(),
  );
  if (browserReady.enrolled !== true || browserReady.coordinatorCount !== 1) {
    throw new Error('Browser did not reach enrolled readiness');
  }

  await eventually(
    () => page.evaluate(() => globalThis.miakappIntegration.state()),
    (state) => state?.temperature === 20 && state.stale === false,
    'the authoritative initial browser snapshot',
  );

  await coordinator.state.set([
    { path: 'integration.temperature', value: 21 },
  ]);
  const patchedState = await eventually(
    () => page.evaluate(() => globalThis.miakappIntegration.state()),
    (state) => state?.temperature === 21 && state.stale === false,
    'the browser state patch',
  );

  const callResult = await page.evaluate(
    () => globalThis.miakappIntegration.call(22),
  );
  if (callResult?.accepted !== true || callResult?.arguments?.target !== 22) {
    throw new Error('Browser call did not return the expected terminal result');
  }

  await eventually(
    () => page.evaluate(() => globalThis.miakappIntegration.tokenReasons()),
    (reasons) => reasons.includes('reauth'),
    'the scheduled browser reauthentication attempt',
  );
  // The initial synthetic lease lasts four seconds and token renewal starts at
  // its midpoint. A successful call three seconds later proves REAUTH_OK was
  // accepted; otherwise the relay's original authentication lease has closed.
  await delay(3_000);
  const postLeaseCallResult = await page.evaluate(
    () => globalThis.miakappIntegration.call(22),
  );
  if (postLeaseCallResult?.accepted !== true
    || postLeaseCallResult?.arguments?.target !== 22) {
    throw new Error('Browser call did not survive the original authentication lease');
  }
  const browserStatus = await page.evaluate(() => ({
    failures: globalThis.miakappIntegration.failures(),
    statuses: globalThis.miakappIntegration.statuses(),
    tokenReasons: globalThis.miakappIntegration.tokenReasons(),
  }));
  if (browserStatus.failures.length !== 0
    || browserStatus.statuses.at(-1) !== 'ready'
    || browserStatus.tokenReasons.includes('reconnect')
    || websocketCount !== 1
    || pageErrorCount !== 0) {
    throw new Error('Browser lifecycle produced an unexpected failure or reconnect');
  }

  await page.evaluate(() => globalThis.miakappIntegration.stop());
  browserClientStopped = true;
  await browser.close();
  browser = undefined;
  await coordinator.stop({ deadlineMs: 2_000 });
  coordinatorStopped = true;
  if (coordinator.status !== 'stopped' || coordinatorFailures !== 0) {
    throw new Error('Coordinator stopped with integration failures');
  }

  process.stdout.write(`${JSON.stringify({
    generation: ready.generation,
    state: patchedState.temperature,
    call: 'succeeded',
    reauthenticated: true,
    post_lease_call: 'succeeded',
    browser: 'chromium',
    websockets: websocketCount,
  })}\n`);
} finally {
  if (!browserClientStopped && page !== undefined) {
    await page.evaluate(() => globalThis.miakappIntegration?.stop()).catch(() => undefined);
  }
  if (browser !== undefined) await browser.close().catch(() => undefined);
  if (!coordinatorStopped) {
    await coordinator.stop({ deadlineMs: 2_000 }).catch(() => undefined);
  }
}
