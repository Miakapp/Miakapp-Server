import assert from 'node:assert/strict';
import { readFileSync, statSync } from 'node:fs';
import { Agent, request as httpsRequest } from 'node:https';
import { createRequire } from 'node:module';
import path from 'node:path';
import process from 'node:process';
import { pathToFileURL } from 'node:url';

const [
  miakapiRepository,
  controlMetadataFile,
  relayMetadataFile,
  secondaryRelayMetadataFile,
  homeKeyFile,
  controlSecretFile,
  relaySecretFile,
  controlEvidenceFile,
  relayEvidenceFile,
  secondaryRelayEvidenceFile,
  browserSourceFile,
] = process.argv.slice(2);
if ([
  miakapiRepository,
  controlMetadataFile,
  relayMetadataFile,
  secondaryRelayMetadataFile,
  homeKeyFile,
  controlSecretFile,
  relaySecretFile,
  controlEvidenceFile,
  relayEvidenceFile,
  secondaryRelayEvidenceFile,
  browserSourceFile,
].some((value) => value === undefined)) {
  throw new Error(
    'Usage: node platform-auth.mjs <MiakAPI> <control-metadata> <relay-metadata> '
      + '<secondary-relay-metadata> <home-key> <control-secret> <relay-secret> '
      + '<control-evidence> <relay-evidence> <secondary-relay-evidence> <browser-source>',
  );
}

function isExactObject(value, keys) {
  return value !== null
    && !Array.isArray(value)
    && typeof value === 'object'
    && Object.keys(value).length === keys.length
    && keys.every((key) => Object.hasOwn(value, key));
}

function exactObject(value, keys, description) {
  if (!isExactObject(value, keys)) {
    throw new Error(`${description} is invalid`);
  }
  return value;
}

function loopbackURL(value, protocol, pathname, description) {
  if (typeof value !== 'string') throw new Error(`${description} is invalid`);
  let parsed;
  try {
    parsed = new URL(value);
  } catch {
    throw new Error(`${description} is invalid`);
  }
  if (parsed.protocol !== protocol
    || parsed.hostname !== '127.0.0.1'
    || parsed.port === ''
    || parsed.username !== ''
    || parsed.password !== ''
    || parsed.pathname !== pathname
    || parsed.search !== ''
    || parsed.hash !== '') {
    throw new Error(`${description} is invalid`);
  }
  return parsed;
}

function jsonFile(file, schema) {
  const value = JSON.parse(readFileSync(file, 'utf8'));
  if (value === null
    || Array.isArray(value)
    || typeof value !== 'object'
    || value.schema !== schema) {
    throw new Error('Platform integration file is invalid');
  }
  return value;
}

const rawControl = jsonFile(controlMetadataFile, 'miakapp.relay-integration-control/1');
const canonicalControlKeys = ['schema', 'controlUrl', 'exchangeEndpoint', 'jwksUrl'];
const transitionalControlKeys = [...canonicalControlKeys, 'controlEndpoint'];
if (!isExactObject(rawControl, canonicalControlKeys)
  && !isExactObject(rawControl, transitionalControlKeys)) {
  throw new Error('Control-plane metadata is invalid');
}
const control = rawControl;
const relay = exactObject(
  jsonFile(relayMetadataFile, 'miakapp.relay-integration-relay/1'),
  ['schema', 'relayUrl'],
  'Relay metadata',
);
const secondaryRelay = exactObject(
  jsonFile(secondaryRelayMetadataFile, 'miakapp.relay-integration-relay/1'),
  ['schema', 'relayUrl'],
  'Secondary relay metadata',
);
const controlURL = loopbackURL(control.controlUrl, 'https:', '/', 'Control-plane URL');
const browserURL = loopbackURL(
  `${controlURL.origin}/__integration/browser`,
  'https:',
  '/__integration/browser',
  'Control-plane browser URL',
);
const exchangeURL = loopbackURL(
  control.exchangeEndpoint,
  'https:',
  '/v1/access-tokens:exchange',
  'Control-plane exchange URL',
);
const jwksURL = loopbackURL(
  control.jwksUrl,
  'https:',
  '/.well-known/jwks.json',
  'Control-plane JWKS URL',
);
const userExchangeURL = loopbackURL(
  `${controlURL.origin}/v1/user-relay-tokens:exchange`,
  'https:',
  '/v1/user-relay-tokens:exchange',
  'Control-plane user exchange URL',
);
const relayURL = loopbackURL(relay.relayUrl, 'wss:', '/ws', 'Relay URL');
const secondaryRelayURL = loopbackURL(
  secondaryRelay.relayUrl,
  'wss:',
  '/ws',
  'Secondary relay URL',
);
if (secondaryRelayURL.href === relayURL.href) {
  throw new Error('Relay integration URLs are not distinct');
}
if (exchangeURL.origin !== controlURL.origin
  || userExchangeURL.origin !== controlURL.origin
  || browserURL.origin !== controlURL.origin
  || jwksURL.origin !== controlURL.origin) {
  throw new Error('Control-plane metadata origins are inconsistent');
}
const controlEndpoint = `${controlURL.origin}/__integration/control`;
const relayControlEndpoint = `https://${relayURL.host}/__integration/control`;
const relayVerifyEndpoint = `https://${relayURL.host}/__integration/verify`;
const secondaryRelayControlEndpoint =
  `https://${secondaryRelayURL.host}/__integration/control`;
if (Object.hasOwn(control, 'controlEndpoint') && control.controlEndpoint !== controlEndpoint) {
  throw new Error('Transitional control-plane metadata is inconsistent');
}
const homeKey = readFileSync(homeKeyFile, 'ascii');
const controlSecret = readFileSync(controlSecretFile, 'ascii').trim();
const relaySecret = readFileSync(relaySecretFile, 'ascii').trim();
const browserSource = exactObject(
  jsonFile(browserSourceFile, 'miakapp.browser-source-credentials/1'),
  [
    'schema',
    'homeId',
    'firebaseUid',
    'firebaseVerifiedEmail',
    'firebaseIdToken',
    'appCheckToken',
  ],
  'Browser source credentials',
);
if (!/^mhk1_[A-Za-z0-9_-]{22}_[A-Za-z0-9_-]{43}$/.test(homeKey)
  || !/^[0-9a-f]{64}$/.test(controlSecret)
  || !/^[0-9a-f]{64}$/.test(relaySecret)
  || typeof browserSource.homeId !== 'string'
  || browserSource.homeId !== 'synthetic-relay-home'
  || typeof browserSource.firebaseUid !== 'string'
  || browserSource.firebaseUid.length === 0
  || browserSource.firebaseUid.length > 128
  || browserSource.firebaseVerifiedEmail !== null
  || typeof browserSource.firebaseIdToken !== 'string'
  || browserSource.firebaseIdToken.split('.').length !== 3
  || typeof browserSource.appCheckToken !== 'string'
  || browserSource.appCheckToken.split('.').length !== 3
  || browserSource.firebaseIdToken === browserSource.appCheckToken
  || (statSync(browserSourceFile).mode & 0o777) !== 0o600) {
  throw new Error('Platform integration inputs are invalid');
}

const fixtureAgent = new Agent({ keepAlive: true, maxSockets: 64 });

function fixtureRequest(endpoint, secret, body) {
  const payload = Buffer.from(JSON.stringify(body), 'utf8');
  return new Promise((resolve, reject) => {
    const request = httpsRequest(endpoint, {
      method: 'POST',
      agent: fixtureAgent,
      headers: {
        accept: 'application/json',
        authorization: `Bearer ${secret}`,
        'content-length': String(payload.byteLength),
        'content-type': 'application/json',
      },
    }, (response) => {
      const chunks = [];
      let length = 0;
      response.on('data', (chunk) => {
        length += chunk.byteLength;
        if (length > 65_536) {
          request.destroy(new Error('Integration fixture response is overlong'));
          return;
        }
        chunks.push(chunk);
      });
      response.on('end', () => {
        const status = response.statusCode ?? 0;
        if (status === 204) {
          resolve({ status, value: undefined });
          return;
        }
        try {
          resolve({
            status,
            value: JSON.parse(Buffer.concat(chunks, length).toString('utf8')),
          });
        } catch {
          reject(new Error('Integration fixture returned invalid JSON'));
        }
      });
    });
    request.once('error', reject);
    request.setTimeout(15_000, () => request.destroy(new Error('Integration fixture timed out')));
    request.end(payload);
  });
}

async function controlAction(action, fields = {}) {
  const response = await fixtureRequest(controlEndpoint, controlSecret, { action, ...fields });
  assert.equal(response.status, 200, `Control action ${action} failed`);
  return response.value;
}

async function relayAction(action, offsetMilliseconds) {
  const body = offsetMilliseconds === undefined
    ? { action }
    : { action, offset_ms: offsetMilliseconds };
  const response = await fixtureRequest(relayControlEndpoint, relaySecret, body);
  assert.equal(response.status, 200, `Relay action ${action} failed`);
  return response.value;
}

async function secondaryRelayAction(action) {
  const response = await fixtureRequest(
    secondaryRelayControlEndpoint,
    relaySecret,
    { action },
  );
  assert.equal(response.status, 200, `Secondary relay action ${action} failed`);
  return response.value;
}

async function verifyToken(target, token) {
  const response = await fixtureRequest(relayVerifyEndpoint, relaySecret, { target, token });
  return response.status;
}

async function waitUntil(predicate, description, milliseconds = 10_000) {
  const deadline = Date.now() + milliseconds;
  while (Date.now() < deadline) {
    const value = await predicate();
    if (value) return value;
    await new Promise((resolve) => setTimeout(resolve, 25));
  }
  throw new Error(`${description} timed out`);
}

function tokenKid(token) {
  const segments = token.split('.');
  if (segments.length !== 3 || segments[0] === undefined) {
    throw new Error('Integration access token is malformed');
  }
  const header = exactObject(
    JSON.parse(Buffer.from(segments[0], 'base64url').toString('utf8')),
    ['alg', 'kid', 'typ'],
    'Integration access-token header',
  );
  if (header.alg !== 'EdDSA'
    || header.typ !== 'at+jwt'
    || typeof header.kid !== 'string'
    || !/^[A-Za-z0-9._-]{1,128}$/.test(header.kid)) {
    throw new Error('Integration access-token header is invalid');
  }
  return header.kid;
}

function tokenWithUnknownKid(token, kid) {
  const segments = token.split('.');
  if (segments.length !== 3
    || segments[0] === undefined
    || segments[1] === undefined
    || segments[2] === undefined
    || !/^unknown-[a-z0-9-]{1,64}$/.test(kid)) {
    throw new Error('Unknown-key test input is invalid');
  }
  const original = exactObject(
    JSON.parse(Buffer.from(segments[0], 'base64url').toString('utf8')),
    ['alg', 'kid', 'typ'],
    'Integration access-token header',
  );
  const header = Buffer.from(JSON.stringify({ ...original, kid }), 'utf8').toString('base64url');
  return `${header}.${segments[1]}.${segments[2]}`;
}

const indexUrl = pathToFileURL(path.join(miakapiRepository, 'dist/index.js')).href;
const coordinatorUrl = pathToFileURL(path.join(miakapiRepository, 'dist/coordinator.js')).href;
const socketUrl = pathToFileURL(path.join(miakapiRepository, 'dist/internal/socket.js')).href;
const codecUrl = pathToFileURL(path.join(miakapiRepository, 'dist/protocol/codec.js')).href;
const { createHomeKeyAccessTokenProvider } = await import(indexUrl);
const { createCoordinatorWithRuntime } = await import(coordinatorUrl);
const { createProductionRuntime } = await import(socketUrl);
const { decodeFrame, Opcode } = await import(codecUrl);
const requireFromMiakAPI = createRequire(path.join(miakapiRepository, 'package.json'));
const { chromium } = requireFromMiakAPI('playwright');

const reasons = [];
const sdkKids = [];
const warmStatuses = [];
let cachesWarmed = false;
const sdkProviderDelegate = createHomeKeyAccessTokenProvider({
  exchangeEndpoint: control.exchangeEndpoint,
  homeKey,
  async fetch(input, init) {
    const body = JSON.parse(init.body);
    reasons.push(body.reason);
    return fetch(input, init);
  },
});
const provider = Object.freeze({
  async getAccessToken(request) {
    const token = await sdkProviderDelegate.getAccessToken(request);
    sdkKids.push(tokenKid(token.token));
    if (!cachesWarmed) {
      assert.equal(request.reason, 'initial');
      warmStatuses.push(await verifyToken('relay', token.token));
      warmStatuses.push(await verifyToken('probe', token.token));
      assert.deepEqual(warmStatuses, [204, 204]);
      cachesWarmed = true;
    }
    return token;
  },
});
const directProvider = createHomeKeyAccessTokenProvider({
  exchangeEndpoint: control.exchangeEndpoint,
  homeKey,
});
const productionRuntime = createProductionRuntime();
const controlledReauthenticationTimers = [];
const minimumReauthenticationDelayMilliseconds = 240_000;
function integrationTimer(callback, delayMilliseconds) {
  if (delayMilliseconds < minimumReauthenticationDelayMilliseconds) {
    return productionRuntime.setTimer(callback, delayMilliseconds);
  }
  const timer = {
    active: true,
    delayMilliseconds,
    fire() {
      assert.equal(timer.active, true, 'Controlled reauthentication timer is inactive');
      timer.active = false;
      callback();
    },
    cancel() {
      timer.active = false;
    },
  };
  controlledReauthenticationTimers.push(timer);
  return timer;
}
let socketConnections = 0;
let processedReauthenticationAcks = 0;
const observedSocketFactory = Object.freeze({
  async connect(url, handlers, signal) {
    socketConnections += 1;
    return productionRuntime.socketFactory.connect(url, {
      message(bytes) {
        const frame = decodeFrame(bytes);
        handlers.message(bytes);
        if (frame.opcode === Opcode.ReauthOk) processedReauthenticationAcks += 1;
      },
      close(code, reason) {
        handlers.close(code, reason);
      },
      error(error) {
        handlers.error(error);
      },
    }, signal);
  },
});
// Preserve the production socket and short timers, while explicitly firing the
// real five-minute lease's scheduled reauthentication after the cache matrix.
const runtime = Object.freeze({
  socketFactory: observedSocketFactory,
  now: productionRuntime.now,
  random: () => 0,
  setTimer: integrationTimer,
});
const failures = [];
const lifecycle = [];
const coordinator = createCoordinatorWithRuntime({
  name: 'integration',
  accessTokenProvider: provider,
  logger: {
    write(record) {
      if (record.level === 'error') failures.push(record);
    },
  },
}, runtime);
coordinator.subscribe((event) => {
  if (lifecycle.length < 128) lifecycle.push(event.current);
});
function configureIntegrationCoordinator(target) {
  target.configure({
    state: { 'integration.temperature': 20 },
    stateAccess: [{ userId: browserSource.firebaseUid, patterns: ['integration.*'] }],
    events: [],
    eventAccess: [],
    functions: {
      async 'integration.set'(call) {
        return { accepted: true, arguments: call.arguments };
      },
    },
  });
}
configureIntegrationCoordinator(coordinator);

const startController = new AbortController();
const startTimeout = setTimeout(
  () => startController.abort(new Error('Coordinator readiness timed out')),
  10_000,
);
let ready;
try {
  ready = await coordinator.start({ signal: startController.signal });
} catch (error) {
  process.stderr.write(`${JSON.stringify({
    schema: 'miakapp.relay-auth-integration-diagnostic/1',
    warm_statuses: warmStatuses,
    failure_kinds: failures.map((failure) => failure.kind),
    lifecycle,
  })}\n`);
  throw error;
} finally {
  clearTimeout(startTimeout);
}
if (ready.generation !== 1 || coordinator.status !== 'ready' || !cachesWarmed) {
  throw new Error('Coordinator did not become ready through prewarmed production caches');
}

let controlState = await controlAction('status');
assert.equal(controlState.phase, 'initial');
assert.equal(controlState.jwks.requests, 2);
assert.equal(controlState.jwks.responses.ok, 2);
assert.equal((await controlAction('prepublish')).phase, 'prepublished');
assert.equal((await controlAction('activate')).phase, 'activated');

const directController = new AbortController();
const futureAccess = await directProvider.getAccessToken(Object.freeze({
  coordinatorName: 'integration',
  reason: 'initial',
  signal: directController.signal,
}));
const futureKid = tokenKid(futureAccess.token);
assert.notEqual(futureKid, sdkKids[0]);
await relayAction('set_clock', 0);

await controlAction('hold_jwks');
const concurrentFuture = Array.from(
  { length: 32 },
  () => verifyToken('probe', futureAccess.token),
);
let lastBarrierState;
try {
  await waitUntil(async () => {
    const [relayState, currentControl] = await Promise.all([
      relayAction('status'),
      controlAction('status'),
    ]);
    lastBarrierState = {
      probe_in_flight: relayState.probe.in_flight,
      probe_maximum_in_flight: relayState.probe.maximum_in_flight,
      jwks_in_flight: currentControl.jwks.in_flight,
      jwks_requests: currentControl.jwks.requests,
    };
    return relayState.probe.in_flight === 32 && currentControl.jwks.in_flight === 1;
  }, 'Concurrent unknown-key single-flight barrier');
} catch (error) {
  process.stderr.write(`${JSON.stringify({
    schema: 'miakapp.relay-auth-barrier-diagnostic/1',
    ...lastBarrierState,
  })}\n`);
  throw error;
}
await controlAction('release_jwks');
assert.deepEqual(await Promise.all(concurrentFuture), Array(32).fill(204));
await waitUntil(async () => (await controlAction('status')).jwks.in_flight === 0,
  'Released JWKS response');
controlState = await controlAction('status');
assert.equal(controlState.jwks.requests, 3);
assert.equal(controlState.jwks.responses.ok, 3);

const unknownTokens = Array.from(
  { length: 32 },
  (_, index) => tokenWithUnknownKid(futureAccess.token, `unknown-inside-${index}`),
);
for (const token of unknownTokens) assert.equal(await verifyToken('probe', token), 401);
assert.equal((await controlAction('status')).jwks.requests, 3);

await relayAction('set_clock', 10_000);
for (let index = 0; index < 32; index += 1) {
  const token = tokenWithUnknownKid(futureAccess.token, `unknown-next-${index}`);
  assert.equal(await verifyToken('probe', token), 401);
}
controlState = await controlAction('status');
assert.equal(controlState.jwks.requests, 4);
assert.equal(controlState.jwks.responses.not_modified, 1);

await relayAction('set_clock', 71_000);
assert.equal(await verifyToken('probe', futureAccess.token), 204);
controlState = await controlAction('status');
assert.equal(controlState.jwks.requests, 5);
assert.equal(controlState.jwks.responses.not_modified, 2);

await relayAction('set_clock', 132_000);
await controlAction('fail_jwks');
assert.equal(await verifyToken('probe', futureAccess.token), 503);
assert.equal((await controlAction('status')).jwks.requests, 6);
assert.equal(await verifyToken('probe', futureAccess.token), 503);
controlState = await controlAction('status');
assert.equal(controlState.jwks.requests, 6);
assert.equal(controlState.jwks.responses.unavailable, 1);

await controlAction('recover_jwks');
await relayAction('set_clock', 133_000);
assert.equal(await verifyToken('probe', futureAccess.token), 204);
controlState = await controlAction('status');
assert.equal(controlState.jwks.requests, 7);
assert.equal(controlState.jwks.responses.not_modified, 3);

assert.equal(controlledReauthenticationTimers.length, 1);
assert.equal(controlledReauthenticationTimers[0].active, true);
controlledReauthenticationTimers[0].fire();
await waitUntil(
  () => processedReauthenticationAcks === 1,
  'Processed same-session REAUTH_OK',
);

if (reasons.length !== 2
  || reasons[0] !== 'initial'
  || reasons[1] !== 'reauth'
  || sdkKids.length !== 2
  || sdkKids[0] === sdkKids[1]
  || sdkKids[1] !== futureKid
  || coordinator.status !== 'ready'
  || failures.length !== 0
  || lifecycle.includes('reconnecting')
  || socketConnections !== 1) {
  throw new Error('Coordinator rotation did not remain on one healthy session');
}

let browser;
let page;
let browserClientStopped = false;
let browserClosed = false;
let browserWebSockets = 0;
let activeBrowserWebSockets = 0;
let maximumActiveBrowserWebSockets = 0;
const browserWebSocketURLs = [];
let browserSentFrames = 0;
let sourceCredentialsOnWebSocket = false;
let browserPageErrors = 0;
let observedUserExchangePosts = 0;
let browserConsoleErrors = 0;
let userExchangeRequestFailures = 0;
const userExchangeResponses = [];
let browserBoundary;
let patchedBrowserState;
let handoffBrowserState;
let secondaryCoordinator;
let secondaryCoordinatorStopped = false;
try {
  browser = await chromium.launch({ headless: true });
  const context = await browser.newContext({ ignoreHTTPSErrors: true });
  await context.addInitScript((value) => {
    Object.defineProperty(globalThis, '__miakappIntegrationBootstrap', {
      configurable: true,
      enumerable: false,
      value,
      writable: false,
    });
  }, {
    schema: 'miakapp.browser-source-bootstrap/1',
    exchangeEndpoint: userExchangeURL.href,
    homeId: browserSource.homeId,
    firebaseIdToken: browserSource.firebaseIdToken,
    appCheckToken: browserSource.appCheckToken,
  });
  page = await context.newPage();
  page.on('websocket', (webSocket) => {
    browserWebSockets += 1;
    activeBrowserWebSockets += 1;
    maximumActiveBrowserWebSockets = Math.max(
      maximumActiveBrowserWebSockets,
      activeBrowserWebSockets,
    );
    browserWebSocketURLs.push(webSocket.url());
    webSocket.on('close', () => { activeBrowserWebSockets -= 1; });
    webSocket.on('framesent', ({ payload }) => {
      browserSentFrames += 1;
      const bytes = typeof payload === 'string' ? Buffer.from(payload, 'utf8') : payload;
      sourceCredentialsOnWebSocket ||= bytes.includes(Buffer.from(
        browserSource.firebaseIdToken,
        'ascii',
      )) || bytes.includes(Buffer.from(browserSource.appCheckToken, 'ascii'));
    });
  });
  page.on('pageerror', () => { browserPageErrors += 1; });
  page.on('console', (message) => {
    if (message.type() !== 'error') return;
    browserConsoleErrors += 1;
  });
  page.on('request', (request) => {
    if (request.url() === userExchangeURL.href && request.method() === 'POST') {
      observedUserExchangePosts += 1;
    }
  });
  page.on('requestfailed', (request) => {
    if (request.url() !== userExchangeURL.href) return;
    userExchangeRequestFailures += 1;
  });
  page.on('response', (response) => {
    if (response.url() === userExchangeURL.href) {
      userExchangeResponses.push({
        method: response.request().method(),
        status: response.status(),
      });
    }
  });
  await page.goto(browserURL.href, { waitUntil: 'load' });

  let browserStartTimer;
  const browserReady = await Promise.race([
    page.evaluate(() => globalThis.miakappIntegration.start()),
    new Promise((_, reject) => {
      browserStartTimer = setTimeout(
        () => reject(new Error('Browser readiness timed out')),
        15_000,
      );
    }),
  ]).finally(() => clearTimeout(browserStartTimer));
  assert.equal(browserReady.enrolled, true);
  assert.equal(browserReady.coordinatorCount, 1);
  await waitUntil(
    () => page.evaluate(() => globalThis.miakappIntegration.state())
      .then((state) => state?.temperature === 20 && state.stale === false),
    'Authoritative browser state',
  );

  await coordinator.state.set([{ path: 'integration.temperature', value: 21 }]);
  patchedBrowserState = await waitUntil(
    async () => {
      const state = await page.evaluate(() => globalThis.miakappIntegration.state());
      return state?.temperature === 21 && state.stale === false ? state : undefined;
    },
    'Browser state patch',
  );
  const initialCall = await page.evaluate(
    () => globalThis.miakappIntegration.call(22),
  );
  assert.deepEqual(initialCall, { accepted: true, arguments: { target: 22 } });

  browserBoundary = await page.evaluate(() => globalThis.miakappIntegration.boundary());
  assert.deepEqual(browserBoundary.credentialReasons, ['initial']);
  assert.equal(browserBoundary.pendingControlledTimers, 1);
  await page.evaluate(() => globalThis.miakappIntegration.fireReauthentication());
  await waitUntil(async () => {
    const [boundary, relayState] = await Promise.all([
      page.evaluate(() => globalThis.miakappIntegration.boundary()),
      relayAction('status'),
    ]);
    return boundary.httpsExchanges === 2
      && boundary.credentialReasons[1] === 'reauth'
      && relayState.successful_user_verifications === 2;
  }, 'Browser same-socket reauthentication');

  const postReauthenticationCall = await page.evaluate(
    () => globalThis.miakappIntegration.call(23),
  );
  assert.deepEqual(postReauthenticationCall, { accepted: true, arguments: { target: 23 } });
  const sameRelayBrowserStatus = await page.evaluate(() => ({
    boundary: globalThis.miakappIntegration.boundary(),
    failures: globalThis.miakappIntegration.failures(),
    statuses: globalThis.miakappIntegration.statuses(),
  }));
  browserBoundary = sameRelayBrowserStatus.boundary;
  assert.deepEqual(browserBoundary.credentialReasons, ['initial', 'reauth']);
  assert.equal(browserBoundary.firebaseTokenRequests, 2);
  assert.equal(browserBoundary.appCheckTokenRequests, 2);
  assert.equal(browserBoundary.httpsExchanges, 2);
  assert.equal(browserBoundary.sourceHeadersConformant, true);
  assert.equal(browserBoundary.emulatorAuthAdapted, true);
  assert.equal(browserBoundary.pendingControlledTimers, 1);
  assert.deepEqual(sameRelayBrowserStatus.failures, []);
  assert.equal(sameRelayBrowserStatus.statuses.at(-1), 'ready');
  assert.equal(sameRelayBrowserStatus.statuses.includes('reconnecting'), false);
  assert.equal(observedUserExchangePosts, 2);
  assert.equal(browserWebSockets, 1);
  assert.ok(browserSentFrames > 0);
  assert.equal(sourceCredentialsOnWebSocket, false);
  assert.equal(browserPageErrors, 0);
  assert.equal(browserConsoleErrors, 0);
  assert.equal(userExchangeRequestFailures, 0);

  await controlAction('route_relay', { relay_url: secondaryRelayURL.href });
  secondaryCoordinator = createCoordinatorWithRuntime({
    name: 'integration',
    accessTokenProvider: directProvider,
    logger: {
      write(record) {
        if (record.level === 'error') failures.push(record);
      },
    },
  }, productionRuntime);
  configureIntegrationCoordinator(secondaryCoordinator);
  const secondaryStartController = new AbortController();
  const secondaryStartTimeout = setTimeout(
    () => secondaryStartController.abort(new Error('Secondary coordinator readiness timed out')),
    10_000,
  );
  let secondaryReady;
  try {
    secondaryReady = await secondaryCoordinator.start({ signal: secondaryStartController.signal });
  } finally {
    clearTimeout(secondaryStartTimeout);
  }
  assert.equal(secondaryReady.generation, 1);
  assert.equal(secondaryCoordinator.status, 'ready');
  assert.equal((await secondaryRelayAction('status')).successful_coordinator_verifications, 1);
  assert.equal((await relayAction('status')).successful_user_verifications, 2);

  await page.evaluate(() => globalThis.miakappIntegration.fireReauthentication());
  await waitUntil(async () => {
    const [boundary, secondaryRelayState, status] = await Promise.all([
      page.evaluate(() => globalThis.miakappIntegration.boundary()),
      secondaryRelayAction('status'),
      page.evaluate(() => globalThis.miakappIntegration.statuses().at(-1)),
    ]);
    return boundary.httpsExchanges === 3
      && boundary.credentialReasons[2] === 'reauth'
      && secondaryRelayState.successful_user_verifications === 1
      && browserWebSockets === 2
      && status === 'ready';
  }, 'Browser authoritative relay handoff');
  await waitUntil(
    () => activeBrowserWebSockets === 1,
    'Old browser WebSocket closure',
  );
  handoffBrowserState = await waitUntil(
    async () => {
      const state = await page.evaluate(() => globalThis.miakappIntegration.state());
      return state?.temperature === 20 && state.stale === false ? state : undefined;
    },
    'Browser state after relay handoff',
  );
  await secondaryCoordinator.state.set([{ path: 'integration.temperature', value: 24 }]);
  handoffBrowserState = await waitUntil(
    async () => {
      const state = await page.evaluate(() => globalThis.miakappIntegration.state());
      return state?.temperature === 24 && state.stale === false ? state : undefined;
    },
    'Browser state patch after relay handoff',
  );
  const postHandoffCall = await page.evaluate(
    () => globalThis.miakappIntegration.call(24),
  );
  assert.deepEqual(postHandoffCall, { accepted: true, arguments: { target: 24 } });

  const handoffBrowserStatus = await page.evaluate(() => ({
    boundary: globalThis.miakappIntegration.boundary(),
    failures: globalThis.miakappIntegration.failures(),
    statuses: globalThis.miakappIntegration.statuses(),
  }));
  browserBoundary = handoffBrowserStatus.boundary;
  assert.deepEqual(browserBoundary.credentialReasons, ['initial', 'reauth', 'reauth']);
  assert.equal(browserBoundary.firebaseTokenRequests, 3);
  assert.equal(browserBoundary.appCheckTokenRequests, 3);
  assert.equal(browserBoundary.httpsExchanges, 3);
  assert.equal(browserBoundary.sourceHeadersConformant, true);
  assert.equal(browserBoundary.pendingControlledTimers, 1);
  assert.deepEqual(handoffBrowserStatus.failures, []);
  assert.equal(handoffBrowserStatus.statuses.at(-1), 'ready');
  assert.equal(handoffBrowserStatus.statuses.includes('reconnecting'), true);
  assert.equal(handoffBrowserStatus.statuses.includes('failed'), false);
  assert.equal(observedUserExchangePosts, 3);
  assert.deepEqual(browserWebSocketURLs, [relayURL.href, secondaryRelayURL.href]);
  assert.equal(browserWebSockets, 2);
  assert.equal(maximumActiveBrowserWebSockets, 1);
  assert.equal(sourceCredentialsOnWebSocket, false);
  assert.equal(browserPageErrors, 0);
  assert.equal(browserConsoleErrors, 0);
  assert.equal(userExchangeRequestFailures, 0);

  await page.evaluate(() => globalThis.miakappIntegration.stop());
  browserClientStopped = true;
  await browser.close();
  browserClosed = true;
  await secondaryCoordinator.stop({ deadlineMs: 2_000 });
  secondaryCoordinatorStopped = true;
  assert.equal(secondaryCoordinator.status, 'stopped');
} catch {
  const pageState = page === undefined ? undefined : await page.evaluate(() => ({
    boundary: globalThis.miakappIntegration?.boundary(),
    failures: globalThis.miakappIntegration?.failures(),
    statuses: globalThis.miakappIntegration?.statuses(),
  })).catch(() => undefined);
  process.stderr.write(`${JSON.stringify({
    schema: 'miakapp.browser-relay-integration-diagnostic/1',
    browser_websockets: browserWebSockets,
    maximum_active_browser_websockets: maximumActiveBrowserWebSockets,
    page_errors: browserPageErrors,
    console_errors: browserConsoleErrors,
    browser_sent_frames: browserSentFrames,
    source_credentials_on_websocket: sourceCredentialsOnWebSocket,
    user_exchange_posts: observedUserExchangePosts,
    user_exchange_request_failures: userExchangeRequestFailures,
    user_exchange_responses: userExchangeResponses,
    page_state: pageState,
  })}\n`);
  throw new Error('Browser relay integration failed');
} finally {
  if (!browserClientStopped && page !== undefined) {
    await page.evaluate(() => globalThis.miakappIntegration?.stop()).catch(() => undefined);
  }
  if (!browserClosed && browser !== undefined) await browser.close().catch(() => undefined);
  if (!secondaryCoordinatorStopped && secondaryCoordinator !== undefined) {
    await secondaryCoordinator.stop({ deadlineMs: 2_000 }).catch(() => undefined);
  }
}

await coordinator.stop({ deadlineMs: 2_000 });
if (coordinator.status !== 'stopped') throw new Error('Coordinator did not stop cleanly');
assert.equal(socketConnections, 1);

const expectedControlEvidence = {
  schema: 'miakapp.relay-integration-jwks/1',
  phase: 'activated',
  held: false,
  failing: false,
  jwks: {
    requests: 9,
    conditional_requests: 6,
    in_flight: 0,
    maximum_in_flight: 1,
    responses: {
      ok: 5,
      not_modified: 3,
      unavailable: 1,
      other: 0,
    },
  },
};
const expectedRelayEvidence = {
  schema: 'miakapp.relay-integration-evidence/3',
  successful_coordinator_verifications: 2,
  successful_user_verifications: 2,
  coordinator_principal_consistent: true,
  user_principal_consistent: true,
  unexpected_roles: 0,
  relay_warmup_successes: 1,
  probe_clock_offset_milliseconds: 133_000,
  probe: {
    requests: 101,
    in_flight: 0,
    maximum_in_flight: 32,
    succeeded: 35,
    rejected: 64,
    temporary: 2,
  },
};
const expectedSecondaryRelayEvidence = {
  schema: 'miakapp.relay-integration-evidence/3',
  successful_coordinator_verifications: 1,
  successful_user_verifications: 1,
  coordinator_principal_consistent: true,
  user_principal_consistent: true,
  unexpected_roles: 0,
  relay_warmup_successes: 0,
  probe_clock_offset_milliseconds: 0,
  probe: {
    requests: 0,
    in_flight: 0,
    maximum_in_flight: 0,
    succeeded: 0,
    rejected: 0,
    temporary: 0,
  },
};
const finalControlState = await controlAction('status');
const finalRelayState = await relayAction('status');
const finalSecondaryRelayState = await secondaryRelayAction('status');
assert.deepEqual(finalControlState, expectedControlEvidence);
assert.deepEqual(finalRelayState, expectedRelayEvidence);
assert.deepEqual(finalSecondaryRelayState, expectedSecondaryRelayEvidence);
assert.deepEqual(
  jsonFile(controlEvidenceFile, 'miakapp.relay-integration-jwks/1'),
  expectedControlEvidence,
);
assert.deepEqual(
  jsonFile(relayEvidenceFile, 'miakapp.relay-integration-evidence/3'),
  expectedRelayEvidence,
);
assert.deepEqual(
  jsonFile(secondaryRelayEvidenceFile, 'miakapp.relay-integration-evidence/3'),
  expectedSecondaryRelayEvidence,
);
assert.equal(statSync(controlEvidenceFile).mode & 0o777, 0o600);
assert.equal(statSync(relayEvidenceFile).mode & 0o777, 0o600);
assert.equal(statSync(secondaryRelayEvidenceFile).mode & 0o777, 0o600);
fixtureAgent.destroy();

process.stdout.write(`${JSON.stringify({
  schema: 'miakapp.relay-auth-integration/4',
  generation: ready.generation,
  coordinator_exchange_reasons: reasons,
  browser_exchange_reasons: browserBoundary.credentialReasons,
  signing_key_changed: true,
  successful_coordinator_verifications:
    expectedRelayEvidence.successful_coordinator_verifications,
  successful_user_verifications: expectedRelayEvidence.successful_user_verifications,
  secondary_coordinator_verifications:
    expectedSecondaryRelayEvidence.successful_coordinator_verifications,
  secondary_user_verifications:
    expectedSecondaryRelayEvidence.successful_user_verifications,
  browser_state_before_handoff: patchedBrowserState.temperature,
  browser_state_after_handoff: handoffBrowserState.temperature,
  browser_calls: 3,
  browser: 'chromium',
  browser_websockets: browserWebSockets,
  browser_handoffs: browserWebSockets - 1,
  maximum_active_browser_websockets: maximumActiveBrowserWebSockets,
  browser_sent_frames: browserSentFrames,
  source_credentials_on_websocket: sourceCredentialsOnWebSocket,
  user_exchange_posts: observedUserExchangePosts,
  jwks_requests: expectedControlEvidence.jwks.requests,
  concurrent_verifications: 32,
  reconnects: socketConnections - 1,
  status: 'conformant',
})}\n`);
