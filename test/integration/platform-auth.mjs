import assert from 'node:assert/strict';
import { readFileSync, statSync } from 'node:fs';
import { Agent, request as httpsRequest } from 'node:https';
import path from 'node:path';
import process from 'node:process';
import { pathToFileURL } from 'node:url';

const [
  miakapiRepository,
  controlMetadataFile,
  relayMetadataFile,
  homeKeyFile,
  controlSecretFile,
  relaySecretFile,
  controlEvidenceFile,
  relayEvidenceFile,
] = process.argv.slice(2);
if ([
  miakapiRepository,
  controlMetadataFile,
  relayMetadataFile,
  homeKeyFile,
  controlSecretFile,
  relaySecretFile,
  controlEvidenceFile,
  relayEvidenceFile,
].some((value) => value === undefined)) {
  throw new Error(
    'Usage: node platform-auth.mjs <MiakAPI> <control-metadata> <relay-metadata> '
      + '<home-key> <control-secret> <relay-secret> <control-evidence> <relay-evidence>',
  );
}

function exactObject(value, keys, description) {
  if (value === null
    || Array.isArray(value)
    || typeof value !== 'object'
    || Object.keys(value).length !== keys.length
    || keys.some((key) => !Object.hasOwn(value, key))) {
    throw new Error(`${description} is invalid`);
  }
  return value;
}

function jsonFile(file, schema) {
  const value = JSON.parse(readFileSync(file, 'utf8'));
  if (value === null || Array.isArray(value) || typeof value !== 'object' || value.schema !== schema) {
    throw new Error('Platform integration file is invalid');
  }
  return value;
}

const control = exactObject(
  jsonFile(controlMetadataFile, 'miakapp.relay-integration-control/1'),
  ['schema', 'controlUrl', 'controlEndpoint', 'exchangeEndpoint', 'jwksUrl'],
  'Control-plane metadata',
);
const relay = exactObject(
  jsonFile(relayMetadataFile, 'miakapp.relay-integration-relay/1'),
  ['schema', 'relayUrl', 'controlEndpoint', 'verifyEndpoint'],
  'Relay metadata',
);
const homeKey = readFileSync(homeKeyFile, 'ascii');
const controlSecret = readFileSync(controlSecretFile, 'ascii').trim();
const relaySecret = readFileSync(relaySecretFile, 'ascii').trim();
if (typeof control.exchangeEndpoint !== 'string'
  || typeof control.controlEndpoint !== 'string'
  || typeof relay.relayUrl !== 'string'
  || typeof relay.controlEndpoint !== 'string'
  || typeof relay.verifyEndpoint !== 'string'
  || !control.controlEndpoint.startsWith('https://127.0.0.1:')
  || !relay.controlEndpoint.startsWith('https://127.0.0.1:')
  || !relay.verifyEndpoint.startsWith('https://127.0.0.1:')
  || !relay.relayUrl.startsWith('wss://127.0.0.1:')
  || !relay.relayUrl.endsWith('/ws')
  || !/^mhk1_[A-Za-z0-9_-]{22}_[A-Za-z0-9_-]{43}$/.test(homeKey)
  || !/^[0-9a-f]{64}$/.test(controlSecret)
  || !/^[0-9a-f]{64}$/.test(relaySecret)) {
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

async function controlAction(action) {
  const response = await fixtureRequest(control.controlEndpoint, controlSecret, { action });
  assert.equal(response.status, 200, `Control action ${action} failed`);
  return response.value;
}

async function relayAction(action, offsetMilliseconds) {
  const body = offsetMilliseconds === undefined
    ? { action }
    : { action, offset_ms: offsetMilliseconds };
  const response = await fixtureRequest(relay.controlEndpoint, relaySecret, body);
  assert.equal(response.status, 200, `Relay action ${action} failed`);
  return response.value;
}

async function verifyToken(target, token) {
  const response = await fixtureRequest(relay.verifyEndpoint, relaySecret, { target, token });
  return response.status;
}

async function waitUntil(predicate, description, milliseconds = 10_000) {
  const deadline = Date.now() + milliseconds;
  while (Date.now() < deadline) {
    if (await predicate()) return;
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
const { createHomeKeyAccessTokenProvider } = await import(indexUrl);
const { createCoordinatorWithRuntime } = await import(coordinatorUrl);
const { createProductionRuntime } = await import(socketUrl);

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
// Preserve real timers and sockets while placing the five-minute lease about
// fifteen seconds from reauthentication. Probe-cache time travel is independent.
const runtime = Object.freeze({
  socketFactory: productionRuntime.socketFactory,
  now: () => Date.now() + 270_000,
  random: () => 0,
  setTimer: productionRuntime.setTimer,
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
coordinator.configure({
  state: { 'integration.temperature': 20 },
  stateAccess: [],
  events: [],
  eventAccess: [],
  functions: {},
});

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

await waitUntil(() => {
  try {
    return jsonFile(
      relayEvidenceFile,
      'miakapp.relay-integration-evidence/2',
    ).successful_coordinator_verifications >= 2;
  } catch {
    return false;
  }
}, 'Scheduled same-session reauthentication', 25_000);

if (reasons.length !== 2
  || reasons[0] !== 'initial'
  || reasons[1] !== 'reauth'
  || sdkKids.length !== 2
  || sdkKids[0] === sdkKids[1]
  || sdkKids[1] !== futureKid
  || coordinator.status !== 'ready'
  || failures.length !== 0
  || lifecycle.includes('reconnecting')) {
  throw new Error('Coordinator rotation did not remain on one healthy session');
}
await coordinator.stop({ deadlineMs: 2_000 });
if (coordinator.status !== 'stopped') throw new Error('Coordinator did not stop cleanly');

const expectedControlEvidence = {
  schema: 'miakapp.relay-integration-jwks/1',
  phase: 'activated',
  held: false,
  failing: false,
  jwks: {
    requests: 8,
    conditional_requests: 6,
    in_flight: 0,
    maximum_in_flight: 1,
    responses: {
      ok: 4,
      not_modified: 3,
      unavailable: 1,
      other: 0,
    },
  },
};
const expectedRelayEvidence = {
  schema: 'miakapp.relay-integration-evidence/2',
  successful_coordinator_verifications: 2,
  principal_consistent: true,
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
const finalControlState = await controlAction('status');
const finalRelayState = await relayAction('status');
assert.deepEqual(finalControlState, expectedControlEvidence);
assert.deepEqual(finalRelayState, expectedRelayEvidence);
assert.deepEqual(
  jsonFile(controlEvidenceFile, 'miakapp.relay-integration-jwks/1'),
  expectedControlEvidence,
);
assert.deepEqual(
  jsonFile(relayEvidenceFile, 'miakapp.relay-integration-evidence/2'),
  expectedRelayEvidence,
);
assert.equal(statSync(controlEvidenceFile).mode & 0o777, 0o600);
assert.equal(statSync(relayEvidenceFile).mode & 0o777, 0o600);
fixtureAgent.destroy();

process.stdout.write(`${JSON.stringify({
  schema: 'miakapp.relay-auth-integration/2',
  generation: ready.generation,
  exchange_reasons: reasons,
  signing_key_changed: true,
  successful_relay_verifications: expectedRelayEvidence.successful_coordinator_verifications,
  jwks_requests: expectedControlEvidence.jwks.requests,
  concurrent_verifications: 32,
  reconnects: 0,
  status: 'conformant',
})}\n`);
