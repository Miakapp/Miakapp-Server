import { readFileSync } from 'node:fs';
import path from 'node:path';
import process from 'node:process';
import { pathToFileURL } from 'node:url';

const [miakapiRepository, controlMetadataFile, relayMetadataFile, homeKeyFile, evidenceFile]
  = process.argv.slice(2);
if (miakapiRepository === undefined
  || controlMetadataFile === undefined
  || relayMetadataFile === undefined
  || homeKeyFile === undefined
  || evidenceFile === undefined) {
  throw new Error('Usage: node platform-auth.mjs <MiakAPI> <control-metadata> <relay-metadata> <home-key> <evidence>');
}

function metadata(file, schema) {
  const value = JSON.parse(readFileSync(file, 'utf8'));
  if (value === null || Array.isArray(value) || typeof value !== 'object' || value.schema !== schema) {
    throw new Error('Platform integration metadata is invalid');
  }
  return value;
}

const control = metadata(controlMetadataFile, 'miakapp.relay-integration-control/1');
const relay = metadata(relayMetadataFile, 'miakapp.relay-integration-relay/1');
const homeKey = readFileSync(homeKeyFile, 'ascii');
if (typeof control.exchangeEndpoint !== 'string'
  || typeof relay.relayUrl !== 'string'
  || !/^mhk1_[A-Za-z0-9_-]{22}_[A-Za-z0-9_-]{43}$/.test(homeKey)) {
  throw new Error('Platform integration inputs are invalid');
}

const indexUrl = pathToFileURL(path.join(miakapiRepository, 'dist/index.js')).href;
const coordinatorUrl = pathToFileURL(path.join(miakapiRepository, 'dist/coordinator.js')).href;
const socketUrl = pathToFileURL(path.join(miakapiRepository, 'dist/internal/socket.js')).href;
const { createHomeKeyAccessTokenProvider } = await import(indexUrl);
const { createCoordinatorWithRuntime } = await import(coordinatorUrl);
const { createProductionRuntime } = await import(socketUrl);
const reasons = [];
const provider = createHomeKeyAccessTokenProvider({
  exchangeEndpoint: control.exchangeEndpoint,
  homeKey,
  async fetch(input, init) {
    const body = JSON.parse(init.body);
    reasons.push(body.reason);
    return fetch(input, init);
  },
});
const productionRuntime = createProductionRuntime();
// Keep real timers and sockets but view the five-minute lease near its refresh
// point so the scheduled REAUTH path completes in a bounded integration test.
const runtime = Object.freeze({
  socketFactory: productionRuntime.socketFactory,
  now: () => Date.now() + 296_000,
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
coordinator.subscribe((event) => lifecycle.push(event.current));
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
const ready = await coordinator.start({ signal: startController.signal })
  .finally(() => clearTimeout(startTimeout));
if (ready.generation !== 1 || coordinator.status !== 'ready') {
  throw new Error('Coordinator did not become ready');
}

const deadline = Date.now() + 10_000;
let successfulVerifications = 0;
while (Date.now() < deadline) {
  try {
    const evidence = JSON.parse(readFileSync(evidenceFile, 'utf8'));
    successfulVerifications = evidence.successful_coordinator_verifications;
    if (successfulVerifications >= 2) break;
  } catch {
    // The fixture replaces its evidence atomically; retry while it starts.
  }
  await new Promise((resolve) => setTimeout(resolve, 50));
}
await new Promise((resolve) => setTimeout(resolve, 100));

if (successfulVerifications !== 2
  || reasons.length !== 2
  || reasons[0] !== 'initial'
  || reasons[1] !== 'reauth'
  || coordinator.status !== 'ready'
  || failures.length !== 0
  || lifecycle.includes('reconnecting')) {
  throw new Error('Coordinator authentication integration did not remain on one healthy session');
}
await coordinator.stop({ deadlineMs: 2_000 });
if (coordinator.status !== 'stopped') throw new Error('Coordinator did not stop cleanly');

process.stdout.write(`${JSON.stringify({
  schema: 'miakapp.relay-auth-integration/1',
  generation: ready.generation,
  exchange_reasons: reasons,
  successful_relay_verifications: successfulVerifications,
  reconnects: 0,
  status: 'conformant',
})}\n`);
