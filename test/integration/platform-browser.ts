import type {
  BrowserClientFailure,
  BrowserClientStatus,
  BrowserRelayCredentialReason,
} from 'miakapi/browser';
import {
  createBrowserClient,
  createControlPlaneBrowserRelayCredentialProvider,
} from 'miakapi/browser';

interface BrowserBootstrap {
  readonly schema: 'miakapp.browser-source-bootstrap/1';
  readonly exchangeEndpoint: string;
  readonly homeId: string;
  readonly firebaseIdToken: string;
  readonly appCheckToken: string;
}

interface BrowserIntegrationFailure {
  readonly kind: BrowserClientFailure['kind'];
  readonly code?: number;
  readonly outcome: BrowserClientFailure['outcome'];
}

interface BrowserIntegration {
  start(): Promise<{ enrolled: boolean; coordinatorCount: number }>;
  state(): { revision: number; stale: boolean; temperature: unknown } | undefined;
  call(target: number): Promise<unknown>;
  fireReauthentication(): number;
  boundary(): Readonly<{
    credentialReasons: readonly BrowserRelayCredentialReason[];
    firebaseTokenRequests: number;
    appCheckTokenRequests: number;
    httpsExchanges: number;
    sourceHeadersConformant: boolean;
    emulatorAuthAdapted: boolean;
    pendingControlledTimers: number;
  }>;
  statuses(): readonly BrowserClientStatus[];
  failures(): readonly BrowserIntegrationFailure[];
  stop(): Promise<void>;
}

interface BrowserGlobal {
  __miakappIntegrationBootstrap?: BrowserBootstrap;
  miakappIntegration?: BrowserIntegration;
}

function isExactObject(value: unknown, keys: readonly string[]): value is Record<string, unknown> {
  return value !== null
    && !Array.isArray(value)
    && typeof value === 'object'
    && Object.keys(value).length === keys.length
    && keys.every((key) => Object.hasOwn(value, key));
}

function sourceToken(value: unknown): value is string {
  return typeof value === 'string'
    && value.length > 0
    && value.length <= 8_192
    && /^[\x21-\x7e]+$/.test(value)
    && value.split('.').length === 3;
}

const browserGlobal = globalThis as unknown as BrowserGlobal;
const bootstrap = browserGlobal.__miakappIntegrationBootstrap;
if (!isExactObject(bootstrap, [
  'schema',
  'exchangeEndpoint',
  'homeId',
  'firebaseIdToken',
  'appCheckToken',
])
  || bootstrap.schema !== 'miakapp.browser-source-bootstrap/1'
  || typeof bootstrap.exchangeEndpoint !== 'string'
  || typeof bootstrap.homeId !== 'string'
  || !sourceToken(bootstrap.firebaseIdToken)
  || !sourceToken(bootstrap.appCheckToken)
  || bootstrap.firebaseIdToken === bootstrap.appCheckToken) {
  throw new Error('Browser integration bootstrap is invalid');
}
delete browserGlobal.__miakappIntegrationBootstrap;

const productionFetch = globalThis.fetch.bind(globalThis);
const nativeSetTimeout = globalThis.setTimeout.bind(globalThis);
const nativeClearTimeout = globalThis.clearTimeout.bind(globalThis);
const controlledTimers = new Map<number, () => void>();
let nextControlledTimer = -1;

globalThis.setTimeout = ((handler: TimerHandler, timeout = 0, ...arguments_: unknown[]) => {
  if (typeof handler === 'function' && timeout >= 240_000) {
    const id = nextControlledTimer;
    nextControlledTimer -= 1;
    controlledTimers.set(id, () => handler(...arguments_));
    return id;
  }
  return nativeSetTimeout(handler, timeout, ...arguments_);
}) as typeof globalThis.setTimeout;
globalThis.clearTimeout = ((id: number | undefined) => {
  if (typeof id === 'number' && controlledTimers.delete(id)) return;
  nativeClearTimeout(id);
}) as typeof globalThis.clearTimeout;

const credentialReasons: BrowserRelayCredentialReason[] = [];
const statuses: BrowserClientStatus[] = [];
const failures: BrowserIntegrationFailure[] = [];
let firebaseTokenRequests = 0;
let appCheckTokenRequests = 0;
let httpsExchanges = 0;
let sourceHeadersConformant = true;

function emulatorProviderToken(value: string): string {
  const segments = value.split('.');
  if (segments.length !== 3 || segments[0] === undefined || segments[2] !== '') {
    throw new Error('Browser integration Firebase emulator token is invalid');
  }
  let header: unknown;
  try {
    header = JSON.parse(atob(segments[0].replaceAll('-', '+').replaceAll('_', '/')));
  } catch {
    throw new Error('Browser integration Firebase emulator token is invalid');
  }
  if (!isExactObject(header, ['alg', 'typ'])
    || header.alg !== 'none'
    || header.typ !== 'JWT') {
    throw new Error('Browser integration Firebase emulator token is invalid');
  }
  return `${value}ZW11bGF0b3I`;
}

const providerFirebaseIdToken = emulatorProviderToken(bootstrap.firebaseIdToken);

const instrumentedFetch: typeof globalThis.fetch = async (input, init) => {
  const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
  const headers = new Headers(init?.headers);
  let body: unknown;
  try {
    body = typeof init?.body === 'string' ? JSON.parse(init.body) : undefined;
  } catch {
    body = undefined;
  }
  const requestConformant = url === bootstrap.exchangeEndpoint
    && init?.method === 'POST'
    && headers.get('authorization') === `Bearer ${providerFirebaseIdToken}`
    && headers.get('x-firebase-appcheck') === bootstrap.appCheckToken
    && isExactObject(body, ['home_id', 'reason'])
    && body.home_id === bootstrap.homeId
    && (body.reason === 'initial' || body.reason === 'reauth' || body.reason === 'reconnect')
    && !url.includes(bootstrap.firebaseIdToken)
    && !url.includes(bootstrap.appCheckToken);
  sourceHeadersConformant &&= requestConformant;
  if (!requestConformant) throw new Error('Browser credential request crossed an invalid boundary');
  credentialReasons.push(body.reason as BrowserRelayCredentialReason);
  httpsExchanges += 1;
  const networkHeaders = new Headers(init?.headers);
  networkHeaders.set('authorization', `Bearer ${bootstrap.firebaseIdToken}`);
  return productionFetch(input, { ...init, headers: networkHeaders });
};

const credentialProvider = createControlPlaneBrowserRelayCredentialProvider({
  exchangeEndpoint: bootstrap.exchangeEndpoint,
  async getFirebaseIdToken() {
    firebaseTokenRequests += 1;
    return providerFirebaseIdToken;
  },
  async getAppCheckToken() {
    appCheckTokenRequests += 1;
    return bootstrap.appCheckToken;
  },
  fetch: instrumentedFetch,
});
const client = createBrowserClient({
  homeId: bootstrap.homeId,
  credentialProvider,
});

client.subscribe(({ current }) => statuses.push(current));
client.errors.subscribe((failure) => failures.push(Object.freeze({
  kind: failure.kind,
  ...(failure.code === undefined ? {} : { code: failure.code }),
  outcome: failure.outcome,
})));

browserGlobal.miakappIntegration = Object.freeze({
  async start() {
    const ready = await client.start();
    return Object.freeze({
      enrolled: ready.enrolled,
      coordinatorCount: ready.coordinators.length,
    });
  },
  state() {
    const snapshot = client.state.snapshot();
    if (snapshot === undefined) return undefined;
    return Object.freeze({
      revision: snapshot.revision,
      stale: snapshot.stale,
      temperature: snapshot.values['integration.temperature'],
    });
  },
  async call(target: number) {
    const call = client.calls.start({
      function: 'integration.set',
      arguments: { target },
      timeoutMs: 5_000,
      idempotencyKey: `browser-integration-${target}`,
    });
    await call.accepted;
    return call.result;
  },
  fireReauthentication() {
    const selected = controlledTimers.entries().next().value as [number, () => void] | undefined;
    if (selected === undefined) throw new Error('Browser reauthentication timer is unavailable');
    controlledTimers.delete(selected[0]);
    queueMicrotask(selected[1]);
    return controlledTimers.size;
  },
  boundary() {
    return Object.freeze({
      credentialReasons: Object.freeze([...credentialReasons]),
      firebaseTokenRequests,
      appCheckTokenRequests,
      httpsExchanges,
      sourceHeadersConformant,
      emulatorAuthAdapted: true,
      pendingControlledTimers: controlledTimers.size,
    });
  },
  statuses: () => Object.freeze([...statuses]),
  failures: () => Object.freeze([...failures]),
  async stop() {
    await client.stop({ deadlineMs: 2_000 });
    controlledTimers.clear();
    globalThis.setTimeout = nativeSetTimeout;
    globalThis.clearTimeout = nativeClearTimeout;
  },
});
