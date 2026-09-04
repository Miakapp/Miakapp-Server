import { createRequire } from 'node:module';
import { pathToFileURL } from 'node:url';
import path from 'node:path';
import process from 'node:process';

const [miakapiRepository, relayUrl] = process.argv.slice(2);
if (!miakapiRepository || !relayUrl) {
  throw new Error('Usage: node miakapi.mjs <miakapi-repository> <relay-url>');
}

const moduleUrl = pathToFileURL(path.join(miakapiRepository, 'dist/index.js')).href;
const codecUrl = pathToFileURL(path.join(miakapiRepository, 'dist/protocol/codec.js')).href;
const { createCoordinator, EventDirection } = await import(moduleUrl);
const { decodeFrame, encodeFrame, Opcode } = await import(codecUrl);
const requireFromMiakAPI = createRequire(path.join(miakapiRepository, 'package.json'));
const WebSocket = requireFromMiakAPI('ws');

class RawUser {
  #socket;
  #frames = [];
  #waiters = [];
  #failure;

  constructor(socket) {
    this.#socket = socket;
    socket.on('message', (data, isBinary) => {
      if (!isBinary) {
        this.#rejectAll(new Error('Relay sent text to the integration user'));
        return;
      }
      let frame;
      try {
        frame = decodeFrame(new Uint8Array(data.buffer, data.byteOffset, data.byteLength));
      } catch (error) {
        this.#rejectAll(error);
        return;
      }
      const waiter = this.#waiters.shift();
      if (waiter) waiter.resolve(frame);
      else this.#frames.push(frame);
    });
    socket.on('error', (error) => this.#rejectAll(error));
    socket.on('close', (code, reason) => {
      if (code !== 1000) {
        this.#rejectAll(new Error(`User WebSocket closed with ${code}: ${reason.toString()}`));
      }
    });
  }

  static async connect(url) {
    const socket = new WebSocket(url, 'miakapp', {
      followRedirects: false,
      maxPayload: 262_144,
      perMessageDeflate: false,
    });
    await new Promise((resolve, reject) => {
      socket.once('open', resolve);
      socket.once('error', reject);
    });
    return new RawUser(socket);
  }

  send(frame) {
    if (this.#failure) throw this.#failure;
    this.#socket.send(encodeFrame(frame), { binary: true, compress: false });
  }

  async next(expectedOpcode) {
    if (this.#failure) throw this.#failure;
    const frame = this.#frames.shift() ?? await Promise.race([
      new Promise((resolve, reject) => this.#waiters.push({ resolve, reject })),
      new Promise((_, reject) => setTimeout(
        () => reject(new Error(`Timed out waiting for opcode 0x${expectedOpcode.toString(16)}`)),
        2_000,
      )),
    ]);
    if (frame.opcode !== expectedOpcode) {
      throw new Error(
        `Expected opcode 0x${expectedOpcode.toString(16)}, received 0x${frame.opcode.toString(16)}`,
      );
    }
    return frame;
  }

  async close() {
    if (this.#socket.readyState === WebSocket.CLOSED) return;
    const closed = new Promise((resolve) => this.#socket.once('close', resolve));
    this.#socket.close(1000, 'integration_complete');
    await closed;
  }

  #rejectAll(error) {
    this.#failure = error instanceof Error ? error : new Error('Raw user transport failed');
    for (const waiter of this.#waiters.splice(0)) waiter.reject(this.#failure);
  }
}

const failures = [];
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
      if (record.level === 'error') failures.push(record);
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

const ready = await coordinator.start();
if (ready.generation !== 1 || coordinator.status !== 'ready') {
  throw new Error(`Coordinator did not reach generation 1 readiness: ${JSON.stringify(ready)}`);
}

const user = await RawUser.connect(relayUrl);
user.send({
  opcode: Opcode.Hello,
  payload: [1, 0, 0, 1, 'integration-user-token', ['integration-home']],
});
const welcome = await user.next(Opcode.Welcome);
if (welcome.payload[4] !== true) throw new Error('Integration user was not enrolled');
const stateDictionary = await user.next(Opcode.StateDict);
const snapshot = await user.next(Opcode.StateSnapshot);
await user.next(Opcode.TopicDict);
const functionDictionary = await user.next(Opcode.FunctionDict);

const stateEntry = stateDictionary.payload[2][0];
if (!Array.isArray(stateEntry) || stateEntry[1] !== 'integration.temperature') {
  throw new Error(`Unexpected state dictionary: ${JSON.stringify(stateDictionary.payload)}`);
}
if (snapshot.payload[2][0]?.[1] !== 20) {
  throw new Error(`Unexpected initial state: ${JSON.stringify(snapshot.payload)}`);
}
const functionEntry = functionDictionary.payload[2][0];
if (!Array.isArray(functionEntry) || functionEntry[1] !== 'integration.set') {
  throw new Error(`Unexpected function dictionary: ${JSON.stringify(functionDictionary.payload)}`);
}

const stateMutation = coordinator.state.set([
  { path: 'integration.temperature', value: 21 },
]);
const patch = await user.next(Opcode.StatePatch);
await stateMutation;
if (patch.payload[3][0]?.[2] !== 21) {
  throw new Error(`Unexpected state patch: ${JSON.stringify(patch.payload)}`);
}

user.send({
  opcode: Opcode.Call,
  payload: [71, 0, null, functionEntry[0], 5_000, 'integration-intent', 1, { target: 22 }],
});
await user.next(Opcode.CallAccepted);
const result = await user.next(Opcode.CallResult);
if (result.payload[0] !== 71
  || result.payload[1] !== true
  || result.payload[2]?.accepted !== true
  || result.payload[2]?.arguments?.target !== 22) {
  throw new Error(`Unexpected call result: ${JSON.stringify(result.payload)}`);
}

user.send({
  opcode: Opcode.Reauth,
  payload: [72, 'integration-user-token-new'],
});
await user.next(Opcode.ReauthOk);

await user.close();
await coordinator.stop({ deadlineMs: 2_000 });
if (coordinator.status !== 'stopped' || failures.length !== 0) {
  throw new Error(`Coordinator stopped with failures: ${JSON.stringify(failures)}`);
}

process.stdout.write(`${JSON.stringify({
  generation: ready.generation,
  state: 21,
  call: 'succeeded',
  reauthenticated: true,
})}\n`);
