import { createPrivateKey, sign } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import process from 'node:process';
import { pathToFileURL } from 'node:url';

const [v3Repository, outputFile] = process.argv.slice(2);
if (v3Repository === undefined || outputFile === undefined || !path.isAbsolute(v3Repository)) {
  throw new Error(
    'Usage: node prepare-browser-source.mjs <absolute-Miakapp-V3-path> <private-output-file>',
  );
}

const authHost = process.env.FIREBASE_AUTH_EMULATOR_HOST;
if (authHost === undefined || !/^127\.0\.0\.1:[0-9]+$/.test(authHost)) {
  throw new Error('Firebase Auth Emulator is required');
}

const projectId = 'demo-miakapp-v4';
const signUp = await fetch(
  `http://${authHost}/identitytoolkit.googleapis.com/v1/accounts:signUp?key=synthetic-api-key`,
  {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      email: 'relay-integration-browser@example.test',
      password: 'synthetic-browser-password-123',
      returnSecureToken: true,
    }),
  },
);
const signedUp = await signUp.json();
if (!signUp.ok
  || typeof signedUp.idToken !== 'string'
  || typeof signedUp.localId !== 'string'
  || signedUp.localId.length === 0
  || signedUp.localId.length > 128) {
  throw new Error(`Synthetic browser Auth signup failed with HTTP ${signUp.status}`);
}

const configModule = pathToFileURL(path.join(
  v3Repository,
  'control-plane/lib/config.js',
)).href;
const { loadEmulatorConfig } = await import(configModule);
const config = loadEmulatorConfig({
  FUNCTIONS_EMULATOR: 'true',
  GCLOUD_PROJECT: projectId,
});
const fixture = JSON.parse(readFileSync(path.join(
  v3Repository,
  'control-plane-contract/fixtures/v1/access-tokens.json',
), 'utf8'));
if (fixture?.provenance?.kind !== 'hand_authored_synthetic'
  || fixture.provenance.contains_production_data !== false
  || fixture?.test_only_private_keys?.warning
    !== 'SYNTHETIC TEST KEYS. NEVER LOAD IN PRODUCTION.') {
  throw new Error('Browser integration signing fixture is not explicitly synthetic');
}
const privateKey = fixture.test_only_private_keys.firebase;
if (privateKey?.kty !== 'RSA'
  || typeof privateKey.kid !== 'string'
  || typeof privateKey.d !== 'string'
  || privateKey.d.length === 0) {
  throw new Error('Browser integration App Check key is invalid');
}

const now = Math.floor(Date.now() / 1_000);
const header = Buffer.from(JSON.stringify({
  alg: 'RS256',
  kid: privateKey.kid,
  typ: 'JWT',
}), 'utf8').toString('base64url');
const claims = Buffer.from(JSON.stringify({
  iss: config.appCheckIssuer,
  aud: [config.appCheckAudience],
  sub: config.appCheckAppId,
  iat: now,
  exp: now + 3_600,
}), 'utf8').toString('base64url');
const signingInput = `${header}.${claims}`;
const signature = sign(
  'RSA-SHA256',
  Buffer.from(signingInput, 'ascii'),
  createPrivateKey({ key: privateKey, format: 'jwk' }),
).toString('base64url');

writeFileSync(outputFile, `${JSON.stringify({
  schema: 'miakapp.browser-source-credentials/1',
  homeId: 'synthetic-relay-home',
  firebaseUid: signedUp.localId,
  firebaseVerifiedEmail: null,
  firebaseIdToken: signedUp.idToken,
  appCheckToken: `${signingInput}.${signature}`,
})}\n`, {
  encoding: 'utf8',
  flag: 'wx',
  mode: 0o600,
});

process.stdout.write(`${JSON.stringify({
  schema: 'miakapp.browser-source-preparation/1',
  firebase_auth: 'emulator',
  app_check: 'synthetic-signed',
  user: 'unenrolled',
  persistent_credentials_created: false,
  ephemeral_private_file: true,
})}\n`);
