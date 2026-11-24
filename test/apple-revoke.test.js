import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { generateKeyPairSync, sign, verify } from 'node:crypto';

const dir = mkdtempSync(join(tmpdir(), 'seeli-apple-'));
const ec = generateKeyPairSync('ec', { namedCurve: 'P-256' });
writeFileSync(join(dir, 'AuthKey.p8'), ec.privateKey.export({ type: 'pkcs8', format: 'pem' }));
Object.assign(process.env, {
  DATA_DIR: dir, AUTH_RATE_LIMIT: '1000',
  APPLE_TEAM_ID: 'TEAM123', APPLE_KEY_ID: 'KEY456', APPLE_KEY_PATH: join(dir, 'AuthKey.p8'),
});

// Fake Apple endpoints; everything else goes to the real fetch.
const calls = [];
const realFetch = globalThis.fetch;
globalThis.fetch = async (url, opts) => {
  if (!String(url).startsWith('https://appleid.apple.com/auth/')) return realFetch(url, opts);
  const params = Object.fromEntries(new URLSearchParams(opts.body));
  calls.push({ path: new URL(url).pathname, params });
  // The client_secret must be an ES256 JWT signed by our .p8 key.
  const [h, b, s] = params.client_secret.split('.');
  assert.equal(JSON.parse(Buffer.from(h, 'base64url')).kid, 'KEY456');
  const claims = JSON.parse(Buffer.from(b, 'base64url'));
  assert.equal(claims.iss, 'TEAM123');
  assert.equal(claims.sub, 'com.tunnaduong.seeli');
  assert.ok(verify('sha256', Buffer.from(`${h}.${b}`), { key: ec.publicKey, dsaEncoding: 'ieee-p1363' }, Buffer.from(s, 'base64url')));
  if (url.endsWith('/auth/token')) {
    return new Response(JSON.stringify({ refresh_token: `rt-${params.code}`, id_token: 'x' }), { status: 200 });
  }
  return new Response('', { status: 200 });
};

const { buildApp } = await import('../src/server.js');
const { _setKeysForTest } = await import('../src/oidc.js');
const app = buildApp({ logger: false });

const rsa = generateKeyPairSync('rsa', { modulusLength: 2048 });
_setKeysForTest('apple', new Map([['k1', rsa.publicKey]]));
const b64 = (o) => Buffer.from(JSON.stringify(o)).toString('base64url');
const appleToken = (sub) => {
  const head = b64({ alg: 'RS256', kid: 'k1' });
  const body = b64({ iss: 'https://appleid.apple.com', aud: 'com.tunnaduong.seeli', sub, exp: Math.floor(Date.now() / 1000) + 600 });
  return `${head}.${body}.${sign('RSA-SHA256', Buffer.from(`${head}.${body}`), rsa.privateKey).toString('base64url')}`;
};
const req = async (method, url, body, token) => {
  const r = await app.inject({ method, url: `/v1${url}`, payload: body, headers: token ? { authorization: `Bearer ${token}` } : {} });
  return { status: r.statusCode, json: r.json() };
};

test('Apple access is revoked when the account is deleted', async () => {
  // Sign-in with an authorization code → refresh token stored.
  const a = await req('POST', '/auth/apple', { idToken: appleToken('apple-A'), authorizationCode: 'code-A', name: 'An' });
  assert.equal(a.status, 201);
  assert.deepEqual(calls.map((c) => c.path), ['/auth/token']);

  const del = await req('DELETE', '/me', undefined, a.json.token);
  assert.equal(del.status, 200);
  assert.equal(del.json.appleRevoked, true);
  const revoke = calls.at(-1);
  assert.equal(revoke.path, '/auth/revoke');
  assert.equal(revoke.params.token, 'rt-code-A');
  assert.equal(revoke.params.token_type_hint, 'refresh_token');

  // Older account without a stored token: server asks the app to re-authenticate first.
  const b = await req('POST', '/auth/apple', { idToken: appleToken('apple-B'), name: 'Bình' });
  assert.equal((await req('DELETE', '/me', undefined, b.json.token)).status, 409);
  const del2 = await req('DELETE', '/me', { appleAuthorizationCode: 'code-B2' }, b.json.token);
  assert.equal(del2.status, 200);
  assert.equal(del2.json.appleRevoked, true);
  assert.equal(calls.at(-1).params.token, 'rt-code-B2');

  // Accounts without Apple are unaffected.
  const c = await req('POST', '/auth/signup', { name: 'C', handle: 'ccc', email: 'c@seeli.test', password: 'password123' });
  const del3 = await req('DELETE', '/me', undefined, c.json.token);
  assert.equal(del3.status, 200);
  assert.equal(del3.json.appleRevoked, undefined);
});
