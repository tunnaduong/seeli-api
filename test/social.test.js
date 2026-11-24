import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { generateKeyPairSync, sign } from 'node:crypto';

process.env.DATA_DIR = mkdtempSync(join(tmpdir(), 'seeli-social-'));
process.env.AUTH_RATE_LIMIT = '1000';
process.env.GOOGLE_CLIENT_IDS = 'test-ios.apps.googleusercontent.com';
const { buildApp } = await import('../src/server.js');
const { _setKeysForTest } = await import('../src/oidc.js');

const app = buildApp({ logger: false });
const { privateKey, publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
const { privateKey: wrongKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
_setKeysForTest('apple', new Map([['k1', publicKey]]));
_setKeysForTest('google', new Map([['k1', publicKey]]));

const b64 = (o) => Buffer.from(JSON.stringify(o)).toString('base64url');
function jwt(claims, key = privateKey) {
  const head = b64({ alg: 'RS256', kid: 'k1' });
  const body = b64({ iat: Math.floor(Date.now() / 1000), exp: Math.floor(Date.now() / 1000) + 600, ...claims });
  return `${head}.${body}.${sign('RSA-SHA256', Buffer.from(`${head}.${body}`), key).toString('base64url')}`;
}
const apple = (claims) => jwt({ iss: 'https://appleid.apple.com', aud: 'com.tunnaduong.seeli', ...claims });
const google = (claims) => jwt({ iss: 'https://accounts.google.com', aud: 'test-ios.apps.googleusercontent.com', ...claims });

async function post(url, body, token) {
  const res = await app.inject({ method: url.startsWith('/me') ? 'PATCH' : 'POST', url: `/v1${url}`, payload: body,
    headers: token ? { authorization: `Bearer ${token}` } : {} });
  return { status: res.statusCode, json: res.json() };
}

test('sign in with Apple / Google', async () => {
  // New Apple account (hidden email) — name only arrives from the app the first time.
  const a1 = await post('/auth/apple', { idToken: apple({ sub: 'apple-001', email: 'x1y2@privaterelay.appleid.com', email_verified: 'true', nonce: 'n1' }), nonce: 'n1', name: 'Phát' });
  assert.equal(a1.status, 201);
  assert.equal(a1.json.isNew, true);
  assert.equal(a1.json.user.handle, 'phat');
  assert.equal(a1.json.user.hasPassword, false);
  assert.deepEqual(a1.json.user.providers, ['apple']);

  // Same Apple ID again → same account.
  const a2 = await post('/auth/apple', { idToken: apple({ sub: 'apple-001' }) });
  assert.equal(a2.status, 200);
  assert.equal(a2.json.user.id, a1.json.user.id);

  // Wrong nonce, wrong audience, forged signature, expired → rejected.
  assert.equal((await post('/auth/apple', { idToken: apple({ sub: 'apple-001', nonce: 'a' }), nonce: 'b' })).status, 401);
  assert.equal((await post('/auth/apple', { idToken: apple({ sub: 'apple-001', aud: 'com.evil.app' }) })).status, 401);
  assert.equal((await post('/auth/apple', { idToken: jwt({ iss: 'https://appleid.apple.com', aud: 'com.tunnaduong.seeli', sub: 'apple-001' }, wrongKey) })).status, 401);
  assert.equal((await post('/auth/apple', { idToken: apple({ sub: 'apple-001', exp: 1000 }) })).status, 401);
  assert.equal((await post('/auth/google', { idToken: apple({ sub: 'apple-001' }) })).status, 401); // Apple token on Google route

  // Email/password account, then Google with the same verified email → linked, not duplicated.
  const pw = await post('/auth/signup', { name: 'Mika', handle: 'mika', email: 'mika@seeli.test', password: 'password123' });
  const g = await post('/auth/google', { idToken: google({ sub: 'g-777', email: 'Mika@seeli.test', email_verified: true, name: 'Mika G' }) });
  assert.equal(g.status, 200);
  assert.equal(g.json.user.id, pw.json.user.id);
  assert.deepEqual(g.json.user.providers, ['google']);
  assert.equal(g.json.user.hasPassword, true);

  // Unverified email must not take over an existing account.
  const u = await post('/auth/google', { idToken: google({ sub: 'g-888', email: 'mika@seeli.test', email_verified: false, name: 'Other' }) });
  assert.equal(u.status, 201);
  assert.notEqual(u.json.user.id, pw.json.user.id);

  // A social-only account cannot be entered with an empty password.
  assert.equal((await post('/auth/login', { email: 'x1y2@privaterelay.appleid.com', password: '' })).status, 401);

  // Handle can be changed afterwards; taken handles are refused.
  assert.equal((await post('/me', { handle: 'mika' }, a1.json.token)).status, 409);
  const renamed = await post('/me', { handle: 'phat.seeli' }, a1.json.token);
  assert.equal(renamed.json.handle, 'phat.seeli');
});
