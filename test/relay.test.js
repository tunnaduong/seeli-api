import { test } from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync } from 'node:crypto';
import { writeFileSync, mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const dir = mkdtempSync(join(tmpdir(), 'seeli-relay-'));
const { privateKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
writeFileSync(join(dir, 'k.p8'), privateKey.export({ type: 'pkcs8', format: 'pem' }));
Object.assign(process.env, {
  DATA_DIR: dir, RELAY_ONLY: 'true', PUSH_RELAY_SECRET: 'relay-test-secret',
  APNS_KEY_ID: 'KEY123', APNS_KEY_PATH: join(dir, 'k.p8'), APPLE_TEAM_ID: 'TEAM123',
});

const { buildApp } = await import('../src/server.js');
const { _setSenderForTest } = await import('../src/apns.js');

test('relay forwards to APNs only with the shared secret', async () => {
  const calls = [];
  _setSenderForTest(async (env, token, headers, payload) => { calls.push({ env, token, headers, payload }); return { status: 200, body: '' }; });
  const app = buildApp({ logger: false });
  const token = 'ab'.repeat(32);
  const body = { env: 'sandbox', token, payload: { aps: { alert: { title: 't', body: 'b' } } } };

  let r = await app.inject({ method: 'POST', url: '/apns', payload: body });
  assert.equal(r.statusCode, 401);
  r = await app.inject({ method: 'POST', url: '/apns', headers: { 'x-relay-secret': 'wrong' }, payload: body });
  assert.equal(r.statusCode, 401);
  r = await app.inject({ method: 'POST', url: '/apns', headers: { 'x-relay-secret': 'relay-test-secret' }, payload: body });
  assert.equal(r.statusCode, 200);
  assert.deepEqual(r.json(), { status: 200, body: '' });
  assert.equal(calls.length, 1);
  assert.equal(calls[0].env, 'sandbox');
  assert.match(calls[0].headers.authorization, /^bearer /);

  // The old API is not served in relay mode.
  r = await app.inject({ method: 'GET', url: '/v1/me' });
  assert.equal(r.statusCode, 404);
  await app.close();
});
