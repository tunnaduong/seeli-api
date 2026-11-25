import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { generateKeyPairSync, verify } from 'node:crypto';

const dir = mkdtempSync(join(tmpdir(), 'seeli-push-'));
const ec = generateKeyPairSync('ec', { namedCurve: 'P-256' });
writeFileSync(join(dir, 'apns.p8'), ec.privateKey.export({ type: 'pkcs8', format: 'pem' }));
Object.assign(process.env, {
  DATA_DIR: dir, AUTH_RATE_LIMIT: '1000',
  APPLE_TEAM_ID: 'TEAM123', APNS_KEY_ID: 'PUSHKEY', APNS_KEY_PATH: join(dir, 'apns.p8'),
});

const { buildApp } = await import('../src/server.js');
const { _setSenderForTest } = await import('../src/apns.js');
const { all } = await import('../src/db.js');
const app = buildApp({ logger: false });

const sent = [];
_setSenderForTest(async (env, token, headers, payload) => {
  const [h, b, s] = headers.authorization.replace('bearer ', '').split('.');
  assert.equal(JSON.parse(Buffer.from(h, 'base64url')).kid, 'PUSHKEY');
  assert.equal(JSON.parse(Buffer.from(b, 'base64url')).iss, 'TEAM123');
  assert.ok(verify('sha256', Buffer.from(`${h}.${b}`), { key: ec.publicKey, dsaEncoding: 'ieee-p1363' }, Buffer.from(s, 'base64url')));
  sent.push({ env, token, payload });
  return token.startsWith('dead') ? { status: 410, body: '{"reason":"Unregistered"}' } : { status: 200 };
});

const call = async (method, url, token, body) => {
  const r = await app.inject({ method, url: `/v1${url}`, payload: body, headers: token ? { authorization: `Bearer ${token}` } : {} });
  return { status: r.statusCode, json: r.json() };
};
const JPEG = Buffer.from([0xff, 0xd8, 0xff, 0xd9]);
async function post(token, audience) {
  const bd = '----x';
  const payload = Buffer.concat([
    Buffer.from(`--${bd}\r\nContent-Disposition: form-data; name="audience"\r\n\r\n${audience}\r\n`),
    Buffer.from(`--${bd}\r\nContent-Disposition: form-data; name="photo"; filename="p.jpg"\r\nContent-Type: image/jpeg\r\n\r\n`),
    JPEG, Buffer.from(`\r\n--${bd}--\r\n`),
  ]);
  return app.inject({ method: 'POST', url: '/v1/moments', payload,
    headers: { authorization: `Bearer ${token}`, 'content-type': `multipart/form-data; boundary=${bd}` } });
}
const tick = () => new Promise((r) => setTimeout(r, 50));

test('friends get a push when someone shares to the circle', async () => {
  const signup = (n) => call('POST', '/auth/signup', undefined, { name: n, handle: n, email: `${n}@seeli.test`, password: 'password123' });
  const a = (await signup('anh')).json, b = (await signup('binh')).json, c = (await signup('chi')).json;
  await call('POST', '/friends', b.token, { code: a.user.inviteCode });

  const tokB = 'ab'.repeat(32), dead = 'dead' + 'f'.repeat(60);
  assert.equal((await call('PUT', '/me/device', b.token, { token: tokB, env: 'sandbox', lang: 'ja' })).status, 200);
  await call('PUT', '/me/device', b.token, { token: dead, env: 'production', lang: 'vi' });
  await call('PUT', '/me/device', c.token, { token: 'cd'.repeat(32) }); // not a friend
  assert.equal((await call('PUT', '/me/device', b.token, { token: 'nope' })).status, 400);

  await post(a.token, 'onlyMe');
  await tick();
  assert.equal(sent.length, 0); // private photos notify no one

  await post(a.token, 'circle');
  await tick();
  assert.deepEqual(sent.map((s) => s.token).sort(), [tokB, dead].sort());
  const ja = sent.find((s) => s.token === tokB);
  assert.equal(ja.env, 'sandbox');
  assert.equal(ja.payload.aps.alert.title, 'anh');
  assert.match(ja.payload.aps.alert.body, /一度だけ/);
  assert.equal(ja.payload.type, 'friend_post');
  assert.equal(all('SELECT * FROM device_tokens WHERE token = ?', dead).length, 0); // dead token cleaned up

  await call('POST', '/auth/logout', b.token);
  assert.equal(all('SELECT * FROM device_tokens WHERE token = ?', tokB).length, 0);
});
