import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { generateKeyPairSync, verify } from 'node:crypto';

const dir = mkdtempSync(join(tmpdir(), 'seeli-push-'));
const ec = generateKeyPairSync('ec', { namedCurve: 'P-256' });
writeFileSync(join(dir, 'apns.p8'), ec.privateKey.export({ type: 'pkcs8', format: 'pem' }));
const rsa = generateKeyPairSync('rsa', { modulusLength: 2048 });
writeFileSync(join(dir, 'firebase.json'), JSON.stringify({
  project_id: 'seeli-test', client_email: 'push@seeli-test.iam.gserviceaccount.com', private_key_id: 'k1',
  private_key: rsa.privateKey.export({ type: 'pkcs8', format: 'pem' }), token_uri: 'https://oauth2.example/token',
}));
Object.assign(process.env, {
  DATA_DIR: dir, AUTH_RATE_LIMIT: '1000',
  APPLE_TEAM_ID: 'TEAM123', APNS_KEY_ID: 'PUSHKEY', APNS_KEY_PATH: join(dir, 'apns.p8'),
  FCM_SERVICE_ACCOUNT_PATH: join(dir, 'firebase.json'),
});

const { buildApp } = await import('../src/server.js');
const { _setSenderForTest } = await import('../src/apns.js');
const { all } = await import('../src/db.js');
const { _setFcmForTest } = await import('../src/fcm.js');
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

const fcmSent = [];
_setFcmForTest({
  fetchToken: async (uri, assertion) => {
    const [h, b, sig] = assertion.split('.');
    assert.equal(uri, 'https://oauth2.example/token');
    assert.equal(JSON.parse(Buffer.from(b, 'base64url')).scope, 'https://www.googleapis.com/auth/firebase.messaging');
    assert.ok(verify('RSA-SHA256', Buffer.from(`${h}.${b}`), rsa.publicKey, Buffer.from(sig, 'base64url')));
    return { access_token: 'ya29.test', expires_in: 3600 };
  },
  send: async (project, bearer, message) => {
    assert.equal(project, 'seeli-test');
    assert.equal(bearer, 'ya29.test');
    fcmSent.push(message);
    return message.token.startsWith('gone') ? { status: 404, body: '{"error":{"status":"NOT_FOUND","details":[{"errorCode":"UNREGISTERED"}]}}' } : { status: 200, body: '{}' };
  },
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

test('Android devices get the same pushes through FCM', async () => {
  const signup = (n) => call('POST', '/auth/signup', undefined, { name: n, handle: n, email: `${n}@seeli.test`, password: 'password123' });
  const d = (await signup('dung')).json, e = (await signup('em')).json;
  const fcmTok = 'fcm:APA91b' + 'x'.repeat(140), gone = 'gone:' + 'y'.repeat(140);
  assert.equal((await call('PUT', '/me/device', e.token, { token: fcmTok, platform: 'android', lang: 'vi' })).status, 200);
  await call('PUT', '/me/device', e.token, { token: gone, platform: 'android' });
  assert.equal((await call('PUT', '/me/device', e.token, { token: 'bad token!', platform: 'android' })).status, 400);

  // d scans e's code → e is told, through FCM, as a data message
  await call('POST', '/friends', d.token, { code: e.user.inviteCode });
  await tick();
  const added = fcmSent.find((m) => m.token === fcmTok);
  assert.equal(added.data.type, 'friend_added');
  assert.equal(added.data.friendId, d.user.id);
  assert.match(added.data.body, /dung đã kết bạn/);
  assert.equal(added.android.priority, 'high');
  assert.equal(all('SELECT * FROM device_tokens WHERE token = ?', gone).length, 0); // unregistered token removed
  assert.equal(all('SELECT platform FROM device_tokens WHERE token = ?', fcmTok)[0].platform, 'android');
});
