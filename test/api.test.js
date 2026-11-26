import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

process.env.DATA_DIR = mkdtempSync(join(tmpdir(), 'seeli-test-'));
process.env.ADMIN_PASSWORD = 'admin-test-password';
const { buildApp } = await import('../src/server.js');
const { run } = await import('../src/db.js');

const app = buildApp({ logger: false });
const JPEG = Buffer.from([0xff, 0xd8, 0xff, 0xe0, 0, 0x10, 0x4a, 0x46, 0x49, 0x46, 0, 1, 0xff, 0xd9]);

async function call(method, url, { token, body } = {}) {
  const res = await app.inject({
    method, url: `/v1${url}`, payload: body,
    headers: token ? { authorization: `Bearer ${token}` } : {},
  });
  return { status: res.statusCode, json: res.headers['content-type']?.includes('json') ? res.json() : null, res };
}

async function upload(token, fields) {
  const boundary = '----seeli';
  const parts = Object.entries(fields).map(([k, v]) =>
    `--${boundary}\r\nContent-Disposition: form-data; name="${k}"\r\n\r\n${v}\r\n`);
  const payload = Buffer.concat([
    Buffer.from(parts.join('')),
    Buffer.from(`--${boundary}\r\nContent-Disposition: form-data; name="photo"; filename="p.jpg"\r\nContent-Type: image/jpeg\r\n\r\n`),
    JPEG,
    Buffer.from(`\r\n--${boundary}--\r\n`),
  ]);
  const res = await app.inject({
    method: 'POST', url: '/v1/moments', payload,
    headers: { authorization: `Bearer ${token}`, 'content-type': `multipart/form-data; boundary=${boundary}` },
  });
  return { status: res.statusCode, json: res.json() };
}

const signup = (name, handle) =>
  call('POST', '/auth/signup', { body: { name, handle, email: `${handle}@seeli.test`, password: 'password123' } });

test('full SEELI flow', async () => {
  const a = await signup('Phat', 'phat');
  const b = await signup('Mika', 'mika');
  assert.equal(a.status, 201);
  assert.equal((await signup('X', 'phat')).status, 409);

  const login = await call('POST', '/auth/login', { body: { email: 'phat@seeli.test', password: 'password123' } });
  assert.equal(login.status, 200);
  assert.equal((await call('POST', '/auth/login', { body: { email: 'phat@seeli.test', password: 'nope' } })).status, 401);
  const ta = login.json.token, tb = b.json.token;

  // Friends via invite code only
  const preview = await call('GET', `/invites/${b.json.user.inviteCode}`, { token: ta });
  assert.equal(preview.json.user.handle, 'mika');
  assert.equal((await call('POST', '/friends', { token: ta, body: { code: b.json.user.inviteCode } })).status, 201);
  assert.equal((await call('GET', '/friends', { token: tb })).json.length, 1);
  await call('PATCH', `/friends/${b.json.user.id}`, { token: ta, body: { memo: 'met at uni' } });
  assert.equal((await call('GET', '/friends', { token: ta })).json[0].memo, 'met at uni');
  assert.equal((await call('GET', '/friends', { token: tb })).json[0].memo, ''); // memo is private

  // Mika posts to her circle; photo hidden until reveal
  const post = await upload(tb, { note: '雨上がりの道', placeName: '東京都新宿区', audience: 'circle' });
  assert.equal(post.status, 201);
  assert.equal(post.json.photoUrl, null);
  const feed = await call('GET', '/feed', { token: ta });
  assert.equal(feed.json.length, 1);
  assert.equal(feed.json[0].photoUrl, null);
  assert.equal(feed.json[0].placeName, undefined); // place never shared
  assert.equal((await call('POST', `/moments/${post.json.id}/reunite`, { token: tb })).status, 403);

  // A friend can open the photo right away, but only once
  const view = await call('POST', `/moments/${post.json.id}/view`, { token: ta });
  assert.equal(view.status, 200);
  const onceUrl = new URL(view.json.photoUrl);
  const oncePhoto = await app.inject({ method: 'GET', url: onceUrl.pathname + onceUrl.search });
  assert.equal(oncePhoto.statusCode, 200);
  assert.equal(oncePhoto.headers['cache-control'], 'no-store');
  // The one-time signature cannot be reused as a normal URL before the reveal date
  const stripped = await app.inject({ method: 'GET', url: onceUrl.pathname + onceUrl.search.replace('&once=1', '') });
  assert.equal(stripped.statusCode, 403);
  assert.ok((await call('GET', '/feed', { token: ta })).json[0].viewedAt);
  assert.equal((await call('POST', `/moments/${post.json.id}/view`, { token: ta })).status, 200); // grace retry
  run('UPDATE photo_views SET opened_at = ? WHERE moment_id = ?', Date.now() - 10 * 60_000, post.json.id);
  const again = await call('POST', `/moments/${post.json.id}/view`, { token: ta });
  assert.equal(again.status, 410);
  assert.equal(again.json.error, 'already_viewed');
  assert.equal((await call('POST', `/moments/${post.json.id}/view`, { token: tb })).status, 404); // not for the owner

  // Perspective: owner sees it, other friends wouldn't
  assert.equal((await call('PUT', `/moments/${post.json.id}/comment`, { token: ta, body: { text: '綺麗' } })).status, 200);
  assert.equal((await call('GET', `/moments/${post.json.id}/comments`, { token: tb })).json.length, 1);
  assert.equal((await call('GET', '/feed', { token: ta })).json[0].myComment, '綺麗');

  // Owner replies to the perspective; only the owner may reply, and the friend sees it in the feed
  const [cm] = (await call('GET', `/moments/${post.json.id}/comments`, { token: tb })).json;
  assert.equal(cm.reply, null);
  assert.equal((await call('PUT', `/moments/${post.json.id}/comments/${cm.id}/reply`, { token: ta, body: { text: 'no' } })).status, 404);
  assert.equal((await call('PUT', `/moments/${post.json.id}/comments/${cm.id}/reply`, { token: tb, body: { text: 'ありがとう' } })).status, 200);
  assert.equal((await call('GET', `/moments/${post.json.id}/comments`, { token: tb })).json[0].reply, 'ありがとう');
  const act = (await call('GET', '/activity?since=0', { token: tb })).json;
  assert.deepEqual(act.items.map((i) => i.type), ['comment']);
  assert.equal((await call('GET', '/activity?since=0', { token: ta })).json.items[0].type, 'comment_reply');
  assert.equal((await call('GET', `/activity?since=${Date.now() + 1000}`, { token: tb })).json.items.length, 0);
  const fed = (await call('GET', '/feed', { token: ta })).json[0];
  assert.equal(fed.myCommentReply, 'ありがとう');
  assert.ok(fed.myCommentRepliedAt);

  // Time passes → photo comes back
  run('UPDATE moments SET reveal_at = ? WHERE id = ?', Date.now() - 1000, post.json.id);
  const mine = await call('GET', '/moments', { token: tb });
  assert.ok(mine.json[0].photoUrl);
  const photo = await app.inject({ method: 'GET', url: new URL(mine.json[0].photoUrl).pathname + new URL(mine.json[0].photoUrl).search });
  assert.equal(photo.statusCode, 200);
  const forged = await app.inject({ method: 'GET', url: `/v1/photos/${post.json.id}?exp=9999999999&sig=x` });
  assert.equal(forged.statusCode, 403);
  assert.equal((await call('POST', `/moments/${post.json.id}/reunite`, { token: tb })).json.reunitedAt != null, true);

  // Block hides the feed and the friendship
  await call('POST', `/friends/${b.json.user.id}/block`, { token: ta });
  assert.equal((await call('GET', '/feed', { token: ta })).json.length, 0);
  assert.equal((await call('POST', '/friends', { token: ta, body: { code: b.json.user.inviteCode } })).status, 404);

  // Unblock brings the friendship and the old posts back
  const un = await call('DELETE', `/blocks/${b.json.user.id}`, { token: ta });
  assert.equal(un.json.friendRestored, true);
  assert.equal((await call('GET', '/feed', { token: ta })).json.length, 1);
  assert.equal((await call('GET', '/friends', { token: tb })).json.length, 1);

  // Logout revokes tokens; delete removes everything
  await call('POST', '/auth/logout', { token: ta });
  assert.equal((await call('GET', '/me', { token: ta })).status, 401);
  assert.equal((await call('DELETE', '/me', { token: tb })).status, 200);
  assert.equal((await call('POST', '/auth/login', { body: { email: 'mika@seeli.test', password: 'password123' } })).status, 401);
});

async function admin(method, url, { cookie, body, csrf = true } = {}) {
  const res = await app.inject({
    method, url: `/v1/admin${url}`, payload: body,
    headers: { ...(cookie ? { cookie } : {}), ...(csrf ? { 'x-seeli-admin': '1' } : {}) },
  });
  return { status: res.statusCode, json: res.json(), res };
}

test('admin area', async () => {
  const page = await app.inject({ method: 'GET', url: '/admin' });
  assert.equal(page.statusCode, 200);
  assert.match(page.headers['content-type'], /text\/html/);

  assert.equal((await admin('GET', '/stats')).status, 401);
  assert.equal((await admin('POST', '/login', { body: { password: 'wrong' } })).status, 401);
  assert.equal((await admin('POST', '/login', { body: { password: 'admin-test-password' }, csrf: false })).status, 403);
  const login = await admin('POST', '/login', { body: { password: 'admin-test-password' } });
  assert.equal(login.status, 200);
  const cookie = login.res.headers['set-cookie'].split(';')[0];
  assert.match(login.res.headers['set-cookie'], /HttpOnly; Secure; SameSite=Strict/);

  // A user token must not open the admin area.
  const u = await signup('Kai', 'kai');
  const v = await signup('Lan', 'lan');
  assert.equal((await admin('GET', '/stats', { cookie: `seeli_admin=${u.json.token}` })).status, 401);

  // Reset one-time photo views (needs the admin cookie)
  assert.equal((await admin('POST', '/photo-views/reset')).status, 401);
  const reset = await admin('POST', '/photo-views/reset', { cookie });
  assert.equal(reset.status, 200);
  assert.equal(typeof reset.json.cleared, 'number');
  assert.equal((await admin('GET', '/stats', { cookie })).json.photoViews, 0);

  const stats = await admin('GET', '/stats', { cookie });
  assert.equal(stats.status, 200);
  assert.ok(stats.json.users >= 2);

  const list = await admin('GET', '/users?q=kai', { cookie });
  assert.equal(list.json.users.length, 1);
  assert.equal(list.json.users[0].handle, 'kai');
  assert.equal(list.json.users[0].note, undefined);

  // Report → shows in admin → suspend blocks login and existing tokens
  await call('POST', '/reports', { token: v.json.token, body: { userId: u.json.user.id, reason: 'spam' } });
  const reports = await admin('GET', '/reports?status=open', { cookie });
  assert.equal(reports.json.length, 1);
  assert.equal(reports.json[0].target.handle, 'kai');
  assert.equal((await admin('POST', `/users/${u.json.user.id}/suspend`, { cookie, body: { suspended: true } })).status, 200);
  assert.equal((await call('GET', '/me', { token: u.json.token })).status, 401);
  const blocked = await call('POST', '/auth/login', { body: { email: 'kai@seeli.test', password: 'password123' } });
  assert.equal(blocked.status, 403);
  assert.equal(blocked.json.error, 'account_suspended');
  await admin('POST', `/users/${u.json.user.id}/suspend`, { cookie, body: { suspended: false } });
  assert.equal((await call('POST', '/auth/login', { body: { email: 'kai@seeli.test', password: 'password123' } })).status, 200);

  assert.equal((await admin('POST', `/reports/${reports.json[0].id}`, { cookie, body: { status: 'resolved' } })).status, 200);
  assert.equal((await admin('GET', '/reports?status=open', { cookie })).json.length, 0);

  // Delete needs the handle typed back
  assert.equal((await admin('DELETE', `/users/${u.json.user.id}`, { cookie, body: { confirmHandle: 'nope' } })).status, 400);
  assert.equal((await admin('DELETE', `/users/${u.json.user.id}`, { cookie, body: { confirmHandle: 'kai' } })).status, 200);
  assert.equal((await admin('GET', '/users?q=kai', { cookie })).json.total, 0);
  assert.ok((await admin('GET', '/stats', { cookie })).json.recentActions.some((a) => a.action === 'delete'));
});
