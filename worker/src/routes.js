import { Hono } from 'hono';
import { config, bindings, background } from './config.js';
import { one, all, run, batch } from './db.js';
import {
  hashPassword, verifyPassword, issueToken, requireUser,
  checkPhotoSignature, checkOncePhotoSignature, oncePhotoSignature, newInviteCode, newId,
} from './auth.js';
import { me, publicUser, myMoment, feedMoment, iso } from './serialize.js';
import { verifyIdToken, TokenError } from './oidc.js';
import { appleConfigured, exchangeCode, revokeToken } from './apple.js';
import { pushToUsers } from './push.js';

/** Profile JSON including which sign-in providers are linked. */
const meOf = async (u) =>
  me(u, (await all('SELECT provider FROM identities WHERE user_id = ? ORDER BY provider', u.id)).map((r) => r.provider));

/** Turns a name/email into an available handle like "phat", "phat2"… */
async function suggestHandle(...seeds) {
  for (const seed of seeds) {
    const base = String(seed || '').normalize('NFD').replace(/[̀-ͯ]/g, '').replace(/đ/gi, 'd')
      .toLowerCase().replace(/[^a-z0-9._-]+/g, '').replace(/^[._-]+|[._-]+$/g, '').slice(0, 24);
    if (base.length < 2) continue;
    for (let i = 0; i < 50; i++) {
      const h = i === 0 ? base : `${base}${i + 1}`;
      if (!(await one('SELECT 1 FROM users WHERE handle = ?', h))) return h;
    }
  }
  for (;;) {
    const h = `seeli${Math.floor(1000 + Math.random() * 900000)}`;
    if (!(await one('SELECT 1 FROM users WHERE handle = ?', h))) return h;
  }
}

const HANDLE_RE = /^[a-z0-9._-]{2,30}$/;
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const AUDIENCES = new Set(['onlyMe', 'circle']);
const ONCE_GRACE_MS = 2 * 60_000;  // retry window after the first open
const ONCE_URL_TTL_SEC = 120;
const DAY = 86_400_000;

const str = (v, max) => (typeof v === 'string' ? v.trim().slice(0, max) : '');
const bad = (c, error, code = 400) => c.json({ error }, code);

/** JSON body, or {} when there is none / it is not JSON. */
export const body = async (c) => {
  try {
    const b = await c.req.json();
    return b && typeof b === 'object' ? b : {};
  } catch {
    return {};
  }
};

export const clientIp = (c) => c.req.header('cf-connecting-ip') || '0.0.0.0';

/** Small per-isolate limiter for auth endpoints (per IP). */
const hits = new Map();
function limited(ip, max = config.authRateLimit, windowMs = 60_000) {
  const now = Date.now();
  const list = (hits.get(ip) || []).filter((t) => now - t < windowMs);
  list.push(now);
  hits.set(ip, list);
  if (hits.size > 5000) hits.clear();
  return list.length > max;
}

const baseUrl = (c) => config.publicUrl || new URL(c.req.url).origin;

const isBlockedEitherWay = async (a, b) =>
  !!(await one('SELECT 1 FROM blocks WHERE (user_id = ? AND blocked_id = ?) OR (user_id = ? AND blocked_id = ?)', a, b, b, a));

const areFriends = async (a, b) => !!(await one('SELECT 1 FROM friendships WHERE user_id = ? AND friend_id = ?', a, b));

function revealTime(createdAt, demo) {
  if (demo && config.allowDemo) return Date.now() + (45 + Math.random() * 45) * 1000;
  const days = config.revealMinDays + Math.random() * (config.revealMaxDays - config.revealMinDays);
  return createdAt + days * DAY;
}

async function uniqueInviteCode() {
  for (;;) {
    const code = newInviteCode();
    if (!(await one('SELECT 1 FROM users WHERE invite_code = ?', code))) return code;
  }
}

const insertUser = (u) => run(
  `INSERT INTO users (id, name, handle, email, password_hash, bio, invite_code, token_version, created_at)
   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
  u.id, u.name, u.handle, u.email, u.password_hash, u.bio, u.invite_code, u.token_version, u.created_at,
);

export const api = new Hono();

api.get('/health', (c) => c.json({ ok: true, time: iso(Date.now()), allowDemo: config.allowDemo }));

// ---------- Auth ----------

api.post('/auth/signup', async (c) => {
  if (limited(clientIp(c))) return bad(c, 'too_many_requests', 429);
  const b = await body(c);
  const name = str(b.name, 40);
  const handle = str(b.handle, 30).toLowerCase().replace(/^@/, '');
  const email = str(b.email, 120).toLowerCase();
  const password = typeof b.password === 'string' ? b.password : '';
  if (!name) return bad(c, 'name_required');
  if (!HANDLE_RE.test(handle)) return bad(c, 'invalid_handle');
  if (!EMAIL_RE.test(email)) return bad(c, 'invalid_email');
  if (password.length < 8 || password.length > 200) return bad(c, 'weak_password');
  if (await one('SELECT 1 FROM users WHERE handle = ?', handle)) return bad(c, 'handle_taken', 409);
  if (await one('SELECT 1 FROM users WHERE email = ?', email)) return bad(c, 'email_taken', 409);

  const user = {
    id: newId(), name, handle, email, password_hash: hashPassword(password),
    bio: '', invite_code: await uniqueInviteCode(), token_version: 0, created_at: Date.now(),
  };
  await insertUser(user);
  return c.json({ token: issueToken(user), user: await meOf(user) }, 201);
});

api.post('/auth/login', async (c) => {
  if (limited(clientIp(c))) return bad(c, 'too_many_requests', 429);
  const b = await body(c);
  const email = str(b.email, 120).toLowerCase();
  const password = typeof b.password === 'string' ? b.password : '';
  const user = await one('SELECT * FROM users WHERE email = ?', email);
  if (!user || !verifyPassword(password, user.password_hash)) return bad(c, 'invalid_credentials', 401);
  if (user.suspended_at) return bad(c, 'account_suspended', 403);
  return c.json({ token: issueToken(user), user: await meOf(user) });
});

/**
 * Sign in with Apple / Google. Body: { idToken, nonce?, name? }.
 * Existing link → sign in. Verified email matching an account → link it.
 * Otherwise a new account is created (handle suggested, editable later).
 */
api.post('/auth/:provider{apple|google}', async (c) => {
  const provider = c.req.param('provider');
  if (limited(clientIp(c))) return bad(c, 'too_many_requests', 429);
  const b = await body(c);
  let claims;
  try {
    claims = await verifyIdToken(provider, b.idToken, { nonce: b.nonce || undefined });
  } catch (e) {
    if (e instanceof TokenError) return bad(c, e.message === 'provider_not_configured' ? 'provider_disabled' : 'invalid_token', 401);
    console.error(e);
    return bad(c, 'provider_unreachable', 502);
  }

  const linked = await one('SELECT u.* FROM identities i JOIN users u ON u.id = i.user_id WHERE i.provider = ? AND i.subject = ?', provider, claims.sub);
  let user = linked;
  let isNew = false;
  if (!user && claims.email && claims.emailVerified) {
    user = await one('SELECT * FROM users WHERE email = ?', claims.email);
  }
  if (user?.suspended_at) return bad(c, 'account_suspended', 403);

  if (!user) {
    const name = str(b.name, 40) || str(claims.name, 40) || (claims.email ? claims.email.split('@')[0] : '') || 'SEELI';
    const email = claims.email && !(await one('SELECT 1 FROM users WHERE email = ?', claims.email))
      ? claims.email
      : `${provider}.${claims.sub.replace(/[^a-zA-Z0-9]/g, '').slice(-24)}@users.seeli.invalid`;
    user = {
      id: newId(), name, handle: await suggestHandle(name, claims.email?.split('@')[0]), email, password_hash: '',
      bio: '', invite_code: await uniqueInviteCode(), token_version: 0, created_at: Date.now(),
    };
    await insertUser(user);
    isNew = true;
  }
  if (!linked) {
    await run('INSERT OR IGNORE INTO identities (provider, subject, user_id, email, created_at) VALUES (?, ?, ?, ?, ?)',
      provider, claims.sub, user.id, claims.email, Date.now());
  }
  // Keep Apple's refresh token so access can be revoked when the account is deleted.
  if (provider === 'apple' && b.authorizationCode) {
    const refresh = await exchangeCode(String(b.authorizationCode)).catch((e) => { console.warn(e); return null; });
    if (refresh) await run('UPDATE identities SET refresh_token = ? WHERE provider = ? AND subject = ?', refresh, provider, claims.sub);
  }
  user = await one('SELECT * FROM users WHERE id = ?', user.id);
  return c.json({ token: issueToken(user), user: await meOf(user), isNew }, isNew ? 201 : 200);
});

// ---------- Photos (signed URL, no auth header) ----------

api.get('/photos/:id', async (c) => {
  const { exp, sig, once } = c.req.query();
  const id = c.req.param('id');
  const valid = once ? checkOncePhotoSignature(id, exp, sig) : checkPhotoSignature(id, exp, sig);
  if (!exp || Number(exp) < Date.now() / 1000 || !valid) return bad(c, 'forbidden', 403);
  const m = await one('SELECT * FROM moments WHERE id = ?', id);
  // A one-time view is allowed before the reveal date: friends see it now, once.
  if (!m || (!once && m.reveal_at > Date.now())) return bad(c, 'not_found', 404);
  const obj = await bindings.PHOTOS.get(m.photo_path);
  if (!obj) return bad(c, 'not_found', 404);
  return new Response(obj.body, {
    headers: {
      'content-type': 'image/jpeg',
      'content-length': String(obj.size),
      'cache-control': once ? 'no-store' : 'private, max-age=3600',
    },
  });
});

// Everything below needs a signed-in user.
const priv = new Hono();
priv.use('*', requireUser);

// ---------- Me ----------

priv.get('/me', async (c) => c.json(await meOf(c.get('user'))));

priv.patch('/me', async (c) => {
  const u = c.get('user');
  const b = await body(c);
  const name = b.name !== undefined ? str(b.name, 40) : u.name;
  const bio = b.bio !== undefined ? str(b.bio, 300) : u.bio;
  const handle = b.handle !== undefined ? str(b.handle, 30).toLowerCase().replace(/^@/, '') : u.handle;
  if (!name) return bad(c, 'name_required');
  if (!HANDLE_RE.test(handle)) return bad(c, 'invalid_handle');
  if (handle !== u.handle && await one('SELECT 1 FROM users WHERE handle = ?', handle)) return bad(c, 'handle_taken', 409);
  await run('UPDATE users SET name = ?, bio = ?, handle = ? WHERE id = ?', name, bio, handle, u.id);
  return c.json(await meOf(await one('SELECT * FROM users WHERE id = ?', u.id)));
});

/** Registers this device for push. env: "sandbox" (debug builds) or "production". */
priv.put('/me/device', async (c) => {
  const b = await body(c);
  const android = b.platform === 'android';
  let token = String(b.token || '');
  // APNs: hex device token. FCM: opaque registration token.
  if (android ? !/^[\w:.-]{20,4096}$/.test(token) : !/^[0-9a-f]{64,200}$/i.test(token)) return bad(c, 'invalid_token');
  if (!android) token = token.toLowerCase();
  const env = b.env === 'sandbox' ? 'sandbox' : 'production';
  const lang = b.lang === 'ja' ? 'ja' : 'vi';
  await run(`INSERT INTO device_tokens (token, user_id, env, lang, platform, updated_at) VALUES (?, ?, ?, ?, ?, ?)
       ON CONFLICT (token) DO UPDATE SET user_id = excluded.user_id, env = excluded.env,
         lang = excluded.lang, platform = excluded.platform, updated_at = excluded.updated_at`,
  token, c.get('user').id, env, lang, android ? 'android' : 'ios', Date.now());
  return c.json({ ok: true });
});

priv.delete('/me/device', async (c) => {
  const t = String((await body(c)).token || '');
  await run('DELETE FROM device_tokens WHERE token IN (?, ?) AND user_id = ?', t, t.toLowerCase(), c.get('user').id);
  return c.json({ ok: true });
});

/** Sign out everywhere. */
priv.post('/auth/logout', async (c) => {
  const id = c.get('user').id;
  await batch([
    ['UPDATE users SET token_version = token_version + 1 WHERE id = ?', id],
    ['DELETE FROM device_tokens WHERE user_id = ?', id],
  ]);
  return c.json({ ok: true });
});

/**
 * Delete account. Linked Apple IDs are revoked first (Guideline 5.1.1(v)).
 * If we hold no Apple token, the app re-authenticates and sends `appleAuthorizationCode`.
 */
priv.delete('/me', async (c) => {
  const u = c.get('user');
  const b = await body(c);
  const appleCode = b.appleAuthorizationCode ? String(b.appleAuthorizationCode) : null;
  const needsCode = appleConfigured() && !appleCode &&
    !!(await one("SELECT 1 FROM identities WHERE user_id = ? AND provider = 'apple' AND refresh_token IS NULL", u.id));
  if (needsCode) return bad(c, 'apple_reauth_required', 409);
  const result = await deleteUserCompletely(u.id, { appleCode });
  return c.json({ ok: true, ...result });
});

priv.post('/me/invite/rotate', async (c) => {
  const id = c.get('user').id;
  await run('UPDATE users SET invite_code = ? WHERE id = ?', await uniqueInviteCode(), id);
  return c.json(await meOf(await one('SELECT * FROM users WHERE id = ?', id)));
});

// ---------- Friends (QR invite codes) ----------

priv.get('/invites/:code', async (c) => {
  const meId = c.get('user').id;
  const u = await one('SELECT * FROM users WHERE invite_code = ?', String(c.req.param('code')).toUpperCase());
  if (!u || await isBlockedEitherWay(meId, u.id)) return bad(c, 'not_found', 404);
  return c.json({ user: publicUser(u), isSelf: u.id === meId, isFriend: await areFriends(meId, u.id) });
});

priv.post('/friends', async (c) => {
  const user = c.get('user');
  const code = str((await body(c)).code, 20).toUpperCase();
  const u = await one('SELECT * FROM users WHERE invite_code = ?', code);
  if (!u || await isBlockedEitherWay(user.id, u.id)) return bad(c, 'not_found', 404);
  if (u.id === user.id) return bad(c, 'self');
  const now = Date.now();
  const isNew = !(await areFriends(user.id, u.id));
  await batch([
    ['INSERT OR IGNORE INTO friendships (user_id, friend_id, created_at, added_by) VALUES (?, ?, ?, ?)', user.id, u.id, now, user.id],
    ['INSERT OR IGNORE INTO friendships (user_id, friend_id, created_at, added_by) VALUES (?, ?, ?, ?)', u.id, user.id, now, user.id],
  ]);
  if (isNew) notifyFriendAdded(user, u.id);
  return c.json(await friendJson(user.id, u.id), 201);
});

priv.get('/friends', async (c) => c.json((await all(
  `SELECT u.id, u.name, u.handle, u.bio, f.memo, f.created_at
     FROM friendships f JOIN users u ON u.id = f.friend_id
    WHERE f.user_id = ? ORDER BY f.created_at DESC`,
  c.get('user').id,
)).map(friendRow)));

priv.patch('/friends/:id', async (c) => {
  const meId = c.get('user').id;
  const r = await run('UPDATE friendships SET memo = ? WHERE user_id = ? AND friend_id = ?',
    str((await body(c)).memo, 500), meId, c.req.param('id'));
  if (!r.changes) return bad(c, 'not_found', 404);
  return c.json(await friendJson(meId, c.req.param('id')));
});

priv.delete('/friends/:id', async (c) => {
  await run(UNFRIEND, ...unfriendParams(c.get('user').id, c.req.param('id')));
  return c.json({ ok: true });
});

priv.post('/friends/:id/block', async (c) => {
  const meId = c.get('user').id, other = c.req.param('id');
  if (!(await one('SELECT 1 FROM users WHERE id = ?', other))) return bad(c, 'not_found', 404);
  const mine = await one('SELECT * FROM friendships WHERE user_id = ? AND friend_id = ?', meId, other);
  const theirs = await one('SELECT * FROM friendships WHERE user_id = ? AND friend_id = ?', other, meId);
  await batch([
    [UNFRIEND, ...unfriendParams(meId, other)],
    [`INSERT OR IGNORE INTO blocks (user_id, blocked_id, created_at, friend_since, memo, their_memo)
      VALUES (?, ?, ?, ?, ?, ?)`,
    meId, other, Date.now(), mine?.created_at ?? null, mine?.memo ?? null, theirs?.memo ?? null],
  ]);
  return c.json({ ok: true });
});

priv.get('/blocks', async (c) => c.json(
  (await all('SELECT u.* FROM blocks b JOIN users u ON u.id = b.blocked_id WHERE b.user_id = ?', c.get('user').id)).map(publicUser),
));

/** Unblocking restores the friendship the block ended (and with it their circle posts). */
priv.delete('/blocks/:id', async (c) => {
  const meId = c.get('user').id, other = c.req.param('id');
  const b = await one('SELECT * FROM blocks WHERE user_id = ? AND blocked_id = ?', meId, other);
  // Restore only if the other person does not block us too.
  const theyBlock = !!(await one('SELECT 1 FROM blocks WHERE user_id = ? AND blocked_id = ?', other, meId));
  const restore = !!b?.friend_since && !theyBlock;
  await batch([
    ['DELETE FROM blocks WHERE user_id = ? AND blocked_id = ?', meId, other],
    ...(restore ? [
      ['INSERT OR IGNORE INTO friendships (user_id, friend_id, memo, created_at) VALUES (?, ?, ?, ?)', meId, other, b.memo ?? '', b.friend_since],
      ['INSERT OR IGNORE INTO friendships (user_id, friend_id, memo, created_at) VALUES (?, ?, ?, ?)', other, meId, b.their_memo ?? '', b.friend_since],
    ] : []),
  ]);
  return c.json({ ok: true, friendRestored: restore });
});

priv.post('/reports', async (c) => {
  const b = await body(c);
  const target = str(b.userId, 64);
  if (!target) return bad(c, 'user_required');
  await run('INSERT INTO reports (id, reporter_id, target_id, reason, created_at) VALUES (?, ?, ?, ?, ?)',
    newId(), c.get('user').id, target, str(b.reason, 1000), Date.now());
  return c.json({ ok: true }, 201);
});

// ---------- Moments ----------

priv.get('/moments', async (c) => c.json((await all(
  `SELECT m.*, (SELECT COUNT(*) FROM comments c WHERE c.moment_id = m.id) AS comment_count
     FROM moments m WHERE m.user_id = ? ORDER BY m.created_at DESC`,
  c.get('user').id,
)).map((m) => myMoment(m, baseUrl(c)))));

priv.post('/moments', async (c) => {
  const user = c.get('user');
  if (Number(c.req.header('content-length') || 0) > config.maxPhotoBytes + 64 * 1024) return bad(c, 'photo_too_large', 413);
  let form;
  try {
    form = await c.req.formData();
  } catch {
    return bad(c, 'photo_required');
  }
  const file = form.get('photo');
  if (!file || typeof file === 'string') return bad(c, 'photo_required');
  if (file.size > config.maxPhotoBytes) return bad(c, 'photo_too_large', 413);
  const photo = new Uint8Array(await file.arrayBuffer());
  if (!(photo[0] === 0xff && photo[1] === 0xd8)) return bad(c, 'jpeg_required');
  const field = (k) => { const v = form.get(k); return typeof v === 'string' ? v : undefined; };

  const now = Date.now();
  const claimed = Date.parse(field('createdAt'));
  const createdAt = Number.isFinite(claimed) && Math.abs(claimed - now) < DAY ? claimed : now;
  const audience = AUDIENCES.has(field('audience')) ? field('audience') : 'onlyMe';
  const id = newId();
  const key = `${user.id}/${id}.jpg`;
  await bindings.PHOTOS.put(key, photo, { httpMetadata: { contentType: 'image/jpeg' } });

  await run(
    `INSERT INTO moments (id, user_id, note, place_name, audience, photo_path, created_at, reveal_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
    id, user.id, str(field('note'), 80), str(field('placeName'), 120) || null, audience, key,
    createdAt, Math.round(revealTime(createdAt, field('demo') === 'true')),
  );
  if (audience === 'circle') notifyCircle(user, id);
  return c.json(myMoment(await one('SELECT * FROM moments WHERE id = ?', id), baseUrl(c)), 201);
});

priv.post('/moments/:id/reunite', async (c) => {
  const m = await ownMoment(c);
  if (!m) return bad(c, 'not_found', 404);
  if (m.reveal_at > Date.now()) return bad(c, 'not_yet', 403);
  if (!m.reunited_at) await run('UPDATE moments SET reunited_at = ? WHERE id = ?', Date.now(), m.id);
  return c.json(myMoment(await one('SELECT * FROM moments WHERE id = ?', m.id), baseUrl(c)));
});

priv.patch('/moments/:id', async (c) => {
  const m = await ownMoment(c);
  if (!m) return bad(c, 'not_found', 404);
  const b = await body(c);
  if (b.reflection !== undefined) {
    await run('UPDATE moments SET reflection = ? WHERE id = ?', str(b.reflection, 500) || null, m.id);
  }
  if (AUDIENCES.has(b.audience)) {
    await run('UPDATE moments SET audience = ? WHERE id = ?', b.audience, m.id);
  }
  return c.json(myMoment(await one('SELECT * FROM moments WHERE id = ?', m.id), baseUrl(c)));
});

priv.delete('/moments/:id', async (c) => {
  const m = await ownMoment(c);
  if (!m) return bad(c, 'not_found', 404);
  await run('DELETE FROM moments WHERE id = ?', m.id);
  await bindings.PHOTOS.delete(m.photo_path).catch(() => {});
  return c.json({ ok: true });
});

// ---------- Let's connect ----------

priv.get('/feed', async (c) => {
  const id = c.get('user').id;
  return c.json((await all(
    `SELECT m.*, u.name AS author_name, u.handle AS author_handle,
            (SELECT text FROM comments c WHERE c.moment_id = m.id AND c.author_id = ?) AS my_comment,
            (SELECT reply FROM comments c WHERE c.moment_id = m.id AND c.author_id = ?) AS my_comment_reply,
            (SELECT replied_at FROM comments c WHERE c.moment_id = m.id AND c.author_id = ?) AS my_comment_replied_at,
            (SELECT opened_at FROM photo_views v WHERE v.moment_id = m.id AND v.viewer_id = ?) AS viewed_at
       FROM moments m
       JOIN friendships f ON f.friend_id = m.user_id AND f.user_id = ?
       JOIN users u ON u.id = m.user_id
      WHERE m.audience = 'circle'
        AND NOT EXISTS (SELECT 1 FROM blocks b WHERE (b.user_id = ? AND b.blocked_id = m.user_id)
                                                  OR (b.user_id = m.user_id AND b.blocked_id = ?))
      ORDER BY m.created_at DESC LIMIT 100`,
    id, id, id, id, id, id, id,
  )).map((m) => feedMoment(m)));
});

/**
 * Opens a friend's photo. The first call records the view; after a short grace
 * period (for a flaky connection) the photo can never be opened again.
 */
priv.post('/moments/:id/view', async (c) => {
  const meId = c.get('user').id;
  const m = await one('SELECT * FROM moments WHERE id = ?', c.req.param('id'));
  if (!m || !(await canComment(meId, m))) return bad(c, 'not_found', 404);
  const now = Date.now();
  const seen = await one('SELECT opened_at FROM photo_views WHERE moment_id = ? AND viewer_id = ?', m.id, meId);
  if (seen && now - seen.opened_at > ONCE_GRACE_MS) {
    return c.json({ error: 'already_viewed', viewedAt: iso(seen.opened_at) }, 410);
  }
  if (!seen) await run('INSERT OR IGNORE INTO photo_views (moment_id, viewer_id, opened_at) VALUES (?, ?, ?)', m.id, meId, now);
  const exp = Math.floor(now / 1000) + ONCE_URL_TTL_SEC;
  return c.json({
    photoUrl: `${baseUrl(c)}/v1/photos/${m.id}?exp=${exp}&once=1&sig=${oncePhotoSignature(m.id, exp)}`,
    viewedAt: iso(seen?.opened_at ?? now),
  });
});

/** Owner sees every comment; a friend sees only their own. */
priv.get('/moments/:id/comments', async (c) => {
  const meId = c.get('user').id;
  const m = await one('SELECT * FROM moments WHERE id = ?', c.req.param('id'));
  if (!m || !(m.user_id === meId || await canComment(meId, m))) return bad(c, 'not_found', 404);
  const owner = m.user_id === meId;
  const rows = await all(
    `SELECT c.*, u.name, u.handle FROM comments c JOIN users u ON u.id = c.author_id
      WHERE c.moment_id = ? ${owner ? '' : 'AND c.author_id = ?'}
      ORDER BY c.created_at`,
    ...(owner ? [m.id] : [m.id, meId]),
  );
  return c.json(rows.map((r) => ({
    id: r.id, text: r.text, createdAt: iso(r.created_at),
    author: { id: r.author_id, name: r.name, handle: r.handle },
    reply: r.reply ?? null, repliedAt: iso(r.replied_at),
  })));
});

/** The photo's owner answers a perspective. One reply per comment, editable; only that friend sees it. */
priv.put('/moments/:id/comments/:commentId/reply', async (c) => {
  const m = await ownMoment(c);
  if (!m) return bad(c, 'not_found', 404);
  const cm = await one('SELECT * FROM comments WHERE id = ? AND moment_id = ?', c.req.param('commentId'), m.id);
  if (!cm) return bad(c, 'not_found', 404);
  const text = str((await body(c)).text, 500);
  if (!text) return bad(c, 'text_required');
  const now = Date.now();
  await run('UPDATE comments SET reply = ?, replied_at = COALESCE(replied_at, ?) WHERE id = ?', text, now, cm.id);
  if (!cm.reply) notifyReply(c.get('user'), cm.author_id, m.id);
  return c.json({ ok: true, reply: text, repliedAt: iso(cm.replied_at ?? now) });
});

priv.delete('/moments/:id/comments/:commentId/reply', async (c) => {
  const m = await ownMoment(c);
  if (!m) return bad(c, 'not_found', 404);
  await run('UPDATE comments SET reply = NULL, replied_at = NULL WHERE id = ? AND moment_id = ?', c.req.param('commentId'), m.id);
  return c.json({ ok: true });
});

/** "Send your perspective" — one per person per moment, editable. */
priv.put('/moments/:id/comment', async (c) => {
  const user = c.get('user');
  const m = await one('SELECT * FROM moments WHERE id = ?', c.req.param('id'));
  if (!m || !(await canComment(user.id, m))) return bad(c, 'not_found', 404);
  const text = str((await body(c)).text, 500);
  if (!text) return bad(c, 'text_required');
  const existed = await one('SELECT 1 FROM comments WHERE moment_id = ? AND author_id = ?', m.id, user.id);
  // Editing keeps created_at, so the owner is told about a perspective only once.
  await run(
    `INSERT INTO comments (id, moment_id, author_id, text, created_at) VALUES (?, ?, ?, ?, ?)
     ON CONFLICT (moment_id, author_id) DO UPDATE SET text = excluded.text`,
    newId(), m.id, user.id, text, Date.now(),
  );
  if (!existed) notifyComment(user, m.user_id, m.id);
  return c.json({ ok: true, text });
});

priv.delete('/moments/:id/comment', async (c) => {
  await run('DELETE FROM comments WHERE moment_id = ? AND author_id = ?', c.req.param('id'), c.get('user').id);
  return c.json({ ok: true });
});

/**
 * New perspectives on my photos, replies to my perspectives and new friends since `since` (ms).
 * Android without Firebase polls this in the background.
 */
priv.get('/activity', async (c) => {
  const id = c.get('user').id;
  const since = Number(c.req.query('since')) || 0;
  const user = (r) => ({ id: r.id, name: r.name, handle: r.handle });
  const comments = (await all(
    `SELECT c.moment_id, c.created_at AS at, u.id, u.name, u.handle FROM comments c
       JOIN moments m ON m.id = c.moment_id JOIN users u ON u.id = c.author_id
      WHERE m.user_id = ? AND c.author_id <> ? AND c.created_at > ?
      ORDER BY c.created_at DESC LIMIT 20`,
    id, id, since,
  )).map((r) => ({ type: 'comment', momentId: r.moment_id, at: iso(r.at), user: user(r) }));
  const replies = (await all(
    `SELECT c.moment_id, c.replied_at AS at, u.id, u.name, u.handle FROM comments c
       JOIN moments m ON m.id = c.moment_id JOIN users u ON u.id = m.user_id
      WHERE c.author_id = ? AND c.replied_at > ?
      ORDER BY c.replied_at DESC LIMIT 20`,
    id, since,
  )).map((r) => ({ type: 'comment_reply', momentId: r.moment_id, at: iso(r.at), user: user(r) }));
  const friends = (await all(
    `SELECT f.created_at AS at, u.id, u.name, u.handle FROM friendships f JOIN users u ON u.id = f.friend_id
      WHERE f.user_id = ? AND f.added_by = f.friend_id AND f.created_at > ?
      ORDER BY f.created_at DESC LIMIT 20`,
    id, since,
  )).map((r) => ({ type: 'friend_added', momentId: null, at: iso(r.at), user: user(r) }));
  return c.json({ now: new Date().toISOString(), items: [...comments, ...replies, ...friends] });
});

api.route('/', priv);

// ---------- Push texts ----------

const FRIEND_POST_TEXT = {
  vi: (name) => ({ title: name, body: 'vừa chia sẻ một khoảnh khắc. Ảnh chỉ hiện một lần thôi.' }),
  ja: (name) => ({ title: name, body: 'さんが瞬間をシェアしました。写真は一度だけ見られます。' }),
};
const FRIEND_ADDED_TEXT = {
  vi: (name) => ({ title: 'SEELI', body: `${name} đã kết bạn với bạn.` }),
  ja: (name) => ({ title: 'SEELI', body: `${name}さんとつながりました。` }),
};
const COMMENT_TEXT = {
  vi: (name) => ({ title: name, body: 'đã gửi góc nhìn về khoảnh khắc của bạn.' }),
  ja: (name) => ({ title: name, body: 'さんがあなたの瞬間に視点を届けました。' }),
};
const REPLY_TEXT = {
  vi: (name) => ({ title: name, body: 'đã trả lời cảm nhận của bạn.' }),
  ja: (name) => ({ title: name, body: 'さんがあなたの視点に返信しました。' }),
};
const text = (table, name) => (lang) => (table[lang] || table.vi)(name);

/** Tells someone that a person scanned their code and they are now friends. */
const notifyFriendAdded = (adder, friendId) =>
  background(pushToUsers([friendId], text(FRIEND_ADDED_TEXT, adder.name), { type: 'friend_added', friendId: adder.id }));

/** Tells a photo's owner a friend sent a perspective on it. */
const notifyComment = (author, ownerId, momentId) =>
  background(pushToUsers([ownerId], text(COMMENT_TEXT, author.name), { type: 'comment', momentId }));

/** Tells a friend the photo's owner answered their perspective. */
const notifyReply = (owner, commenterId, momentId) =>
  background(pushToUsers([commenterId], text(REPLY_TEXT, owner.name), { type: 'comment_reply', momentId }));

/** Tells friends (not blocked either way) that someone shared to their circle. */
const notifyCircle = (author, momentId) => background((async () => {
  const friends = (await all(
    `SELECT f.friend_id AS id FROM friendships f
      WHERE f.user_id = ?
        AND EXISTS (SELECT 1 FROM friendships r WHERE r.user_id = f.friend_id AND r.friend_id = f.user_id)
        AND NOT EXISTS (SELECT 1 FROM blocks b WHERE (b.user_id = f.friend_id AND b.blocked_id = ?)
                                                  OR (b.user_id = ? AND b.blocked_id = f.friend_id))`,
    author.id, author.id, author.id,
  )).map((r) => r.id);
  await pushToUsers(friends, text(FRIEND_POST_TEXT, author.name), { type: 'friend_post', momentId });
})());

/** Removes the account, every row that belongs to it (FK cascade) and its photos. */
export async function deleteUserCompletely(userId, { appleCode = null } = {}) {
  let appleRevoked = null;
  for (const idn of await all("SELECT * FROM identities WHERE user_id = ? AND provider = 'apple'", userId)) {
    try {
      const token = idn.refresh_token || (appleCode ? await exchangeCode(appleCode) : null);
      appleRevoked = token ? await revokeToken(token) : false;
    } catch (e) {
      appleRevoked = false;
      console.warn(e);
    }
    if (!appleRevoked) console.warn('apple_revoke_failed', userId);
  }
  await run('DELETE FROM users WHERE id = ?', userId);
  await deletePhotos(`${userId}/`);
  return appleRevoked === null ? {} : { appleRevoked };
}

async function deletePhotos(prefix) {
  let cursor;
  do {
    const page = await bindings.PHOTOS.list({ prefix, cursor });
    if (page.objects.length) await bindings.PHOTOS.delete(page.objects.map((o) => o.key));
    cursor = page.truncated ? page.cursor : undefined;
  } while (cursor);
}

async function canComment(userId, m) {
  return m.audience === 'circle' && await areFriends(userId, m.user_id) && !(await isBlockedEitherWay(userId, m.user_id));
}

const ownMoment = (c) => one('SELECT * FROM moments WHERE id = ? AND user_id = ?', c.req.param('id'), c.get('user').id);

const UNFRIEND = 'DELETE FROM friendships WHERE (user_id = ? AND friend_id = ?) OR (user_id = ? AND friend_id = ?)';
const unfriendParams = (a, b) => [a, b, b, a];

function friendRow(r) {
  return { id: r.id, name: r.name, handle: r.handle, bio: r.bio, memo: r.memo, connectedAt: iso(r.created_at) };
}

async function friendJson(meId, friendId) {
  return friendRow(await one(
    `SELECT u.id, u.name, u.handle, u.bio, f.memo, f.created_at
       FROM friendships f JOIN users u ON u.id = f.friend_id WHERE f.user_id = ? AND f.friend_id = ?`,
    meId, friendId,
  ));
}
