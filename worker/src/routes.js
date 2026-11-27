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
import { notifyNewUser, clientPlatform } from './notify.js';

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
const AUDIENCES = new Set(['onlyMe', 'circle', 'closeFriends', 'selected']);
const VISIBILITIES = new Set(['owner', 'circle']);
const MAX_RECIPIENTS = 200;
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

/** Parses recipient ids (JSON array or comma list) and keeps only the owner's friends. */
async function validRecipients(ownerId, raw) {
  let ids = raw;
  if (typeof raw === 'string') {
    try { ids = JSON.parse(raw); } catch { ids = raw.split(','); }
  }
  if (!Array.isArray(ids)) return [];
  ids = [...new Set(ids.map((v) => String(v).trim()).filter(Boolean))].slice(0, MAX_RECIPIENTS);
  if (!ids.length) return [];
  const rows = await all(
    'SELECT friend_id FROM friendships WHERE user_id = ? AND friend_id IN (SELECT value FROM json_each(?))',
    ownerId, JSON.stringify(ids),
  );
  return rows.map((r) => r.friend_id);
}

const setRecipients = (momentId, ids) => batch([
  ['DELETE FROM moment_recipients WHERE moment_id = ?', momentId],
  ...ids.map((uid) => ['INSERT OR IGNORE INTO moment_recipients (moment_id, user_id) VALUES (?, ?)', momentId, uid]),
]);

const recipientsOf = async (momentId) =>
  (await all('SELECT user_id FROM moment_recipients WHERE moment_id = ?', momentId)).map((r) => r.user_id);

/** Whether `userId` may see (and comment on) moment `m`. */
async function canSee(userId, m) {
  if (!m) return false;
  if (m.user_id === userId) return true;
  if (m.audience === 'onlyMe') return false;
  // The owner's row carries the close-friend flag.
  const f = await one('SELECT close FROM friendships WHERE user_id = ? AND friend_id = ?', m.user_id, userId);
  if (!f || await isBlockedEitherWay(userId, m.user_id)) return false;
  if (m.audience === 'circle') return true;
  if (m.audience === 'closeFriends') return !!f.close;
  if (m.audience === 'selected') {
    return !!(await one('SELECT 1 FROM moment_recipients WHERE moment_id = ? AND user_id = ?', m.id, userId));
  }
  return false;
}

/** People who can see a moment (for push), excluding the owner. */
async function audienceOf(m) {
  if (m.audience === 'onlyMe') return [];
  const extra = m.audience === 'closeFriends' ? 'AND f.close = 1'
    : m.audience === 'selected' ? 'AND EXISTS (SELECT 1 FROM moment_recipients r WHERE r.moment_id = ? AND r.user_id = f.friend_id)'
      : '';
  return (await all(
    `SELECT f.friend_id AS id FROM friendships f
      WHERE f.user_id = ? ${extra}
        AND EXISTS (SELECT 1 FROM friendships r WHERE r.user_id = f.friend_id AND r.friend_id = f.user_id)
        AND NOT EXISTS (SELECT 1 FROM blocks b WHERE (b.user_id = f.friend_id AND b.blocked_id = f.user_id)
                                                  OR (b.user_id = f.user_id AND b.blocked_id = f.friend_id))`,
    ...(m.audience === 'selected' ? [m.user_id, m.id] : [m.user_id]),
  )).map((r) => r.id);
}

// ---------- Comment visibility ----------

/**
 * Who sees a comment on moment m (owner O), for viewer V:
 *  - O sees everything; an author always sees their own comments.
 *  - O's comments: replies to a private comment are seen by that comment's author;
 *    otherwise O's comments are public to the post's audience.
 *  - Anyone else's comment: public only when visibility = 'circle' and O approved it.
 */
function commentVisible(cm, viewerId, ownerId, byId) {
  if (viewerId === ownerId || cm.author_id === viewerId) return true;
  const parent = cm.parent_id ? byId.get(cm.parent_id) : null;
  if (cm.parent_id && !parent) return false; // parent deleted
  if (parent && !commentVisible(parent, viewerId, ownerId, byId)) return false;
  // The owner's top-level comments are public; their replies follow the comment they answer.
  if (cm.author_id === ownerId) return !parent || isPublic(parent, ownerId) || parent.author_id === viewerId;
  return isPublic(cm, ownerId);
}

const isPublic = (cm, ownerId) =>
  cm.author_id === ownerId || (cm.visibility === 'circle' && cm.status === 'approved');

async function commentsOf(momentIds) {
  if (!momentIds.length) return new Map();
  const rows = await all(
    `SELECT c.*, u.name, u.handle FROM comments c JOIN users u ON u.id = c.author_id
      WHERE c.moment_id IN (SELECT value FROM json_each(?)) ORDER BY c.created_at`,
    JSON.stringify(momentIds),
  );
  const byMoment = new Map();
  for (const r of rows) {
    if (!byMoment.has(r.moment_id)) byMoment.set(r.moment_id, []);
    byMoment.get(r.moment_id).push(r);
  }
  return byMoment;
}

/** Comments of moment m that viewer may see, oldest first. */
function visibleComments(rows, viewerId, ownerId) {
  const byId = new Map(rows.map((r) => [r.id, r]));
  return rows.filter((r) => commentVisible(r, viewerId, ownerId, byId));
}

const commentJson = (r, viewerId) => ({
  id: r.id,
  parentId: r.parent_id ?? null,
  text: r.text,
  createdAt: iso(r.created_at),
  editedAt: iso(r.edited_at),
  author: { id: r.author_id, name: r.name, handle: r.handle },
  visibility: r.visibility,
  status: r.status,
  mine: r.author_id === viewerId,
});

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
  notifyNewUser(user, 'email', clientPlatform(c.req));
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
    notifyNewUser(user, provider, clientPlatform(c.req));
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
  return c.json({
    user: publicUser(u), isSelf: u.id === meId, isFriend: await areFriends(meId, u.id),
    requested: !!(await one('SELECT 1 FROM friend_requests WHERE from_id = ? AND to_id = ?', meId, u.id)),
    requestedMe: !!(await one('SELECT 1 FROM friend_requests WHERE from_id = ? AND to_id = ?', u.id, meId)),
  });
});

/** Makes two people friends and clears any pending requests between them. */
const befriend = (a, b, addedBy, now = Date.now()) => batch([
  ['INSERT OR IGNORE INTO friendships (user_id, friend_id, created_at, added_by) VALUES (?, ?, ?, ?)', a, b, now, addedBy],
  ['INSERT OR IGNORE INTO friendships (user_id, friend_id, created_at, added_by) VALUES (?, ?, ?, ?)', b, a, now, addedBy],
  ['DELETE FROM friend_requests WHERE (from_id = ? AND to_id = ?) OR (from_id = ? AND to_id = ?)', a, b, b, a],
]);

/**
 * Scan a friend's code. Body: { code, request? }.
 * New apps send request: true → a friend request the other person must accept
 * (or instant friendship if they had already asked us). Older apps connect at once.
 */
priv.post('/friends', async (c) => {
  const user = c.get('user');
  const b = await body(c);
  const code = str(b.code, 20).toUpperCase();
  const u = await one('SELECT * FROM users WHERE invite_code = ?', code);
  if (!u || await isBlockedEitherWay(user.id, u.id)) return bad(c, 'not_found', 404);
  if (u.id === user.id) return bad(c, 'self');
  const already = await areFriends(user.id, u.id);

  if (b.request === true) {
    if (already) return c.json({ status: 'friends', friend: await friendJson(user.id, u.id) });
    const theyAsked = await one('SELECT 1 FROM friend_requests WHERE from_id = ? AND to_id = ?', u.id, user.id);
    if (theyAsked) {
      await befriend(user.id, u.id, user.id);
      notifyFriendAdded(user, u.id);
      return c.json({ status: 'friends', friend: await friendJson(user.id, u.id) }, 201);
    }
    const res = await run('INSERT OR IGNORE INTO friend_requests (from_id, to_id, created_at) VALUES (?, ?, ?)', user.id, u.id, Date.now());
    if (res.changes) notifyFriendRequest(user, u.id);
    return c.json({ status: 'requested', user: publicUser(u) }, 201);
  }

  await befriend(user.id, u.id, user.id);
  if (!already) notifyFriendAdded(user, u.id);
  return c.json(await friendJson(user.id, u.id), 201);
});

priv.get('/friend-requests', async (c) => {
  const id = c.get('user').id;
  const row = (r) => ({ user: { id: r.id, name: r.name, handle: r.handle }, createdAt: iso(r.created_at) });
  const incoming = await all(
    `SELECT u.id, u.name, u.handle, r.created_at FROM friend_requests r JOIN users u ON u.id = r.from_id
      WHERE r.to_id = ? ORDER BY r.created_at DESC`, id);
  const outgoing = await all(
    `SELECT u.id, u.name, u.handle, r.created_at FROM friend_requests r JOIN users u ON u.id = r.to_id
      WHERE r.from_id = ? ORDER BY r.created_at DESC`, id);
  return c.json({ incoming: incoming.map(row), outgoing: outgoing.map(row) });
});

priv.post('/friend-requests/:id/accept', async (c) => {
  const user = c.get('user');
  const from = c.req.param('id');
  if (!(await one('SELECT 1 FROM friend_requests WHERE from_id = ? AND to_id = ?', from, user.id))) return bad(c, 'not_found', 404);
  if (await isBlockedEitherWay(user.id, from)) return bad(c, 'not_found', 404);
  await befriend(user.id, from, user.id);
  notifyFriendAdded(user, from);
  return c.json(await friendJson(user.id, from), 201);
});

/** Decline an incoming request or cancel an outgoing one. */
priv.delete('/friend-requests/:id', async (c) => {
  const me = c.get('user').id, other = c.req.param('id');
  await run('DELETE FROM friend_requests WHERE (from_id = ? AND to_id = ?) OR (from_id = ? AND to_id = ?)', other, me, me, other);
  return c.json({ ok: true });
});

priv.get('/friends', async (c) => c.json((await all(
  `SELECT u.id, u.name, u.handle, u.bio, f.memo, f.close, f.created_at
     FROM friendships f JOIN users u ON u.id = f.friend_id
    WHERE f.user_id = ? ORDER BY f.created_at DESC`,
  c.get('user').id,
)).map(friendRow)));

/** Body: { memo?, close? } — close marks a close friend (for the "Close friends" audience). */
priv.patch('/friends/:id', async (c) => {
  const meId = c.get('user').id;
  const b = await body(c);
  const f = await one('SELECT * FROM friendships WHERE user_id = ? AND friend_id = ?', meId, c.req.param('id'));
  if (!f) return bad(c, 'not_found', 404);
  await run('UPDATE friendships SET memo = ?, close = ? WHERE user_id = ? AND friend_id = ?',
    b.memo !== undefined ? str(b.memo, 500) : f.memo,
    b.close !== undefined ? (b.close ? 1 : 0) : f.close,
    meId, f.friend_id);
  return c.json(await friendJson(meId, f.friend_id));
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
    ['DELETE FROM friend_requests WHERE (from_id = ? AND to_id = ?) OR (from_id = ? AND to_id = ?)', meId, other, other, meId],
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

/** My moments, with comment counts and who each one is shared with. */
priv.get('/moments', async (c) => {
  const id = c.get('user').id;
  const rows = await all(
    `SELECT m.*,
            (SELECT COUNT(*) FROM comments c WHERE c.moment_id = m.id AND c.author_id <> m.user_id) AS comment_count,
            (SELECT COUNT(*) FROM comments c WHERE c.moment_id = m.id AND c.visibility = 'circle'
                AND c.status = 'pending' AND c.author_id <> m.user_id) AS pending_count,
            (SELECT MAX(c.created_at) FROM comments c WHERE c.moment_id = m.id AND c.author_id <> m.user_id) AS last_comment_at,
            (SELECT json_group_array(r.user_id) FROM moment_recipients r WHERE r.moment_id = m.id) AS recipient_ids
       FROM moments m WHERE m.user_id = ? ORDER BY m.created_at DESC`,
    id,
  );
  return c.json(rows.map((m) => myMoment(m, baseUrl(c))));
});

const momentWithExtras = async (id) => one(
  `SELECT m.*,
          (SELECT COUNT(*) FROM comments c WHERE c.moment_id = m.id AND c.author_id <> m.user_id) AS comment_count,
          (SELECT COUNT(*) FROM comments c WHERE c.moment_id = m.id AND c.visibility = 'circle'
              AND c.status = 'pending' AND c.author_id <> m.user_id) AS pending_count,
          (SELECT MAX(c.created_at) FROM comments c WHERE c.moment_id = m.id AND c.author_id <> m.user_id) AS last_comment_at,
          (SELECT json_group_array(r.user_id) FROM moment_recipients r WHERE r.moment_id = m.id) AS recipient_ids
     FROM moments m WHERE m.id = ?`, id);

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
  let audience = AUDIENCES.has(field('audience')) ? field('audience') : 'onlyMe';
  const recipients = audience === 'selected' ? await validRecipients(user.id, field('recipients')) : [];
  if (audience === 'selected' && !recipients.length) return bad(c, 'recipients_required');
  const id = newId();
  const key = `${user.id}/${id}.jpg`;
  await bindings.PHOTOS.put(key, photo, { httpMetadata: { contentType: 'image/jpeg' } });

  await run(
    `INSERT INTO moments (id, user_id, note, place_name, audience, photo_path, created_at, reveal_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
    id, user.id, str(field('note'), 80), str(field('placeName'), 120) || null, audience, key,
    createdAt, Math.round(revealTime(createdAt, field('demo') === 'true')),
  );
  if (recipients.length) await setRecipients(id, recipients);
  const m = await momentWithExtras(id);
  notifyNewPost(user, m);
  return c.json(myMoment(m, baseUrl(c)), 201);
});

priv.post('/moments/:id/reunite', async (c) => {
  const m = await ownMoment(c);
  if (!m) return bad(c, 'not_found', 404);
  if (m.reveal_at > Date.now()) return bad(c, 'not_yet', 403);
  if (!m.reunited_at) await run('UPDATE moments SET reunited_at = ? WHERE id = ?', Date.now(), m.id);
  return c.json(myMoment(await momentWithExtras(m.id), baseUrl(c)));
});

/** Body: { reflection?, audience?, recipients? }. */
priv.patch('/moments/:id', async (c) => {
  const user = c.get('user');
  const m = await ownMoment(c);
  if (!m) return bad(c, 'not_found', 404);
  const b = await body(c);
  if (b.reflection !== undefined) {
    await run('UPDATE moments SET reflection = ? WHERE id = ?', str(b.reflection, 500) || null, m.id);
  }
  if (AUDIENCES.has(b.audience)) {
    const before = new Set(await audienceOf(m));
    let recipients = [];
    if (b.audience === 'selected') {
      recipients = await validRecipients(user.id, b.recipients);
      if (!recipients.length) return bad(c, 'recipients_required');
    }
    await batch([
      ['UPDATE moments SET audience = ? WHERE id = ?', b.audience, m.id],
      ['DELETE FROM moment_recipients WHERE moment_id = ?', m.id],
      ...recipients.map((uid) => ['INSERT OR IGNORE INTO moment_recipients (moment_id, user_id) VALUES (?, ?)', m.id, uid]),
    ]);
    // Tell only the people who can see it now and could not before.
    const updated = await one('SELECT * FROM moments WHERE id = ?', m.id);
    const added = (await audienceOf(updated)).filter((uid) => !before.has(uid));
    if (added.length) background(pushToUsers(added, text(FRIEND_POST_TEXT, user.name), { type: 'friend_post', momentId: m.id }));
  }
  return c.json(myMoment(await momentWithExtras(m.id), baseUrl(c)));
});

priv.delete('/moments/:id', async (c) => {
  const m = await ownMoment(c);
  if (!m) return bad(c, 'not_found', 404);
  await run('DELETE FROM moments WHERE id = ?', m.id);
  await bindings.PHOTOS.delete(m.photo_path).catch(() => {});
  return c.json({ ok: true });
});

// ---------- Let's connect ----------

/**
 * Friends' posts I may see. Besides the old single-perspective fields (kept for
 * older apps) each post says how many comments I can see and when something that
 * concerns me last happened (my comments, and answers to them).
 */
priv.get('/feed', async (c) => {
  const id = c.get('user').id;
  const rows = await all(
    `SELECT m.*, u.name AS author_name, u.handle AS author_handle,
            (SELECT opened_at FROM photo_views v WHERE v.moment_id = m.id AND v.viewer_id = ?) AS viewed_at
       FROM moments m
       JOIN friendships f ON f.user_id = m.user_id AND f.friend_id = ?
       JOIN users u ON u.id = m.user_id
      WHERE (m.audience = 'circle'
             OR (m.audience = 'closeFriends' AND f.close = 1)
             OR (m.audience = 'selected' AND EXISTS (SELECT 1 FROM moment_recipients r WHERE r.moment_id = m.id AND r.user_id = ?)))
        AND EXISTS (SELECT 1 FROM friendships mine WHERE mine.user_id = ? AND mine.friend_id = m.user_id)
        AND NOT EXISTS (SELECT 1 FROM blocks b WHERE (b.user_id = ? AND b.blocked_id = m.user_id)
                                                  OR (b.user_id = m.user_id AND b.blocked_id = ?))
      ORDER BY m.created_at DESC LIMIT 100`,
    id, id, id, id, id, id,
  );
  const comments = await commentsOf(rows.map((m) => m.id));
  return c.json(rows.map((m) => {
    const visible = visibleComments(comments.get(m.id) || [], id, m.user_id);
    const mineTop = visible.filter((r) => r.author_id === id && !r.parent_id);
    const myIds = new Set(visible.filter((r) => r.author_id === id).map((r) => r.id));
    const toMe = visible.filter((r) => r.author_id !== id && r.parent_id && myIds.has(r.parent_id));
    const ownerToMe = toMe.filter((r) => r.author_id === m.user_id);
    const last = (list) => list.length ? list[list.length - 1] : null;
    const mine = visible.filter((r) => r.author_id === id);
    return feedMoment({
      ...m,
      my_comment: last(mineTop)?.text ?? null,
      my_comment_reply: last(ownerToMe)?.text ?? null,
      my_comment_replied_at: last(ownerToMe)?.created_at ?? null,
      comment_count: visible.length,
      my_comment_count: mine.length,
      replies_to_me: toMe.length,
      last_activity_at: Math.max(0, ...mine.map((r) => r.created_at), ...toMe.map((r) => r.created_at)) || null,
    });
  }));
});

/**
 * Opens a friend's photo. The first call records the view; after a short grace
 * period (for a flaky connection) the photo can never be opened again.
 */
priv.post('/moments/:id/view', async (c) => {
  const meId = c.get('user').id;
  const m = await one('SELECT * FROM moments WHERE id = ?', c.req.param('id'));
  if (!m || m.user_id === meId || !(await canSee(meId, m))) return bad(c, 'not_found', 404);
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

// ---------- Comments ----------

const loadComments = async (m) => (await commentsOf([m.id])).get(m.id) || [];

/**
 * ?v=2 → every comment the viewer may see, flat (replies carry parentId).
 * Without it (older apps): top-level comments only, each with the owner's latest reply;
 * the owner sees all of them, a friend only their own.
 */
priv.get('/moments/:id/comments', async (c) => {
  const meId = c.get('user').id;
  const m = await one('SELECT * FROM moments WHERE id = ?', c.req.param('id'));
  if (!(await canSee(meId, m))) return bad(c, 'not_found', 404);
  const rows = await loadComments(m);
  if (c.req.query('v') === '2') {
    return c.json({
      isOwner: m.user_id === meId,
      comments: visibleComments(rows, meId, m.user_id).map((r) => commentJson(r, meId)),
    });
  }
  const owner = m.user_id === meId;
  const tops = rows.filter((r) => !r.parent_id && r.author_id !== m.user_id && (owner || r.author_id === meId));
  return c.json(tops.map((r) => {
    const reply = rows.filter((x) => x.parent_id === r.id && x.author_id === m.user_id).pop();
    return {
      id: r.id, text: r.text, createdAt: iso(r.created_at),
      author: { id: r.author_id, name: r.name, handle: r.handle },
      reply: reply?.text ?? null, repliedAt: iso(reply?.created_at),
    };
  }));
});

/**
 * New comment. Body: { text, parentId?, visibility: 'owner' | 'circle' }.
 * 'circle' from a friend waits for the owner's approval before others see it.
 */
priv.post('/moments/:id/comments', async (c) => {
  const user = c.get('user');
  const m = await one('SELECT * FROM moments WHERE id = ?', c.req.param('id'));
  if (!(await canSee(user.id, m))) return bad(c, 'not_found', 404);
  const b = await body(c);
  const textValue = str(b.text, 500);
  if (!textValue) return bad(c, 'text_required');
  const rows = await loadComments(m);
  let parent = null;
  if (b.parentId) {
    parent = rows.find((r) => r.id === String(b.parentId));
    const visible = parent && visibleComments(rows, user.id, m.user_id).some((r) => r.id === parent.id);
    if (!visible) return bad(c, 'parent_not_found', 404);
  }
  const isOwner = m.user_id === user.id;
  const visibility = isOwner ? 'circle' : (VISIBILITIES.has(b.visibility) ? b.visibility : 'owner');
  const status = !isOwner && visibility === 'circle' ? 'pending' : 'approved';
  const id = newId();
  const now = Date.now();
  await run(
    `INSERT INTO comments (id, moment_id, author_id, parent_id, text, visibility, status, created_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
    id, m.id, user.id, parent?.id ?? null, textValue, visibility, status, now,
  );
  notifyNewComment(user, m, parent);
  const row = await one('SELECT c.*, u.name, u.handle FROM comments c JOIN users u ON u.id = c.author_id WHERE c.id = ?', id);
  return c.json(commentJson(row, user.id), 201);
});

/** Edit my own comment. Body: { text }. */
priv.patch('/moments/:id/comments/:commentId', async (c) => {
  const user = c.get('user');
  const cm = await one('SELECT * FROM comments WHERE id = ? AND moment_id = ? AND author_id = ?',
    c.req.param('commentId'), c.req.param('id'), user.id);
  if (!cm) return bad(c, 'not_found', 404);
  const textValue = str((await body(c)).text, 500);
  if (!textValue) return bad(c, 'text_required');
  await run('UPDATE comments SET text = ?, edited_at = ? WHERE id = ?', textValue, Date.now(), cm.id);
  const row = await one('SELECT c.*, u.name, u.handle FROM comments c JOIN users u ON u.id = c.author_id WHERE c.id = ?', cm.id);
  return c.json(commentJson(row, user.id));
});

/** The author or the photo's owner removes a comment (and the replies under it). */
priv.delete('/moments/:id/comments/:commentId', async (c) => {
  const user = c.get('user');
  const m = await one('SELECT * FROM moments WHERE id = ?', c.req.param('id'));
  const cm = m && await one('SELECT * FROM comments WHERE id = ? AND moment_id = ?', c.req.param('commentId'), m.id);
  if (!cm || (cm.author_id !== user.id && m.user_id !== user.id)) return bad(c, 'not_found', 404);
  const rows = await loadComments(m);
  const doomed = new Set([cm.id]);
  for (let grew = true; grew;) {
    grew = false;
    for (const r of rows) if (r.parent_id && doomed.has(r.parent_id) && !doomed.has(r.id)) { doomed.add(r.id); grew = true; }
  }
  await run('DELETE FROM comments WHERE id IN (SELECT value FROM json_each(?))', JSON.stringify([...doomed]));
  return c.json({ ok: true, deleted: doomed.size });
});

/** Owner decides whether a comment meant for the circle is shown to it. Body: { approve: bool }. */
priv.post('/moments/:id/comments/:commentId/approve', async (c) => {
  const m = await ownMoment(c);
  if (!m) return bad(c, 'not_found', 404);
  const cm = await one("SELECT * FROM comments WHERE id = ? AND moment_id = ? AND visibility = 'circle'", c.req.param('commentId'), m.id);
  if (!cm) return bad(c, 'not_found', 404);
  const approve = (await body(c)).approve !== false;
  await run('UPDATE comments SET status = ? WHERE id = ?', approve ? 'approved' : 'rejected', cm.id);
  // An approved answer to someone's comment now reaches them.
  if (approve && cm.status !== 'approved' && cm.parent_id) {
    const parent = await one('SELECT * FROM comments WHERE id = ?', cm.parent_id);
    const author = await one('SELECT * FROM users WHERE id = ?', cm.author_id);
    if (parent && author && parent.author_id !== author.id && parent.author_id !== m.user_id) {
      background(pushToUsers([parent.author_id], text(REPLY_TEXT, author.name), { type: 'comment_reply', momentId: m.id }));
    }
  }
  return c.json({ ok: true, status: approve ? 'approved' : 'rejected' });
});

// Older apps: one perspective per friend + one reply from the owner.

/** (old) The owner answers a perspective — edits their latest reply under it, or adds one. */
priv.put('/moments/:id/comments/:commentId/reply', async (c) => {
  const user = c.get('user');
  const m = await ownMoment(c);
  if (!m) return bad(c, 'not_found', 404);
  const cm = await one('SELECT * FROM comments WHERE id = ? AND moment_id = ?', c.req.param('commentId'), m.id);
  if (!cm) return bad(c, 'not_found', 404);
  const textValue = str((await body(c)).text, 500);
  if (!textValue) return bad(c, 'text_required');
  const existing = await one('SELECT * FROM comments WHERE parent_id = ? AND author_id = ? ORDER BY created_at DESC LIMIT 1', cm.id, m.user_id);
  const now = Date.now();
  if (existing) {
    await run('UPDATE comments SET text = ?, edited_at = ? WHERE id = ?', textValue, now, existing.id);
  } else {
    await run(
      `INSERT INTO comments (id, moment_id, author_id, parent_id, text, visibility, status, created_at)
       VALUES (?, ?, ?, ?, ?, 'circle', 'approved', ?)`,
      newId(), m.id, m.user_id, cm.id, textValue, now,
    );
    notifyNewComment(user, m, cm);
  }
  return c.json({ ok: true, reply: textValue, repliedAt: iso(existing?.created_at ?? now) });
});

priv.delete('/moments/:id/comments/:commentId/reply', async (c) => {
  const m = await ownMoment(c);
  if (!m) return bad(c, 'not_found', 404);
  await run('DELETE FROM comments WHERE parent_id = ? AND moment_id = ? AND author_id = ?', c.req.param('commentId'), m.id, m.user_id);
  return c.json({ ok: true });
});

/** (old) "Send your perspective": edits my latest private top-level comment, or adds one. */
priv.put('/moments/:id/comment', async (c) => {
  const user = c.get('user');
  const m = await one('SELECT * FROM moments WHERE id = ?', c.req.param('id'));
  if (!m || m.user_id === user.id || !(await canSee(user.id, m))) return bad(c, 'not_found', 404);
  const textValue = str((await body(c)).text, 500);
  if (!textValue) return bad(c, 'text_required');
  const existing = await one(
    'SELECT * FROM comments WHERE moment_id = ? AND author_id = ? AND parent_id IS NULL ORDER BY created_at DESC LIMIT 1', m.id, user.id);
  if (existing) {
    await run('UPDATE comments SET text = ?, edited_at = ? WHERE id = ?', textValue, Date.now(), existing.id);
  } else {
    await run(
      `INSERT INTO comments (id, moment_id, author_id, parent_id, text, visibility, status, created_at)
       VALUES (?, ?, ?, NULL, ?, 'owner', 'approved', ?)`,
      newId(), m.id, user.id, textValue, Date.now(),
    );
    notifyNewComment(user, m, null);
  }
  return c.json({ ok: true, text: textValue });
});

/** (old) Removes all my comments on a moment. */
priv.delete('/moments/:id/comment', async (c) => {
  const me = c.get('user').id;
  const mine = await all('SELECT id FROM comments WHERE moment_id = ? AND author_id = ?', c.req.param('id'), me);
  const ids = mine.map((r) => r.id);
  if (ids.length) {
    await run('DELETE FROM comments WHERE id IN (SELECT value FROM json_each(?)) OR parent_id IN (SELECT value FROM json_each(?))',
      JSON.stringify(ids), JSON.stringify(ids));
  }
  return c.json({ ok: true });
});

/**
 * What happened since `since` (ms): comments on my photos, answers to my comments,
 * new friends, and (v=2) friend requests. Android without Firebase polls this.
 */
priv.get('/activity', async (c) => {
  const id = c.get('user').id;
  const since = Number(c.req.query('since')) || 0;
  const v2 = c.req.query('v') === '2';
  const user = (r) => ({ id: r.uid, name: r.name, handle: r.handle });
  const snippet = (s) => (s && s.length > 80 ? `${s.slice(0, 79)}…` : s);
  const comments = (await all(
    `SELECT c.id AS cid, c.moment_id, c.created_at AS at, c.text, c.visibility, c.status, c.parent_id,
            u.id AS uid, u.name, u.handle FROM comments c
       JOIN moments m ON m.id = c.moment_id JOIN users u ON u.id = c.author_id
      WHERE m.user_id = ? AND c.author_id <> ? AND c.created_at > ?
      ORDER BY c.created_at DESC LIMIT 30`,
    id, id, since,
  )).map((r) => ({
    type: 'comment', momentId: r.moment_id, at: iso(r.at), user: user(r),
    ...(v2 ? { commentId: r.cid, text: snippet(r.text), mine: true, pending: r.visibility === 'circle' && r.status === 'pending' } : {}),
  }));
  // Answers to my comments (from the owner, or from anyone who can see them).
  const answers = await all(
    `SELECT c.id AS cid, c.moment_id, c.created_at AS at, c.text, c.author_id, m.user_id AS owner_id,
            u.id AS uid, u.name, u.handle FROM comments c
       JOIN comments p ON p.id = c.parent_id
       JOIN moments m ON m.id = c.moment_id JOIN users u ON u.id = c.author_id
      WHERE p.author_id = ? AND c.author_id <> ? AND c.created_at > ? AND m.user_id <> ?
        AND (c.author_id = m.user_id OR (c.visibility = 'circle' AND c.status = 'approved'))
      ORDER BY c.created_at DESC LIMIT 30`,
    id, id, since, id,
  );
  const replies = answers
    .filter((r) => v2 || r.author_id === r.owner_id)
    .map((r) => ({
      type: 'comment_reply', momentId: r.moment_id, at: iso(r.at), user: user(r),
      ...(v2 ? { commentId: r.cid, text: snippet(r.text), mine: false } : {}),
    }));
  const friends = (await all(
    `SELECT f.created_at AS at, u.id AS uid, u.name, u.handle FROM friendships f JOIN users u ON u.id = f.friend_id
      WHERE f.user_id = ? AND f.added_by = f.friend_id AND f.created_at > ?
      ORDER BY f.created_at DESC LIMIT 20`,
    id, since,
  )).map((r) => ({ type: 'friend_added', momentId: null, at: iso(r.at), user: user(r) }));
  const requests = v2 ? (await all(
    `SELECT r.created_at AS at, u.id AS uid, u.name, u.handle FROM friend_requests r JOIN users u ON u.id = r.from_id
      WHERE r.to_id = ? AND r.created_at > ? ORDER BY r.created_at DESC LIMIT 20`,
    id, since,
  )).map((r) => ({ type: 'friend_request', momentId: null, at: iso(r.at), user: user(r) })) : [];
  const items = [...comments, ...replies, ...friends, ...requests].sort((a, b) => (a.at < b.at ? 1 : -1));
  return c.json({ now: new Date().toISOString(), items });
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
const FRIEND_REQUEST_TEXT = {
  vi: (name) => ({ title: 'SEELI', body: `${name} muốn kết bạn với bạn.` }),
  ja: (name) => ({ title: 'SEELI', body: `${name}さんからつながりリクエストが届きました。` }),
};
const COMMENT_TEXT = {
  vi: (name) => ({ title: name, body: 'đã bình luận về khoảnh khắc của bạn.' }),
  ja: (name) => ({ title: name, body: 'さんがあなたの瞬間にコメントしました。' }),
};
const REPLY_TEXT = {
  vi: (name) => ({ title: name, body: 'đã trả lời bình luận của bạn.' }),
  ja: (name) => ({ title: name, body: 'さんがあなたのコメントに返信しました。' }),
};
const text = (table, name) => (lang) => (table[lang] || table.vi)(name);

/** Tells someone that a person connected with them. */
const notifyFriendAdded = (adder, friendId) =>
  background(pushToUsers([friendId], text(FRIEND_ADDED_TEXT, adder.name), { type: 'friend_added', friendId: adder.id }));

const notifyFriendRequest = (from, toId) =>
  background(pushToUsers([toId], text(FRIEND_REQUEST_TEXT, from.name), { type: 'friend_request', friendId: from.id }));

/** A new comment: tell the photo's owner, and the author of the comment it answers. */
const notifyNewComment = (author, m, parent, { visibleToParent } = {}) => {
  // The parent's author hears about it only once they can see it (owner's answer, or approved).
  const seen = visibleToParent ?? author.id === m.user_id;
  if (parent && parent.author_id !== author.id && seen) {
    background(pushToUsers([parent.author_id], text(REPLY_TEXT, author.name), { type: 'comment_reply', momentId: m.id }));
  }
  if (m.user_id !== author.id && parent?.author_id !== m.user_id) {
    background(pushToUsers([m.user_id], text(COMMENT_TEXT, author.name), { type: 'comment', momentId: m.id }));
  }
};

/** Tells everyone who can see a new post. */
const notifyNewPost = (author, m) => background((async () => {
  const ids = await audienceOf(m);
  if (ids.length) await pushToUsers(ids, text(FRIEND_POST_TEXT, author.name), { type: 'friend_post', momentId: m.id });
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

const ownMoment = (c) => one('SELECT * FROM moments WHERE id = ? AND user_id = ?', c.req.param('id'), c.get('user').id);

const UNFRIEND = 'DELETE FROM friendships WHERE (user_id = ? AND friend_id = ?) OR (user_id = ? AND friend_id = ?)';
const unfriendParams = (a, b) => [a, b, b, a];

function friendRow(r) {
  return { id: r.id, name: r.name, handle: r.handle, bio: r.bio, memo: r.memo, close: !!r.close, connectedAt: iso(r.created_at) };
}

async function friendJson(meId, friendId) {
  return friendRow(await one(
    `SELECT u.id, u.name, u.handle, u.bio, f.memo, f.close, f.created_at
       FROM friendships f JOIN users u ON u.id = f.friend_id WHERE f.user_id = ? AND f.friend_id = ?`,
    meId, friendId,
  ));
}
