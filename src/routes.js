import { createReadStream, mkdirSync } from 'node:fs';
import { unlink, writeFile, rm } from 'node:fs/promises';
import { join, dirname } from 'node:path';
import { config } from './config.js';
import { one, all, run, tx } from './db.js';
import {
  hashPassword, verifyPassword, issueToken, requireUser,
  checkPhotoSignature, checkOncePhotoSignature, oncePhotoSignature, newInviteCode, newId,
} from './auth.js';
import { me, publicUser, myMoment, feedMoment, iso } from './serialize.js';
import { verifyIdToken, TokenError } from './oidc.js';
import { appleConfigured, exchangeCode, revokeToken } from './apple.js';
import { pushToUsers } from './apns.js';

/** Profile JSON including which sign-in providers are linked. */
const meOf = (u) => me(u, all('SELECT provider FROM identities WHERE user_id = ? ORDER BY provider', u.id).map((r) => r.provider));

/** Turns a name/email into an available handle like "phat", "phat2"… */
function suggestHandle(...seeds) {
  for (const seed of seeds) {
    const base = String(seed || '').normalize('NFD').replace(/[\u0300-\u036f]/g, '').replace(/đ/gi, 'd')
      .toLowerCase().replace(/[^a-z0-9._-]+/g, '').replace(/^[._-]+|[._-]+$/g, '').slice(0, 24);
    if (base.length < 2) continue;
    for (let i = 0; i < 50; i++) {
      const h = i === 0 ? base : `${base}${i + 1}`;
      if (!one('SELECT 1 FROM users WHERE handle = ?', h)) return h;
    }
  }
  for (;;) {
    const h = `seeli${Math.floor(1000 + Math.random() * 900000)}`;
    if (!one('SELECT 1 FROM users WHERE handle = ?', h)) return h;
  }
}

const HANDLE_RE = /^[a-z0-9._-]{2,30}$/;
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const AUDIENCES = new Set(['onlyMe', 'circle']);
const ONCE_GRACE_MS = 2 * 60_000;  // retry window after the first open
const ONCE_URL_TTL_SEC = 120;
const DAY = 86_400_000;

const str = (v, max) => (typeof v === 'string' ? v.trim().slice(0, max) : '');
const bad = (reply, error, code = 400) => reply.code(code).send({ error });

/** Tiny in-memory limiter for auth endpoints (per IP). */
const hits = new Map();
function limited(ip, max = config.authRateLimit, windowMs = 60_000) {
  const now = Date.now();
  const list = (hits.get(ip) || []).filter((t) => now - t < windowMs);
  list.push(now);
  hits.set(ip, list);
  return list.length > max;
}

const baseUrl = (req) => config.publicUrl || `${req.protocol}://${req.host}`;

const isBlockedEitherWay = (a, b) =>
  !!one('SELECT 1 FROM blocks WHERE (user_id = ? AND blocked_id = ?) OR (user_id = ? AND blocked_id = ?)', a, b, b, a);

const areFriends = (a, b) => !!one('SELECT 1 FROM friendships WHERE user_id = ? AND friend_id = ?', a, b);

function revealTime(createdAt, demo) {
  if (demo && config.allowDemo) return Date.now() + (45 + Math.random() * 45) * 1000;
  const days = config.revealMinDays + Math.random() * (config.revealMaxDays - config.revealMinDays);
  return createdAt + days * DAY;
}

function uniqueInviteCode() {
  for (;;) {
    const code = newInviteCode();
    if (!one('SELECT 1 FROM users WHERE invite_code = ?', code)) return code;
  }
}

export default async function routes(app) {
  app.get('/health', async () => ({ ok: true, time: iso(Date.now()), allowDemo: config.allowDemo }));

  // ---------- Auth ----------

  app.post('/auth/signup', async (req, reply) => {
    if (limited(req.ip)) return bad(reply, 'too_many_requests', 429);
    const name = str(req.body?.name, 40);
    const handle = str(req.body?.handle, 30).toLowerCase().replace(/^@/, '');
    const email = str(req.body?.email, 120).toLowerCase();
    const password = typeof req.body?.password === 'string' ? req.body.password : '';
    if (!name) return bad(reply, 'name_required');
    if (!HANDLE_RE.test(handle)) return bad(reply, 'invalid_handle');
    if (!EMAIL_RE.test(email)) return bad(reply, 'invalid_email');
    if (password.length < 8 || password.length > 200) return bad(reply, 'weak_password');
    if (one('SELECT 1 FROM users WHERE handle = ?', handle)) return bad(reply, 'handle_taken', 409);
    if (one('SELECT 1 FROM users WHERE email = ?', email)) return bad(reply, 'email_taken', 409);

    const user = {
      id: newId(), name, handle, email, password_hash: hashPassword(password),
      bio: '', invite_code: uniqueInviteCode(), token_version: 0, created_at: Date.now(),
    };
    run(
      `INSERT INTO users (id, name, handle, email, password_hash, bio, invite_code, token_version, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      user.id, user.name, user.handle, user.email, user.password_hash, user.bio,
      user.invite_code, user.token_version, user.created_at,
    );
    return reply.code(201).send({ token: issueToken(user), user: meOf(user) });
  });

  app.post('/auth/login', async (req, reply) => {
    if (limited(req.ip)) return bad(reply, 'too_many_requests', 429);
    const email = str(req.body?.email, 120).toLowerCase();
    const password = typeof req.body?.password === 'string' ? req.body.password : '';
    const user = one('SELECT * FROM users WHERE email = ?', email);
    if (!user || !verifyPassword(password, user.password_hash)) return bad(reply, 'invalid_credentials', 401);
    if (user.suspended_at) return bad(reply, 'account_suspended', 403);
    return { token: issueToken(user), user: meOf(user) };
  });

  /**
   * Sign in with Apple / Google. Body: { idToken, nonce?, name? }.
   * Existing link → sign in. Verified email matching an account → link it.
   * Otherwise a new account is created (handle suggested, editable later).
   */
  app.post('/auth/:provider', async (req, reply) => {
    const provider = req.params.provider;
    if (provider !== 'apple' && provider !== 'google') return bad(reply, 'not_found', 404);
    if (limited(req.ip)) return bad(reply, 'too_many_requests', 429);
    let claims;
    try {
      claims = await verifyIdToken(provider, req.body?.idToken, { nonce: req.body?.nonce || undefined });
    } catch (e) {
      if (e instanceof TokenError) return bad(reply, e.message === 'provider_not_configured' ? 'provider_disabled' : 'invalid_token', 401);
      req.log.error(e);
      return bad(reply, 'provider_unreachable', 502);
    }

    const linked = one('SELECT u.* FROM identities i JOIN users u ON u.id = i.user_id WHERE i.provider = ? AND i.subject = ?', provider, claims.sub);
    let user = linked;
    let isNew = false;
    if (!user && claims.email && claims.emailVerified) {
      user = one('SELECT * FROM users WHERE email = ?', claims.email);
    }
    if (user?.suspended_at) return bad(reply, 'account_suspended', 403);

    if (!user) {
      const name = str(req.body?.name, 40) || str(claims.name, 40) || (claims.email ? claims.email.split('@')[0] : '') || 'SEELI';
      const email = claims.email && !one('SELECT 1 FROM users WHERE email = ?', claims.email)
        ? claims.email
        : `${provider}.${claims.sub.replace(/[^a-zA-Z0-9]/g, '').slice(-24)}@users.seeli.invalid`;
      user = {
        id: newId(), name, handle: suggestHandle(name, claims.email?.split('@')[0]), email, password_hash: '',
        bio: '', invite_code: uniqueInviteCode(), token_version: 0, created_at: Date.now(),
      };
      run(
        `INSERT INTO users (id, name, handle, email, password_hash, bio, invite_code, token_version, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        user.id, user.name, user.handle, user.email, user.password_hash, user.bio,
        user.invite_code, user.token_version, user.created_at,
      );
      isNew = true;
    }
    if (!linked) {
      run('INSERT OR IGNORE INTO identities (provider, subject, user_id, email, created_at) VALUES (?, ?, ?, ?, ?)',
        provider, claims.sub, user.id, claims.email, Date.now());
    }
    // Keep Apple's refresh token so access can be revoked when the account is deleted.
    if (provider === 'apple' && req.body?.authorizationCode) {
      const refresh = await exchangeCode(String(req.body.authorizationCode)).catch((e) => { req.log.warn(e); return null; });
      if (refresh) run('UPDATE identities SET refresh_token = ? WHERE provider = ? AND subject = ?', refresh, provider, claims.sub);
    }
    user = one('SELECT * FROM users WHERE id = ?', user.id);
    return reply.code(isNew ? 201 : 200).send({ token: issueToken(user), user: meOf(user), isNew });
  });

  // Everything below needs a signed-in user (except /photos, which uses signed URLs).
  app.register(async (priv) => {
    priv.addHook('preHandler', requireUser);

    // ---------- Me ----------

    priv.get('/me', async (req) => meOf(req.user));

    priv.patch('/me', async (req, reply) => {
      const name = req.body?.name !== undefined ? str(req.body.name, 40) : req.user.name;
      const bio = req.body?.bio !== undefined ? str(req.body.bio, 300) : req.user.bio;
      const handle = req.body?.handle !== undefined ? str(req.body.handle, 30).toLowerCase().replace(/^@/, '') : req.user.handle;
      if (!name) return bad(reply, 'name_required');
      if (!HANDLE_RE.test(handle)) return bad(reply, 'invalid_handle');
      if (handle !== req.user.handle && one('SELECT 1 FROM users WHERE handle = ?', handle)) return bad(reply, 'handle_taken', 409);
      run('UPDATE users SET name = ?, bio = ?, handle = ? WHERE id = ?', name, bio, handle, req.user.id);
      return meOf(one('SELECT * FROM users WHERE id = ?', req.user.id));
    });

    /** Sign out everywhere. */
    /** Registers this device for push. env: "sandbox" (debug builds) or "production". */
    priv.put('/me/device', async (req, reply) => {
      const token = String(req.body?.token || '');
      if (!/^[0-9a-f]{64,200}$/i.test(token)) return bad(reply, 'invalid_token');
      const env = req.body?.env === 'sandbox' ? 'sandbox' : 'production';
      const lang = req.body?.lang === 'ja' ? 'ja' : 'vi';
      run(`INSERT INTO device_tokens (token, user_id, env, lang, updated_at) VALUES (?, ?, ?, ?, ?)
           ON CONFLICT (token) DO UPDATE SET user_id = excluded.user_id, env = excluded.env,
             lang = excluded.lang, updated_at = excluded.updated_at`,
      token.toLowerCase(), req.user.id, env, lang, Date.now());
      return { ok: true };
    });

    priv.delete('/me/device', async (req) => {
      run('DELETE FROM device_tokens WHERE token = ? AND user_id = ?', String(req.body?.token || '').toLowerCase(), req.user.id);
      return { ok: true };
    });

    priv.post('/auth/logout', async (req) => {
      run('UPDATE users SET token_version = token_version + 1 WHERE id = ?', req.user.id);
      run('DELETE FROM device_tokens WHERE user_id = ?', req.user.id);
      return { ok: true };
    });

    /**
     * Delete account. Linked Apple IDs are revoked first (Guideline 5.1.1(v)).
     * If we hold no Apple token, the app re-authenticates and sends `appleAuthorizationCode`.
     */
    priv.delete('/me', async (req, reply) => {
      const appleCode = req.body?.appleAuthorizationCode ? String(req.body.appleAuthorizationCode) : null;
      const needsCode = appleConfigured() && !appleCode &&
        !!one("SELECT 1 FROM identities WHERE user_id = ? AND provider = 'apple' AND refresh_token IS NULL", req.user.id);
      if (needsCode) return bad(reply, 'apple_reauth_required', 409);
      const result = await deleteUserCompletely(req.user.id, { appleCode, log: req.log });
      return { ok: true, ...result };
    });

    priv.post('/me/invite/rotate', async (req) => {
      run('UPDATE users SET invite_code = ? WHERE id = ?', uniqueInviteCode(), req.user.id);
      return meOf(one('SELECT * FROM users WHERE id = ?', req.user.id));
    });

    // ---------- Friends (QR invite codes) ----------

    priv.get('/invites/:code', async (req, reply) => {
      const u = one('SELECT * FROM users WHERE invite_code = ?', String(req.params.code).toUpperCase());
      if (!u || isBlockedEitherWay(req.user.id, u.id)) return bad(reply, 'not_found', 404);
      return { user: publicUser(u), isSelf: u.id === req.user.id, isFriend: areFriends(req.user.id, u.id) };
    });

    priv.post('/friends', async (req, reply) => {
      const code = str(req.body?.code, 20).toUpperCase();
      const u = one('SELECT * FROM users WHERE invite_code = ?', code);
      if (!u || isBlockedEitherWay(req.user.id, u.id)) return bad(reply, 'not_found', 404);
      if (u.id === req.user.id) return bad(reply, 'self');
      const now = Date.now();
      tx(() => {
        run('INSERT OR IGNORE INTO friendships (user_id, friend_id, created_at) VALUES (?, ?, ?)', req.user.id, u.id, now);
        run('INSERT OR IGNORE INTO friendships (user_id, friend_id, created_at) VALUES (?, ?, ?)', u.id, req.user.id, now);
      });
      return reply.code(201).send(friendJson(req.user.id, u.id));
    });

    priv.get('/friends', async (req) =>
      all(
        `SELECT u.id, u.name, u.handle, u.bio, f.memo, f.created_at
           FROM friendships f JOIN users u ON u.id = f.friend_id
          WHERE f.user_id = ? ORDER BY f.created_at DESC`,
        req.user.id,
      ).map(friendRow),
    );

    priv.patch('/friends/:id', async (req, reply) => {
      const r = run('UPDATE friendships SET memo = ? WHERE user_id = ? AND friend_id = ?',
        str(req.body?.memo, 500), req.user.id, req.params.id);
      if (!r.changes) return bad(reply, 'not_found', 404);
      return friendJson(req.user.id, req.params.id);
    });

    priv.delete('/friends/:id', async (req) => {
      unfriend(req.user.id, req.params.id);
      return { ok: true };
    });

    priv.post('/friends/:id/block', async (req, reply) => {
      if (!one('SELECT 1 FROM users WHERE id = ?', req.params.id)) return bad(reply, 'not_found', 404);
      tx(() => {
        const mine = one('SELECT * FROM friendships WHERE user_id = ? AND friend_id = ?', req.user.id, req.params.id);
        const theirs = one('SELECT * FROM friendships WHERE user_id = ? AND friend_id = ?', req.params.id, req.user.id);
        unfriend(req.user.id, req.params.id);
        run(`INSERT OR IGNORE INTO blocks (user_id, blocked_id, created_at, friend_since, memo, their_memo)
             VALUES (?, ?, ?, ?, ?, ?)`,
          req.user.id, req.params.id, Date.now(), mine?.created_at ?? null, mine?.memo ?? null, theirs?.memo ?? null);
      });
      return { ok: true };
    });

    priv.get('/blocks', async (req) =>
      all('SELECT u.* FROM blocks b JOIN users u ON u.id = b.blocked_id WHERE b.user_id = ?', req.user.id).map(publicUser),
    );

    /** Unblocking restores the friendship the block ended (and with it their circle posts). */
    priv.delete('/blocks/:id', async (req) => {
      let restored = false;
      tx(() => {
        const b = one('SELECT * FROM blocks WHERE user_id = ? AND blocked_id = ?', req.user.id, req.params.id);
        run('DELETE FROM blocks WHERE user_id = ? AND blocked_id = ?', req.user.id, req.params.id);
        if (b?.friend_since && !isBlockedEitherWay(req.user.id, req.params.id)) {
          run('INSERT OR IGNORE INTO friendships (user_id, friend_id, memo, created_at) VALUES (?, ?, ?, ?)',
            req.user.id, req.params.id, b.memo ?? '', b.friend_since);
          run('INSERT OR IGNORE INTO friendships (user_id, friend_id, memo, created_at) VALUES (?, ?, ?, ?)',
            req.params.id, req.user.id, b.their_memo ?? '', b.friend_since);
          restored = true;
        }
      });
      return { ok: true, friendRestored: restored };
    });

    priv.post('/reports', async (req, reply) => {
      const target = str(req.body?.userId, 64);
      if (!target) return bad(reply, 'user_required');
      run('INSERT INTO reports (id, reporter_id, target_id, reason, created_at) VALUES (?, ?, ?, ?, ?)',
        newId(), req.user.id, target, str(req.body?.reason, 1000), Date.now());
      return reply.code(201).send({ ok: true });
    });

    // ---------- Moments ----------

    priv.get('/moments', async (req) =>
      all(
        `SELECT m.*, (SELECT COUNT(*) FROM comments c WHERE c.moment_id = m.id) AS comment_count
           FROM moments m WHERE m.user_id = ? ORDER BY m.created_at DESC`,
        req.user.id,
      ).map((m) => myMoment(m, baseUrl(req))),
    );

    priv.post('/moments', async (req, reply) => {
      const fields = {};
      let photo = null;
      for await (const part of req.parts()) {
        if (part.type === 'file') {
          if (part.fieldname === 'photo') photo = await part.toBuffer();
          else await part.toBuffer();
        } else {
          fields[part.fieldname] = part.value;
        }
      }
      if (!photo) return bad(reply, 'photo_required');
      if (!(photo[0] === 0xff && photo[1] === 0xd8)) return bad(reply, 'jpeg_required');

      const now = Date.now();
      const claimed = Date.parse(fields.createdAt);
      const createdAt = Number.isFinite(claimed) && Math.abs(claimed - now) < DAY ? claimed : now;
      const audience = AUDIENCES.has(fields.audience) ? fields.audience : 'onlyMe';
      const id = newId();
      const rel = join(req.user.id, `${id}.jpg`);
      const abs = join(config.photoDir, rel);
      mkdirSync(dirname(abs), { recursive: true });
      await writeFile(abs, photo);

      run(
        `INSERT INTO moments (id, user_id, note, place_name, audience, photo_path, created_at, reveal_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
        id, req.user.id, str(fields.note, 80), str(fields.placeName, 120) || null, audience, rel,
        createdAt, Math.round(revealTime(createdAt, fields.demo === 'true')),
      );
      if (audience === 'circle') notifyCircle(req.user, id, req.log);
      return reply.code(201).send(myMoment(one('SELECT * FROM moments WHERE id = ?', id), baseUrl(req)));
    });

    priv.post('/moments/:id/reunite', async (req, reply) => {
      const m = ownMoment(req);
      if (!m) return bad(reply, 'not_found', 404);
      if (m.reveal_at > Date.now()) return bad(reply, 'not_yet', 403);
      if (!m.reunited_at) run('UPDATE moments SET reunited_at = ? WHERE id = ?', Date.now(), m.id);
      return myMoment(one('SELECT * FROM moments WHERE id = ?', m.id), baseUrl(req));
    });

    priv.patch('/moments/:id', async (req, reply) => {
      const m = ownMoment(req);
      if (!m) return bad(reply, 'not_found', 404);
      if (req.body?.reflection !== undefined) {
        run('UPDATE moments SET reflection = ? WHERE id = ?', str(req.body.reflection, 500) || null, m.id);
      }
      if (AUDIENCES.has(req.body?.audience)) {
        run('UPDATE moments SET audience = ? WHERE id = ?', req.body.audience, m.id);
      }
      return myMoment(one('SELECT * FROM moments WHERE id = ?', m.id), baseUrl(req));
    });

    priv.delete('/moments/:id', async (req, reply) => {
      const m = ownMoment(req);
      if (!m) return bad(reply, 'not_found', 404);
      run('DELETE FROM moments WHERE id = ?', m.id);
      await unlink(join(config.photoDir, m.photo_path)).catch(() => {});
      return { ok: true };
    });

    // ---------- Let's connect ----------

    priv.get('/feed', async (req) =>
      all(
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
        req.user.id, req.user.id, req.user.id, req.user.id, req.user.id, req.user.id, req.user.id,
      ).map((m) => feedMoment(m)),
    );

    /**
     * Opens a friend's photo. The first call records the view; after a short grace
     * period (for a flaky connection) the photo can never be opened again.
     */
    priv.post('/moments/:id/view', async (req, reply) => {
      const m = one('SELECT * FROM moments WHERE id = ?', req.params.id);
      if (!m || !canComment(req.user.id, m)) return bad(reply, 'not_found', 404);
      const now = Date.now();
      const seen = one('SELECT opened_at FROM photo_views WHERE moment_id = ? AND viewer_id = ?', m.id, req.user.id);
      if (seen && now - seen.opened_at > ONCE_GRACE_MS) {
        return reply.code(410).send({ error: 'already_viewed', viewedAt: iso(seen.opened_at) });
      }
      if (!seen) run('INSERT INTO photo_views (moment_id, viewer_id, opened_at) VALUES (?, ?, ?)', m.id, req.user.id, now);
      const exp = Math.floor(now / 1000) + ONCE_URL_TTL_SEC;
      return {
        photoUrl: `${baseUrl(req)}/v1/photos/${m.id}?exp=${exp}&once=1&sig=${oncePhotoSignature(m.id, exp)}`,
        viewedAt: iso(seen?.opened_at ?? now),
      };
    });

    /** Owner sees every comment; a friend sees only their own. */
    priv.get('/moments/:id/comments', async (req, reply) => {
      const m = one('SELECT * FROM moments WHERE id = ?', req.params.id);
      if (!m || !(m.user_id === req.user.id || canComment(req.user.id, m))) return bad(reply, 'not_found', 404);
      const rows = all(
        `SELECT c.*, u.name, u.handle FROM comments c JOIN users u ON u.id = c.author_id
          WHERE c.moment_id = ? ${m.user_id === req.user.id ? '' : 'AND c.author_id = ?'}
          ORDER BY c.created_at`,
        ...(m.user_id === req.user.id ? [m.id] : [m.id, req.user.id]),
      );
      return rows.map((c) => ({
        id: c.id, text: c.text, createdAt: iso(c.created_at),
        author: { id: c.author_id, name: c.name, handle: c.handle },
        reply: c.reply ?? null, repliedAt: iso(c.replied_at),
      }));
    });

    /** The photo's owner answers a perspective. One reply per comment, editable; only that friend sees it. */
    priv.put('/moments/:id/comments/:commentId/reply', async (req, reply) => {
      const m = ownMoment(req);
      if (!m) return bad(reply, 'not_found', 404);
      const c = one('SELECT * FROM comments WHERE id = ? AND moment_id = ?', req.params.commentId, m.id);
      if (!c) return bad(reply, 'not_found', 404);
      const text = str(req.body?.text, 500);
      if (!text) return bad(reply, 'text_required');
      const now = Date.now();
      run('UPDATE comments SET reply = ?, replied_at = ? WHERE id = ?', text, now, c.id);
      if (!c.reply) notifyReply(req.user, c.author_id, m.id, req.log);
      return { ok: true, reply: text, repliedAt: iso(now) };
    });

    priv.delete('/moments/:id/comments/:commentId/reply', async (req, reply) => {
      const m = ownMoment(req);
      if (!m) return bad(reply, 'not_found', 404);
      run('UPDATE comments SET reply = NULL, replied_at = NULL WHERE id = ? AND moment_id = ?', req.params.commentId, m.id);
      return { ok: true };
    });

    /** "Send your perspective" — one per person per moment, editable. */
    priv.put('/moments/:id/comment', async (req, reply) => {
      const m = one('SELECT * FROM moments WHERE id = ?', req.params.id);
      if (!m || !canComment(req.user.id, m)) return bad(reply, 'not_found', 404);
      const text = str(req.body?.text, 500);
      if (!text) return bad(reply, 'text_required');
      run(
        `INSERT INTO comments (id, moment_id, author_id, text, created_at) VALUES (?, ?, ?, ?, ?)
         ON CONFLICT (moment_id, author_id) DO UPDATE SET text = excluded.text, created_at = excluded.created_at`,
        newId(), m.id, req.user.id, text, Date.now(),
      );
      return { ok: true, text };
    });

    priv.delete('/moments/:id/comment', async (req) => {
      run('DELETE FROM comments WHERE moment_id = ? AND author_id = ?', req.params.id, req.user.id);
      return { ok: true };
    });
  });

  // ---------- Photos (signed URL, no auth header) ----------

  app.get('/photos/:id', async (req, reply) => {
    const { exp, sig, once } = req.query;
    const valid = once ? checkOncePhotoSignature(req.params.id, exp, sig) : checkPhotoSignature(req.params.id, exp, sig);
    if (!exp || Number(exp) < Date.now() / 1000 || !valid) {
      return bad(reply, 'forbidden', 403);
    }
    const m = one('SELECT * FROM moments WHERE id = ?', req.params.id);
    // A one-time view is allowed before the reveal date: friends see it now, once.
    if (!m || (!once && m.reveal_at > Date.now())) return bad(reply, 'not_found', 404);
    reply.header('Cache-Control', once ? 'no-store' : 'private, max-age=3600');
    return reply.type('image/jpeg').send(createReadStream(join(config.photoDir, m.photo_path)));
  });
}

const FRIEND_POST_TEXT = {
  vi: (name) => ({ title: name, body: 'vừa chia sẻ một khoảnh khắc. Ảnh chỉ hiện một lần thôi.' }),
  ja: (name) => ({ title: name, body: 'さんが瞬間をシェアしました。写真は一度だけ見られます。' }),
};

/** Tells friends (not blocked either way) that someone shared to their circle. Fire and forget. */
const REPLY_TEXT = {
  vi: (name) => ({ title: name, body: 'đã trả lời cảm nhận của bạn.' }),
  ja: (name) => ({ title: name, body: 'さんがあなたの感想に返信しました。' }),
};

/** Tells a friend the photo's owner answered their perspective. */
function notifyReply(owner, commenterId, momentId, log) {
  pushToUsers([commenterId], (lang) => (REPLY_TEXT[lang] || REPLY_TEXT.vi)(owner.name),
    { type: 'comment_reply', momentId }, log).catch(() => {});
}

function notifyCircle(author, momentId, log) {
  const friends = all(
    `SELECT f.friend_id AS id FROM friendships f
      WHERE f.user_id = ?
        AND EXISTS (SELECT 1 FROM friendships r WHERE r.user_id = f.friend_id AND r.friend_id = f.user_id)
        AND NOT EXISTS (SELECT 1 FROM blocks b WHERE (b.user_id = f.friend_id AND b.blocked_id = ?)
                                                  OR (b.user_id = ? AND b.blocked_id = f.friend_id))`,
    author.id, author.id, author.id,
  ).map((r) => r.id);
  pushToUsers(friends, (lang) => (FRIEND_POST_TEXT[lang] || FRIEND_POST_TEXT.vi)(author.name),
    { type: 'friend_post', momentId }, log).catch(() => {});
}

/** Removes the account, every row that belongs to it (FK cascade) and its photos. */
export async function deleteUserCompletely(userId, { appleCode = null, log = null } = {}) {
  let appleRevoked = null;
  for (const idn of all("SELECT * FROM identities WHERE user_id = ? AND provider = 'apple'", userId)) {
    try {
      const token = idn.refresh_token || (appleCode ? await exchangeCode(appleCode) : null);
      appleRevoked = token ? await revokeToken(token) : false;
    } catch (e) {
      appleRevoked = false;
      log?.warn(e);
    }
    if (!appleRevoked) log?.warn({ userId }, 'apple_revoke_failed');
  }
  run('DELETE FROM users WHERE id = ?', userId);
  await rm(join(config.photoDir, userId), { recursive: true, force: true });
  return appleRevoked === null ? {} : { appleRevoked };
}

function canComment(userId, m) {
  return m.audience === 'circle' && areFriends(userId, m.user_id) && !isBlockedEitherWay(userId, m.user_id);
}

function ownMoment(req) {
  return one('SELECT * FROM moments WHERE id = ? AND user_id = ?', req.params.id, req.user.id);
}

function unfriend(a, b) {
  run('DELETE FROM friendships WHERE (user_id = ? AND friend_id = ?) OR (user_id = ? AND friend_id = ?)', a, b, b, a);
}

function friendRow(r) {
  return { id: r.id, name: r.name, handle: r.handle, bio: r.bio, memo: r.memo, connectedAt: iso(r.created_at) };
}

function friendJson(me, friendId) {
  return friendRow(one(
    `SELECT u.id, u.name, u.handle, u.bio, f.memo, f.created_at
       FROM friendships f JOIN users u ON u.id = f.friend_id WHERE f.user_id = ? AND f.friend_id = ?`,
    me, friendId,
  ));
}
