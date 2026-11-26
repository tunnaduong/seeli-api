import { Hono } from 'hono';
import { config, bindings } from './config.js';
import { one, all, run } from './db.js';
import { issueAdminToken, readAdminToken, checkAdminPassword } from './auth.js';
import { deleteUserCompletely, body, clientIp } from './routes.js';
import { iso } from './serialize.js';
import pageHtml from '../../src/admin.html';

const COOKIE = 'seeli_admin';

/**
 * Admin area. Deliberately shows accounts, reports and numbers only —
 * never photos, notes, places, comments or private memos.
 */
export const admin = new Hono();

// Brute-force protection: per IP, plus a global lockout (per isolate).
const failures = new Map();
let globalFails = [];
const blocked = (ip) => {
  const now = Date.now();
  globalFails = globalFails.filter((t) => now - t < 15 * 60_000);
  const mine = (failures.get(ip) || []).filter((t) => now - t < 15 * 60_000);
  failures.set(ip, mine);
  return mine.length >= 5 || globalFails.length >= 30;
};
const fail = (ip) => {
  failures.set(ip, [...(failures.get(ip) || []), Date.now()]);
  globalFails.push(Date.now());
};

const cookieValue = (c) => {
  const m = /(?:^|;\s*)seeli_admin=([^;]+)/.exec(c.req.header('cookie') || '');
  return m ? decodeURIComponent(m[1]) : '';
};
const setCookie = (c, value, maxAge) => c.header('Set-Cookie',
  `${COOKIE}=${value}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${maxAge}`);
const log = (c, action, target = null, detail = null) =>
  run('INSERT INTO admin_log (action, target, detail, ip, created_at) VALUES (?, ?, ?, ?, ?)',
    action, target, detail, clientIp(c), Date.now());

admin.get('/admin', (c) => {
  c.header('Cache-Control', 'no-store');
  c.header('X-Frame-Options', 'DENY');
  c.header('Referrer-Policy', 'no-referrer');
  c.header('X-Robots-Tag', 'noindex, nofollow');
  return c.html(pageHtml);
});

const adm = new Hono();
adm.use('*', async (c, next) => {
  c.header('Cache-Control', 'no-store');
  if (!config.adminPassword) return c.json({ error: 'admin_disabled' }, 503);
  // Mutating requests must come from our own page (CSRF guard on top of SameSite=Strict).
  if (c.req.method !== 'GET' && c.req.header('x-seeli-admin') !== '1') return c.json({ error: 'forbidden' }, 403);
  const open = c.req.path.endsWith('/login') || c.req.path.endsWith('/session');
  if (!open && !readAdminToken(cookieValue(c))) return c.json({ error: 'unauthorized' }, 401);
  await next();
});

adm.get('/session', (c) => c.json({ ok: readAdminToken(cookieValue(c)) }));

adm.post('/login', async (c) => {
  const ip = clientIp(c);
  if (blocked(ip)) return c.json({ error: 'too_many_requests' }, 429);
  if (!checkAdminPassword((await body(c)).password ?? '')) {
    fail(ip);
    return c.json({ error: 'invalid_credentials' }, 401);
  }
  failures.delete(ip);
  setCookie(c, issueAdminToken(), config.adminSessionHours * 3600);
  await log(c, 'login');
  return c.json({ ok: true });
});

adm.post('/logout', (c) => {
  setCookie(c, '', 0);
  return c.json({ ok: true });
});

adm.get('/stats', async (c) => {
  const now = Date.now();
  const week = now - 7 * 86_400_000;
  const count = async (sql, ...p) => (await one(sql, ...p)).c;
  let photoBytes = 0;
  let photoFiles = 0;
  let cursor;
  do {
    const page = await bindings.PHOTOS.list({ cursor });
    for (const o of page.objects) { photoBytes += o.size; photoFiles++; }
    cursor = page.truncated ? page.cursor : undefined;
  } while (cursor);
  return c.json({
    users: await count('SELECT count(*) c FROM users'),
    newUsers7d: await count('SELECT count(*) c FROM users WHERE created_at > ?', week),
    suspended: await count('SELECT count(*) c FROM users WHERE suspended_at IS NOT NULL'),
    moments: await count('SELECT count(*) c FROM moments'),
    moments7d: await count('SELECT count(*) c FROM moments WHERE created_at > ?', week),
    sleeping: await count('SELECT count(*) c FROM moments WHERE reveal_at > ?', now),
    reunited: await count('SELECT count(*) c FROM moments WHERE reunited_at IS NOT NULL'),
    friendships: (await count('SELECT count(*) c FROM friendships')) / 2,
    perspectives: await count('SELECT count(*) c FROM comments'),
    photoViews: await count('SELECT count(*) c FROM photo_views'),
    openReports: await count("SELECT count(*) c FROM reports WHERE status = 'open'"),
    photoFiles,
    photoBytes,
    // R2 has no fixed disk size.
    diskFreeBytes: null,
    diskTotalBytes: null,
    allowDemo: config.allowDemo,
    recentActions: (await all('SELECT action, target, detail, created_at FROM admin_log ORDER BY id DESC LIMIT 12'))
      .map((a) => ({ ...a, created_at: iso(a.created_at) })),
  });
});

adm.get('/users', async (c) => {
  const q = String(c.req.query('q') || '').trim().toLowerCase();
  const limit = Math.min(Number(c.req.query('limit')) || 50, 200);
  const offset = Math.max(Number(c.req.query('offset')) || 0, 0);
  const filter = q ? 'WHERE lower(u.name) LIKE ? OR u.handle LIKE ? OR u.email LIKE ?' : '';
  const params = q ? [`%${q}%`, `%${q}%`, `%${q}%`] : [];
  const rows = await all(
    `SELECT u.id, u.name, u.handle, u.email, u.created_at, u.suspended_at,
            (SELECT count(*) FROM moments m WHERE m.user_id = u.id) AS moments,
            (SELECT count(*) FROM friendships f WHERE f.user_id = u.id) AS friends,
            (SELECT count(*) FROM reports r WHERE r.target_id = u.id AND r.status = 'open') AS open_reports
       FROM users u ${filter} ORDER BY u.created_at DESC LIMIT ? OFFSET ?`,
    ...params, limit, offset,
  );
  const total = (await one(`SELECT count(*) c FROM users u ${filter}`, ...params)).c;
  return c.json({
    total,
    users: rows.map((u) => ({
      id: u.id, name: u.name, handle: u.handle, email: u.email,
      createdAt: iso(u.created_at), suspendedAt: iso(u.suspended_at),
      moments: u.moments, friends: u.friends, openReports: u.open_reports,
    })),
  });
});

adm.post('/users/:id/suspend', async (c) => {
  const u = await one('SELECT * FROM users WHERE id = ?', c.req.param('id'));
  if (!u) return c.json({ error: 'not_found' }, 404);
  const suspend = (await body(c)).suspended !== false;
  // Suspending also signs the person out everywhere.
  await run('UPDATE users SET suspended_at = ?, token_version = token_version + ? WHERE id = ?',
    suspend ? Date.now() : null, suspend ? 1 : 0, u.id);
  await log(c, suspend ? 'suspend' : 'unsuspend', `@${u.handle}`);
  return c.json({ ok: true });
});

/** Lets every friend open every Let's Connect photo once more (clears who-viewed-what). */
adm.post('/photo-views/reset', async (c) => {
  const { changes } = await run('DELETE FROM photo_views');
  await log(c, 'reset_views', `${changes} lượt`);
  return c.json({ ok: true, cleared: changes });
});

adm.post('/users/:id/signout', async (c) => {
  const u = await one('SELECT * FROM users WHERE id = ?', c.req.param('id'));
  if (!u) return c.json({ error: 'not_found' }, 404);
  await run('UPDATE users SET token_version = token_version + 1 WHERE id = ?', u.id);
  await log(c, 'signout', `@${u.handle}`);
  return c.json({ ok: true });
});

adm.delete('/users/:id', async (c) => {
  const u = await one('SELECT * FROM users WHERE id = ?', c.req.param('id'));
  if (!u) return c.json({ error: 'not_found' }, 404);
  if ((await body(c)).confirmHandle !== u.handle) return c.json({ error: 'confirm_handle' }, 400);
  await deleteUserCompletely(u.id);
  await log(c, 'delete', `@${u.handle}`);
  return c.json({ ok: true });
});

adm.get('/reports', async (c) => {
  const s = c.req.query('status');
  const status = ['open', 'resolved', 'dismissed'].includes(s) ? s : null;
  return c.json((await all(
    `SELECT r.*, rep.name AS reporter_name, rep.handle AS reporter_handle,
            t.name AS target_name, t.handle AS target_handle, t.suspended_at AS target_suspended,
            (SELECT count(*) FROM reports r2 WHERE r2.target_id = r.target_id) AS target_report_count
       FROM reports r
       LEFT JOIN users rep ON rep.id = r.reporter_id
       LEFT JOIN users t ON t.id = r.target_id
      ${status ? 'WHERE r.status = ?' : ''}
      ORDER BY r.created_at DESC LIMIT 200`,
    ...(status ? [status] : []),
  )).map((r) => ({
    id: r.id, status: r.status, reason: r.reason, createdAt: iso(r.created_at), resolvedAt: iso(r.resolved_at),
    reporter: r.reporter_handle ? { name: r.reporter_name, handle: r.reporter_handle } : null,
    target: r.target_handle
      ? { id: r.target_id, name: r.target_name, handle: r.target_handle, suspended: !!r.target_suspended }
      : null,
    targetReportCount: r.target_report_count,
  })));
});

adm.post('/reports/:id', async (c) => {
  const status = (await body(c)).status;
  if (!['open', 'resolved', 'dismissed'].includes(status)) return c.json({ error: 'invalid_status' }, 400);
  const r = await run('UPDATE reports SET status = ?, resolved_at = ? WHERE id = ?',
    status, status === 'open' ? null : Date.now(), c.req.param('id'));
  if (!r.changes) return c.json({ error: 'not_found' }, 404);
  await log(c, `report_${status}`, c.req.param('id').slice(0, 8));
  return c.json({ ok: true });
});

admin.route('/v1/admin', adm);
