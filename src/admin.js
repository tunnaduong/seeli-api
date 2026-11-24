import { readFileSync } from 'node:fs';
import { readdir, stat, statfs } from 'node:fs/promises';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { config } from './config.js';
import { one, all, run } from './db.js';
import { issueAdminToken, readAdminToken, checkAdminPassword } from './auth.js';
import { deleteUserCompletely } from './routes.js';
import { iso } from './serialize.js';

const COOKIE = 'seeli_admin';
const pageHtml = readFileSync(join(dirname(fileURLToPath(import.meta.url)), 'admin.html'), 'utf8');

/**
 * Admin area. Deliberately shows accounts, reports and numbers only —
 * never photos, notes, places, comments or private memos.
 */
export default async function adminRoutes(app) {
  // Brute-force protection: per IP, plus a global lockout.
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

  const cookieValue = (req) => {
    const m = /(?:^|;\s*)seeli_admin=([^;]+)/.exec(req.headers.cookie || '');
    return m ? decodeURIComponent(m[1]) : '';
  };
  const setCookie = (reply, value, maxAge) => reply.header('Set-Cookie',
    `${COOKIE}=${value}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${maxAge}`);
  const log = (req, action, target = null, detail = null) =>
    run('INSERT INTO admin_log (action, target, detail, ip, created_at) VALUES (?, ?, ?, ?, ?)',
      action, target, detail, req.ip, Date.now());

  app.get('/admin', async (req, reply) => {
    reply.header('Cache-Control', 'no-store');
    reply.header('X-Frame-Options', 'DENY');
    reply.header('Referrer-Policy', 'no-referrer');
    reply.header('X-Robots-Tag', 'noindex, nofollow');
    return reply.type('text/html; charset=utf-8').send(pageHtml);
  });

  app.register(async (adm) => {
    adm.addHook('onRequest', async (req, reply) => {
      reply.header('Cache-Control', 'no-store');
      if (!config.adminPassword) return reply.code(503).send({ error: 'admin_disabled' });
      // Mutating requests must come from our own page (CSRF guard on top of SameSite=Strict).
      if (req.method !== 'GET' && req.headers['x-seeli-admin'] !== '1') return reply.code(403).send({ error: 'forbidden' });
      const open = req.url.endsWith('/login') || req.url.endsWith('/session');
      if (!open && !readAdminToken(cookieValue(req))) return reply.code(401).send({ error: 'unauthorized' });
    });

    adm.get('/session', async (req) => ({ ok: readAdminToken(cookieValue(req)) }));

    adm.post('/login', async (req, reply) => {
      if (blocked(req.ip)) return reply.code(429).send({ error: 'too_many_requests' });
      if (!checkAdminPassword(req.body?.password ?? '')) {
        fail(req.ip);
        return reply.code(401).send({ error: 'invalid_credentials' });
      }
      failures.delete(req.ip);
      setCookie(reply, issueAdminToken(), config.adminSessionHours * 3600);
      log(req, 'login');
      return { ok: true };
    });

    adm.post('/logout', async (req, reply) => {
      setCookie(reply, '', 0);
      return { ok: true };
    });

    adm.get('/stats', async () => {
      const now = Date.now();
      const week = now - 7 * 86_400_000;
      const count = (sql, ...p) => one(sql, ...p).c;
      let photoBytes = 0;
      let photoFiles = 0;
      for (const dir of await readdir(config.photoDir).catch(() => [])) {
        for (const f of await readdir(join(config.photoDir, dir)).catch(() => [])) {
          photoBytes += (await stat(join(config.photoDir, dir, f)).catch(() => ({ size: 0 }))).size;
          photoFiles++;
        }
      }
      const fs = await statfs(config.dataDir).catch(() => null);
      return {
        users: count('SELECT count(*) c FROM users'),
        newUsers7d: count('SELECT count(*) c FROM users WHERE created_at > ?', week),
        suspended: count('SELECT count(*) c FROM users WHERE suspended_at IS NOT NULL'),
        moments: count('SELECT count(*) c FROM moments'),
        moments7d: count('SELECT count(*) c FROM moments WHERE created_at > ?', week),
        sleeping: count('SELECT count(*) c FROM moments WHERE reveal_at > ?', now),
        reunited: count('SELECT count(*) c FROM moments WHERE reunited_at IS NOT NULL'),
        friendships: count('SELECT count(*) c FROM friendships') / 2,
        perspectives: count('SELECT count(*) c FROM comments'),
        openReports: count("SELECT count(*) c FROM reports WHERE status = 'open'"),
        photoFiles,
        photoBytes,
        diskFreeBytes: fs ? fs.bavail * fs.bsize : null,
        diskTotalBytes: fs ? fs.blocks * fs.bsize : null,
        allowDemo: config.allowDemo,
        recentActions: all('SELECT action, target, detail, created_at FROM admin_log ORDER BY id DESC LIMIT 12')
          .map((a) => ({ ...a, created_at: iso(a.created_at) })),
      };
    });

    adm.get('/users', async (req) => {
      const q = String(req.query.q || '').trim().toLowerCase();
      const limit = Math.min(Number(req.query.limit) || 50, 200);
      const offset = Math.max(Number(req.query.offset) || 0, 0);
      const filter = q ? 'WHERE lower(u.name) LIKE ? OR u.handle LIKE ? OR u.email LIKE ?' : '';
      const params = q ? [`%${q}%`, `%${q}%`, `%${q}%`] : [];
      const rows = all(
        `SELECT u.id, u.name, u.handle, u.email, u.created_at, u.suspended_at,
                (SELECT count(*) FROM moments m WHERE m.user_id = u.id) AS moments,
                (SELECT count(*) FROM friendships f WHERE f.user_id = u.id) AS friends,
                (SELECT count(*) FROM reports r WHERE r.target_id = u.id AND r.status = 'open') AS open_reports
           FROM users u ${filter} ORDER BY u.created_at DESC LIMIT ? OFFSET ?`,
        ...params, limit, offset,
      );
      const total = one(`SELECT count(*) c FROM users u ${filter}`, ...params).c;
      return {
        total,
        users: rows.map((u) => ({
          id: u.id, name: u.name, handle: u.handle, email: u.email,
          createdAt: iso(u.created_at), suspendedAt: iso(u.suspended_at),
          moments: u.moments, friends: u.friends, openReports: u.open_reports,
        })),
      };
    });

    adm.post('/users/:id/suspend', async (req, reply) => {
      const u = one('SELECT * FROM users WHERE id = ?', req.params.id);
      if (!u) return reply.code(404).send({ error: 'not_found' });
      const suspend = req.body?.suspended !== false;
      // Suspending also signs the person out everywhere.
      run('UPDATE users SET suspended_at = ?, token_version = token_version + ? WHERE id = ?',
        suspend ? Date.now() : null, suspend ? 1 : 0, u.id);
      log(req, suspend ? 'suspend' : 'unsuspend', `@${u.handle}`);
      return { ok: true };
    });

    adm.post('/users/:id/signout', async (req, reply) => {
      const u = one('SELECT * FROM users WHERE id = ?', req.params.id);
      if (!u) return reply.code(404).send({ error: 'not_found' });
      run('UPDATE users SET token_version = token_version + 1 WHERE id = ?', u.id);
      log(req, 'signout', `@${u.handle}`);
      return { ok: true };
    });

    adm.delete('/users/:id', async (req, reply) => {
      const u = one('SELECT * FROM users WHERE id = ?', req.params.id);
      if (!u) return reply.code(404).send({ error: 'not_found' });
      if (req.body?.confirmHandle !== u.handle) return reply.code(400).send({ error: 'confirm_handle' });
      await deleteUserCompletely(u.id, { log: req.log });
      log(req, 'delete', `@${u.handle}`);
      return { ok: true };
    });

    adm.get('/reports', async (req) => {
      const status = ['open', 'resolved', 'dismissed'].includes(req.query.status) ? req.query.status : null;
      return all(
        `SELECT r.*, rep.name AS reporter_name, rep.handle AS reporter_handle,
                t.name AS target_name, t.handle AS target_handle, t.suspended_at AS target_suspended,
                (SELECT count(*) FROM reports r2 WHERE r2.target_id = r.target_id) AS target_report_count
           FROM reports r
           LEFT JOIN users rep ON rep.id = r.reporter_id
           LEFT JOIN users t ON t.id = r.target_id
          ${status ? 'WHERE r.status = ?' : ''}
          ORDER BY r.created_at DESC LIMIT 200`,
        ...(status ? [status] : []),
      ).map((r) => ({
        id: r.id, status: r.status, reason: r.reason, createdAt: iso(r.created_at), resolvedAt: iso(r.resolved_at),
        reporter: r.reporter_handle ? { name: r.reporter_name, handle: r.reporter_handle } : null,
        target: r.target_handle
          ? { id: r.target_id, name: r.target_name, handle: r.target_handle, suspended: !!r.target_suspended }
          : null,
        targetReportCount: r.target_report_count,
      }));
    });

    adm.post('/reports/:id', async (req, reply) => {
      const status = req.body?.status;
      if (!['open', 'resolved', 'dismissed'].includes(status)) return reply.code(400).send({ error: 'invalid_status' });
      const r = run('UPDATE reports SET status = ?, resolved_at = ? WHERE id = ?',
        status, status === 'open' ? null : Date.now(), req.params.id);
      if (!r.changes) return reply.code(404).send({ error: 'not_found' });
      log(req, `report_${status}`, req.params.id.slice(0, 8));
      return { ok: true };
    });
  }, { prefix: '/v1/admin' });
}
