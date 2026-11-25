import { createHmac, randomBytes, scryptSync, timingSafeEqual, randomUUID } from 'node:crypto';
import { config } from './config.js';
import { one } from './db.js';

const b64 = (buf) => Buffer.from(buf).toString('base64url');

export function hashPassword(password) {
  const salt = randomBytes(16);
  const hash = scryptSync(password, salt, 64);
  return `scrypt$${b64(salt)}$${b64(hash)}`;
}

export function verifyPassword(password, stored) {
  if (!stored) return false; // social-only account: no password set
  const [, saltB64, hashB64] = String(stored).split('$');
  if (!saltB64 || !hashB64) return false;
  const expected = Buffer.from(hashB64, 'base64url');
  const actual = scryptSync(password, Buffer.from(saltB64, 'base64url'), expected.length);
  return timingSafeEqual(expected, actual);
}

const sign = (data) => createHmac('sha256', config.secret).update(data).digest('base64url');

const safeEqual = (a, b) => a.length === b.length && timingSafeEqual(Buffer.from(a), Buffer.from(b));

/** Token = base64url(json).signature. No expiry; revoked by bumping users.token_version. */
export function issueToken(user) {
  const payload = b64(JSON.stringify({ sub: user.id, v: user.token_version }));
  return `${payload}.${sign(payload)}`;
}

export function readToken(token) {
  const [payload, sig] = String(token || '').split('.');
  if (!payload || !sig || !safeEqual(sign(payload), sig)) return null;
  try {
    const { sub, v } = JSON.parse(Buffer.from(payload, 'base64url').toString());
    const user = one('SELECT * FROM users WHERE id = ?', sub);
    return user && user.token_version === v && !user.suspended_at ? user : null;
  } catch {
    return null;
  }
}

/** Fastify preHandler: requires `Authorization: Bearer <token>`. */
export async function requireUser(req, reply) {
  const header = req.headers.authorization || '';
  const user = readToken(header.startsWith('Bearer ') ? header.slice(7) : '');
  if (!user) return reply.code(401).send({ error: 'unauthorized' });
  req.user = user;
}

// ---- Admin session (separate scope, short-lived, invalidated when the password changes) ----

const adminKey = () => createHmac('sha256', config.secret).update(`admin-pw:${config.adminPassword}`).digest('base64url').slice(0, 16);

export function issueAdminToken() {
  const payload = b64(JSON.stringify({ scope: 'admin', exp: Date.now() + config.adminSessionHours * 3_600_000, k: adminKey() }));
  return `${payload}.${sign(`admin:${payload}`)}`;
}

export function readAdminToken(token) {
  if (!config.adminPassword) return false;
  const [payload, sig] = String(token || '').split('.');
  if (!payload || !sig || !safeEqual(sign(`admin:${payload}`), sig)) return false;
  try {
    const { scope, exp, k } = JSON.parse(Buffer.from(payload, 'base64url').toString());
    return scope === 'admin' && exp > Date.now() && k === adminKey();
  } catch {
    return false;
  }
}

export function checkAdminPassword(input) {
  if (!config.adminPassword) return false;
  const digest = (s) => createHmac('sha256', 'seeli-admin').update(String(s)).digest();
  return timingSafeEqual(digest(input), digest(config.adminPassword));
}

/** Signed, short-lived photo URLs so the app can load them without auth headers. */
export const photoSignature = (momentId, exp) => sign(`photo:${momentId}:${exp}`);
export const checkPhotoSignature = (momentId, exp, sig) => safeEqual(photoSignature(momentId, exp), String(sig || ''));
/** One-time-view URLs use their own signature, so they cannot be turned into normal ones. */
export const oncePhotoSignature = (momentId, exp) => sign(`photo-once:${momentId}:${exp}`);
export const checkOncePhotoSignature = (momentId, exp, sig) => safeEqual(oncePhotoSignature(momentId, exp), String(sig || ''));

/** 8 chars without ambiguous letters — easy to read aloud when two people meet. */
export function newInviteCode() {
  const alphabet = 'ABCDEFGHJKMNPQRSTUVWXYZ23456789';
  return Array.from(randomBytes(8), (b) => alphabet[b % alphabet.length]).join('');
}

export const newId = () => randomUUID();
