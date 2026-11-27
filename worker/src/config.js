/**
 * Settings come from Worker vars and secrets (wrangler.jsonc + `wrangler secret put`).
 * `config` is filled from `env` on each request; the same names as the old Node .env.
 */
export const config = {};
export const bindings = { DB: null, PHOTOS: null, EMAIL: null, ctx: null };

const list = (s, fallback = '') => String(s ?? fallback).split(',').map((x) => x.trim()).filter(Boolean);

export function loadEnv(env, ctx) {
  bindings.DB = env.DB;
  bindings.PHOTOS = env.PHOTOS;
  bindings.EMAIL = env.EMAIL;
  bindings.ctx = ctx;
  Object.assign(config, {
    secret: env.JWT_SECRET || 'dev-only-secret-change-me',
    revealMinDays: Number(env.REVEAL_MIN_DAYS || 27),
    revealMaxDays: Number(env.REVEAL_MAX_DAYS || 37),
    allowDemo: (env.ALLOW_DEMO ?? 'true') === 'true',
    maxPhotoBytes: Number(env.MAX_PHOTO_MB || 8) * 1024 * 1024,
    photoUrlTtlSec: 60 * 60,
    appleAudiences: list(env.APPLE_AUDIENCES, 'com.tunnaduong.seeli'),
    appleTeamId: env.APPLE_TEAM_ID || '',
    appleKeyId: env.APPLE_KEY_ID || '',
    // Sign in with Apple .p8 contents (secret).
    appleKey: env.APPLE_KEY || '',
    // Firebase service-account JSON contents (secret).
    fcmServiceAccount: env.FCM_SERVICE_ACCOUNT || '',
    // iPhone pushes go through a small relay (APNs needs HTTP/2, which Workers cannot open).
    pushRelayUrl: (env.PUSH_RELAY_URL || '').replace(/\/$/, ''),
    pushRelaySecret: env.PUSH_RELAY_SECRET || '',
    googleClientIds: list(env.GOOGLE_CLIENT_IDS),
    authRateLimit: Number(env.AUTH_RATE_LIMIT || 10),
    adminPassword: env.ADMIN_PASSWORD || '',
    adminSessionHours: 12,
    publicUrl: (env.PUBLIC_URL || '').replace(/\/$/, ''),
    // Email alert to the owner when someone creates an account (empty = off).
    newUserNotifyTo: (env.NEW_USER_NOTIFY_EMAIL || '').trim(),
    // Sender for that alert; the domain must be onboarded in Cloudflare Email Sending.
    notifyFrom: (env.NOTIFY_FROM_EMAIL || 'noreply@seeli.cam').trim(),
  });
}

/** Runs work after the response is sent (pushes, cleanup). */
export const background = (promise) => {
  const p = Promise.resolve(promise).catch((e) => console.warn('background', e?.message || e));
  if (bindings.ctx) bindings.ctx.waitUntil(p);
  return p;
};
