import { createPrivateKey, sign } from 'node:crypto';
import { readFileSync, existsSync } from 'node:fs';
import { config } from './config.js';

/**
 * Sign in with Apple server-to-server calls:
 *  - exchange the authorization code from the app for a refresh token (kept so we can revoke later)
 *  - revoke that token when the account is deleted (App Store Review Guideline 5.1.1(v)).
 * Needs a "Sign in with Apple" key (.p8) from developer.apple.com.
 */
const APPLE = 'https://appleid.apple.com';

export const appleConfigured = () =>
  !!(config.appleTeamId && config.appleKeyId && config.appleKeyPath && existsSync(config.appleKeyPath));

let cachedKey = null;
function privateKey() {
  if (!cachedKey) cachedKey = createPrivateKey(readFileSync(config.appleKeyPath, 'utf8'));
  return cachedKey;
}

const b64 = (o) => Buffer.from(JSON.stringify(o)).toString('base64url');

/** client_secret = ES256 JWT signed with the .p8 key, valid for 5 minutes. */
export function clientSecret(clientId = config.appleAudiences[0]) {
  const now = Math.floor(Date.now() / 1000);
  const head = b64({ alg: 'ES256', kid: config.appleKeyId });
  const body = b64({ iss: config.appleTeamId, iat: now, exp: now + 300, aud: APPLE, sub: clientId });
  // JOSE wants the raw r||s signature, not DER.
  const sig = sign('sha256', Buffer.from(`${head}.${body}`), { key: privateKey(), dsaEncoding: 'ieee-p1363' });
  return `${head}.${body}.${sig.toString('base64url')}`;
}

async function post(path, params) {
  const res = await fetch(`${APPLE}${path}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams(params),
    signal: AbortSignal.timeout(10_000),
  });
  const text = await res.text();
  let json = {};
  try { json = text ? JSON.parse(text) : {}; } catch { /* revoke returns an empty body */ }
  return { ok: res.ok, status: res.status, json };
}

/** Authorization code (from the app) → refresh token, or null if unavailable. */
export async function exchangeCode(code) {
  if (!appleConfigured() || !code) return null;
  const clientId = config.appleAudiences[0];
  const r = await post('/auth/token', {
    client_id: clientId, client_secret: clientSecret(clientId), code, grant_type: 'authorization_code',
  });
  return r.ok ? r.json.refresh_token || null : null;
}

/** Revokes a refresh token. Returns true when Apple accepted it. */
export async function revokeToken(token, hint = 'refresh_token') {
  if (!appleConfigured() || !token) return false;
  const clientId = config.appleAudiences[0];
  const r = await post('/auth/revoke', {
    client_id: clientId, client_secret: clientSecret(clientId), token, token_type_hint: hint,
  });
  return r.ok;
}
