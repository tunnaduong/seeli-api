import { readFileSync } from 'node:fs';
import { createPrivateKey, sign } from 'node:crypto';
import { config } from './config.js';

/**
 * Firebase Cloud Messaging (HTTP v1) for the Android app.
 * Needs a Firebase service-account JSON (Project settings → Service accounts → Generate new private key).
 */
let account = null;
function serviceAccount() {
  if (account) return account;
  if (!config.fcmServiceAccountPath) return null;
  try {
    account = JSON.parse(readFileSync(config.fcmServiceAccountPath, 'utf8'));
  } catch {
    return null;
  }
  return account;
}

export const fcmConfigured = () => !!serviceAccount()?.private_key;

let cached = { token: '', exp: 0 };
/** OAuth access token from a self-signed RS256 JWT, reused until 5 minutes before it expires. */
async function accessToken() {
  if (cached.token && Date.now() < cached.exp - 5 * 60_000) return cached.token;
  const sa = serviceAccount();
  const now = Math.floor(Date.now() / 1000);
  const b = (o) => Buffer.from(JSON.stringify(o)).toString('base64url');
  const head = b({ alg: 'RS256', typ: 'JWT', kid: sa.private_key_id });
  const body = b({
    iss: sa.client_email, scope: 'https://www.googleapis.com/auth/firebase.messaging',
    aud: sa.token_uri || 'https://oauth2.googleapis.com/token', iat: now, exp: now + 3600,
  });
  const sig = sign('RSA-SHA256', Buffer.from(`${head}.${body}`), createPrivateKey(sa.private_key)).toString('base64url');
  const res = await tokenFetcher(sa.token_uri || 'https://oauth2.googleapis.com/token', `${head}.${body}.${sig}`);
  cached = { token: res.access_token, exp: Date.now() + (res.expires_in || 3600) * 1000 };
  return cached.token;
}

async function fetchToken(uri, assertion) {
  const r = await fetch(uri, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer', assertion }),
  });
  if (!r.ok) throw new Error(`fcm oauth ${r.status}`);
  return r.json();
}

async function sendHttp(projectId, bearer, message) {
  const r = await fetch(`https://fcm.googleapis.com/v1/projects/${projectId}/messages:send`, {
    method: 'POST',
    headers: { authorization: `Bearer ${bearer}`, 'content-type': 'application/json' },
    body: JSON.stringify({ message }),
    signal: AbortSignal.timeout(10_000),
  });
  return { status: r.status, body: await r.text() };
}

/** Test hooks. */
let tokenFetcher = fetchToken;
let sender = sendHttp;
export const _setFcmForTest = ({ fetchToken: f, send: s }) => {
  if (f) tokenFetcher = f;
  if (s) sender = s;
  cached = { token: '', exp: 0 };
};

/**
 * Sends a data message (the app builds the notification itself, so taps deep-link correctly
 * and the text stays in the user's language). Returns 'sent' | 'dead' | 'failed'.
 */
export async function sendFcm(token, { title, body }, data, log) {
  const strings = Object.fromEntries(
    Object.entries({ ...data, title, body }).filter(([, v]) => v != null).map(([k, v]) => [k, String(v)]),
  );
  const res = await sender(serviceAccount().project_id, await accessToken(), {
    token, data: strings, android: { priority: 'high' },
  });
  if (res.status === 200) return 'sent';
  if (res.status === 404 || /UNREGISTERED|not a valid FCM registration token/.test(res.body || '')) return 'dead';
  log?.warn({ status: res.status, body: res.body }, 'fcm push failed');
  return 'failed';
}
