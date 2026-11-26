import { readFileSync } from 'node:fs';
import { createPrivateKey, sign } from 'node:crypto';
import http2 from 'node:http2';
import { config } from './config.js';
import { all, run } from './db.js';
import { fcmConfigured, sendFcm } from './fcm.js';

const HOSTS = { production: 'https://api.push.apple.com', sandbox: 'https://api.sandbox.push.apple.com' };
const teamId = () => process.env.APNS_TEAM_ID || config.appleTeamId;

export const apnsConfigured = () => !!(config.apnsKeyId && config.apnsKeyPath && teamId());

let cached = { jwt: '', at: 0 };
let key = null;
/** Provider token: ES256 JWT, reused for 50 minutes (Apple allows up to 60). */
function providerToken() {
  if (cached.jwt && Date.now() - cached.at < 50 * 60_000) return cached.jwt;
  key ??= createPrivateKey(readFileSync(config.apnsKeyPath));
  const b = (o) => Buffer.from(JSON.stringify(o)).toString('base64url');
  const head = b({ alg: 'ES256', kid: config.apnsKeyId });
  const body = b({ iss: teamId(), iat: Math.floor(Date.now() / 1000) });
  const sig = sign('sha256', Buffer.from(`${head}.${body}`), { key, dsaEncoding: 'ieee-p1363' }).toString('base64url');
  cached = { jwt: `${head}.${body}.${sig}`, at: Date.now() };
  return cached.jwt;
}

/** Test hook: replace the HTTP/2 sender. */
let sender = sendHttp2;
export const _setSenderForTest = (fn) => { sender = fn; };

function sendHttp2(env, token, headers, payload) {
  return new Promise((resolve) => {
    const client = http2.connect(HOSTS[env] || HOSTS.production);
    client.on('error', () => resolve({ status: 0 }));
    const req = client.request({ ':method': 'POST', ':path': `/3/device/${token}`, ...headers });
    let data = '';
    req.setEncoding('utf8');
    req.on('response', (h) => { req.status = h[':status']; });
    req.on('data', (c) => { data += c; });
    req.on('end', () => { client.close(); resolve({ status: req.status, body: data }); });
    req.on('error', () => { client.close(); resolve({ status: 0 }); });
    req.setTimeout(10_000, () => req.close());
    req.end(JSON.stringify(payload));
  });
}

/** One APNs request with our provider token. Used by the push relay for the Cloudflare Worker. */
export function sendApns(env, token, payload) {
  return sender(env, token, {
    authorization: `bearer ${providerToken()}`,
    'apns-topic': config.apnsTopic,
    'apns-push-type': 'alert',
    'apns-priority': '10',
  }, payload);
}

/**
 * Sends one alert to every device of the given users: APNs for iPhones, FCM for Android.
 * `message(lang)` returns { title, body }. Tokens reported as dead are removed. Never throws.
 */
export async function pushToUsers(userIds, message, data = {}, log = null) {
  const ios = apnsConfigured(), android = fcmConfigured();
  if ((!ios && !android) || userIds.length === 0) return 0;
  const rows = all(
    `SELECT token, env, lang, platform FROM device_tokens WHERE user_id IN (${userIds.map(() => '?').join(',')})`,
    ...userIds,
  );
  let sent = 0;
  await Promise.all(rows.map(async (r) => {
    try {
      if (r.platform === 'android') {
        if (!android) return;
        const result = await sendFcm(r.token, message(r.lang), data, log);
        if (result === 'sent') sent++;
        else if (result === 'dead') run('DELETE FROM device_tokens WHERE token = ?', r.token);
        return;
      }
      if (!ios) return;
      const { title, body } = message(r.lang);
      const res = await sender(r.env, r.token, {
        authorization: `bearer ${providerToken()}`,
        'apns-topic': config.apnsTopic,
        'apns-push-type': 'alert',
        'apns-priority': '10',
      }, { aps: { alert: { title, body }, sound: 'default' }, ...data });
      if (res.status === 200) sent++;
      else if (res.status === 410 || /BadDeviceToken|Unregistered|DeviceTokenNotForTopic/.test(res.body || '')) {
        run('DELETE FROM device_tokens WHERE token = ?', r.token);
      } else log?.warn({ status: res.status, body: res.body }, 'apns push failed');
    } catch (e) {
      log?.warn({ err: e.message }, 'apns push error');
    }
  }));
  return sent;
}
