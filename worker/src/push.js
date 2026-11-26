import { config } from './config.js';
import { all, run } from './db.js';
import { fcmConfigured, sendFcm } from './fcm.js';

/** iPhone pushes go to the APNs relay on the Pi (Workers cannot speak HTTP/2 to APNs). */
const relayConfigured = () => !!(config.pushRelayUrl && config.pushRelaySecret);

async function sendApns(env, token, payload) {
  const r = await fetch(`${config.pushRelayUrl}/apns`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', 'x-relay-secret': config.pushRelaySecret },
    body: JSON.stringify({ env, token, payload }),
    signal: AbortSignal.timeout(15_000),
  });
  if (!r.ok) return { status: 0, body: `relay ${r.status}` };
  return r.json();
}

/**
 * Sends one alert to every device of the given users: APNs (via relay) for iPhones, FCM for Android.
 * `message(lang)` returns { title, body }. Tokens reported as dead are removed. Never throws.
 */
export async function pushToUsers(userIds, message, data = {}) {
  const ios = relayConfigured(), android = fcmConfigured();
  if ((!ios && !android) || userIds.length === 0) return 0;
  const rows = await all(
    `SELECT token, env, lang, platform FROM device_tokens WHERE user_id IN (${userIds.map(() => '?').join(',')})`,
    ...userIds,
  );
  const log = { warn: (o, msg) => console.warn(msg, JSON.stringify(o)) };
  let sent = 0;
  await Promise.all(rows.map(async (r) => {
    try {
      if (r.platform === 'android') {
        if (!android) return;
        const result = await sendFcm(r.token, message(r.lang), data, log);
        if (result === 'sent') sent++;
        else if (result === 'dead') await run('DELETE FROM device_tokens WHERE token = ?', r.token);
        return;
      }
      if (!ios) return;
      const { title, body } = message(r.lang);
      const res = await sendApns(r.env, r.token, { aps: { alert: { title, body }, sound: 'default' }, ...data });
      if (res.status === 200) sent++;
      else if (res.status === 410 || /BadDeviceToken|Unregistered|DeviceTokenNotForTopic/.test(res.body || '')) {
        await run('DELETE FROM device_tokens WHERE token = ?', r.token);
      } else log.warn({ status: res.status, body: res.body }, 'apns push failed');
    } catch (e) {
      log.warn({ err: e.message }, 'push error');
    }
  }));
  return sent;
}
