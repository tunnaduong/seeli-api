import { config, bindings, background } from './config.js';

const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (ch) => (
  { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[ch]
));

const METHOD_LABEL = { email: 'Email + mật khẩu', apple: 'Sign in with Apple', google: 'Sign in with Google' };
const PLATFORM_LABEL = { ios: 'iPhone / iPad (iOS)', android: 'Android', web: 'Trình duyệt web', unknown: 'Không rõ' };

/**
 * Which client made the request: an explicit `X-Client-Platform` header (ios|android|web)
 * wins; otherwise guess from User-Agent (URLSession sends "Darwin", OkHttp sends "okhttp").
 */
export function clientPlatform(req) {
  const hinted = (req.header('x-client-platform') || '').trim().toLowerCase();
  if (hinted in PLATFORM_LABEL) return hinted;
  const ua = req.header('user-agent') || '';
  if (/okhttp|android/i.test(ua)) return 'android';
  if (/cfnetwork|darwin/i.test(ua)) return 'ios';
  if (/mozilla/i.test(ua)) return 'web';
  return 'unknown';
}

/**
 * Emails the owner (NEW_USER_NOTIFY_EMAIL) when a new account is created.
 * Runs after the response is sent, and never throws into the request.
 * Needs the `send_email` binding "EMAIL" and an onboarded sending domain.
 */
export function notifyNewUser(user, method, platform = 'unknown') {
  if (!config.newUserNotifyTo || !bindings.EMAIL) return Promise.resolve();
  const when = new Date().toISOString();
  const via = METHOD_LABEL[method] || method;
  const subject = `[SEELI] Người dùng mới: ${user.name} (@${user.handle})`;

  const rows = [
    ['Tên', user.name],
    ['Handle', `@${user.handle}`],
    ['Email', user.email],
    ['Cách đăng ký', via],
    ['Thiết bị', PLATFORM_LABEL[platform] || PLATFORM_LABEL.unknown],
    ['Thời gian (UTC)', when],
  ];
  const text = `Có người dùng mới đăng ký SEELI.\n\n${rows.map(([k, v]) => `${k}: ${v}`).join('\n')}\n`;
  const html = `<p>Có người dùng mới đăng ký SEELI.</p><table cellpadding="6" style="border-collapse:collapse">${
    rows.map(([k, v]) => `<tr><td style="border:1px solid #ddd"><b>${esc(k)}</b></td><td style="border:1px solid #ddd">${esc(v)}</td></tr>`).join('')
  }</table>`;

  return background(
    bindings.EMAIL.send({
      from: { email: config.notifyFrom, name: 'SEELI' },
      to: config.newUserNotifyTo,
      subject,
      text,
      html,
    }),
  );
}
