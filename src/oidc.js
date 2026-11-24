import { createPublicKey, verify } from 'node:crypto';
import { config } from './config.js';

/**
 * Verifies ID tokens (JWT, RS256) from Sign in with Apple and Google Sign-In
 * against the providers' published public keys. No third-party libraries.
 */
const PROVIDERS = {
  apple: {
    jwks: 'https://appleid.apple.com/auth/keys',
    issuers: ['https://appleid.apple.com'],
    audiences: () => config.appleAudiences,
  },
  google: {
    jwks: 'https://www.googleapis.com/oauth2/v3/certs',
    issuers: ['https://accounts.google.com', 'accounts.google.com'],
    audiences: () => config.googleClientIds,
  },
};

const keyCache = new Map(); // provider -> { at, keys: Map(kid -> KeyObject) }

async function keysFor(provider, { refresh = false } = {}) {
  const cached = keyCache.get(provider);
  if (!refresh && cached && Date.now() - cached.at < 6 * 3600_000) return cached.keys;
  const res = await fetch(PROVIDERS[provider].jwks, { signal: AbortSignal.timeout(8000) });
  if (!res.ok) throw new Error(`jwks_${res.status}`);
  const { keys } = await res.json();
  const map = new Map(keys.map((jwk) => [jwk.kid, createPublicKey({ key: jwk, format: 'jwk' })]));
  keyCache.set(provider, { at: Date.now(), keys: map });
  return map;
}

const decode = (part) => JSON.parse(Buffer.from(part, 'base64url').toString());

export class TokenError extends Error {}

/** Returns the verified claims, or throws TokenError. */
export async function verifyIdToken(provider, token, { nonce } = {}) {
  const p = PROVIDERS[provider];
  if (!p) throw new TokenError('unknown_provider');
  const audiences = p.audiences();
  if (!audiences.length) throw new TokenError('provider_not_configured');

  const parts = String(token || '').split('.');
  if (parts.length !== 3) throw new TokenError('invalid_token');
  let header, claims;
  try {
    header = decode(parts[0]);
    claims = decode(parts[1]);
  } catch {
    throw new TokenError('invalid_token');
  }
  if (header.alg !== 'RS256' || !header.kid) throw new TokenError('invalid_token');

  let key = (await keysFor(provider)).get(header.kid);
  if (!key) key = (await keysFor(provider, { refresh: true })).get(header.kid); // keys rotated
  if (!key) throw new TokenError('invalid_token');

  const ok = verify('RSA-SHA256', Buffer.from(`${parts[0]}.${parts[1]}`), key, Buffer.from(parts[2], 'base64url'));
  if (!ok) throw new TokenError('invalid_token');

  const now = Math.floor(Date.now() / 1000);
  if (!p.issuers.includes(claims.iss)) throw new TokenError('invalid_token');
  const aud = Array.isArray(claims.aud) ? claims.aud : [claims.aud];
  if (!aud.some((a) => audiences.includes(a))) throw new TokenError('invalid_audience');
  if (typeof claims.exp !== 'number' || claims.exp < now - 60) throw new TokenError('token_expired');
  if (typeof claims.iat === 'number' && claims.iat > now + 300) throw new TokenError('invalid_token');
  if (nonce !== undefined && claims.nonce !== nonce) throw new TokenError('invalid_nonce');
  if (!claims.sub) throw new TokenError('invalid_token');

  const emailVerified = claims.email_verified === true || claims.email_verified === 'true';
  return { sub: String(claims.sub), email: claims.email ? String(claims.email).toLowerCase() : null, emailVerified, name: claims.name || null };
}

/** Test hook: inject keys without network. */
export function _setKeysForTest(provider, keys) {
  keyCache.set(provider, { at: Date.now(), keys });
}
