import { config } from './config.js';
import { photoSignature } from './auth.js';

export const iso = (ms) => (ms == null ? null : new Date(ms).toISOString().replace(/\.\d{3}Z$/, 'Z'));

export const publicUser = (u) => ({ id: u.id, name: u.name, handle: u.handle });

export const me = (u, providers = []) => ({
  ...publicUser(u),
  hasPassword: !!u.password_hash,
  providers,
  email: u.email,
  bio: u.bio,
  inviteCode: u.invite_code,
  createdAt: iso(u.created_at),
});

/** A photo URL exists only once the reveal date has passed. */
export function photoUrl(m, baseUrl) {
  if (m.reveal_at > Date.now()) return null;
  const exp = Math.floor(Date.now() / 1000) + config.photoUrlTtlSec;
  return `${baseUrl}/v1/photos/${m.id}?exp=${exp}&sig=${photoSignature(m.id, exp)}`;
}

export const myMoment = (m, baseUrl) => ({
  id: m.id,
  note: m.note,
  placeName: m.place_name,
  audience: m.audience,
  createdAt: iso(m.created_at),
  revealAt: iso(m.reveal_at),
  reunitedAt: iso(m.reunited_at),
  reflection: m.reflection,
  commentCount: m.comment_count ?? 0,
  photoUrl: photoUrl(m, baseUrl),
});

/**
 * What a friend sees: never the place, and never a photo URL in the feed.
 * The photo is fetched through POST /moments/:id/view, which works only once.
 */
export const feedMoment = (m) => ({
  id: m.id,
  author: { id: m.user_id, name: m.author_name, handle: m.author_handle },
  note: m.note,
  createdAt: iso(m.created_at),
  revealed: m.reveal_at <= Date.now(),
  photoUrl: null,
  viewedAt: iso(m.viewed_at),
  myComment: m.my_comment ?? null,
  scene: parseInt(m.id.slice(0, 6), 16) % 3,
});
