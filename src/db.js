import { DatabaseSync } from 'node:sqlite';
import { config } from './config.js';

export const db = new DatabaseSync(config.dbPath);
db.exec(`
PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;
PRAGMA busy_timeout = 5000;

CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  handle TEXT NOT NULL UNIQUE,
  email TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  bio TEXT NOT NULL DEFAULT '',
  invite_code TEXT NOT NULL UNIQUE,
  token_version INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS friendships (
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  friend_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  memo TEXT NOT NULL DEFAULT '',
  created_at INTEGER NOT NULL,
  PRIMARY KEY (user_id, friend_id)
);

CREATE TABLE IF NOT EXISTS blocks (
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  blocked_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  created_at INTEGER NOT NULL,
  PRIMARY KEY (user_id, blocked_id)
);

CREATE TABLE IF NOT EXISTS reports (
  id TEXT PRIMARY KEY,
  reporter_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  target_id TEXT NOT NULL,
  reason TEXT NOT NULL DEFAULT '',
  created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS moments (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  note TEXT NOT NULL DEFAULT '',
  place_name TEXT,
  audience TEXT NOT NULL DEFAULT 'onlyMe',
  photo_path TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  reveal_at INTEGER NOT NULL,
  reunited_at INTEGER,
  reflection TEXT
);
CREATE INDEX IF NOT EXISTS moments_user ON moments(user_id, created_at DESC);

CREATE TABLE IF NOT EXISTS comments (
  id TEXT PRIMARY KEY,
  moment_id TEXT NOT NULL REFERENCES moments(id) ON DELETE CASCADE,
  author_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  text TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  UNIQUE (moment_id, author_id)
);
`);

// ---- Migrations (idempotent) ----
const hasColumn = (table, col) => db.prepare(`PRAGMA table_info(${table})`).all().some((c) => c.name === col);
if (!hasColumn('users', 'suspended_at')) db.exec('ALTER TABLE users ADD COLUMN suspended_at INTEGER');
if (!hasColumn('reports', 'status')) db.exec("ALTER TABLE reports ADD COLUMN status TEXT NOT NULL DEFAULT 'open'");
if (!hasColumn('comments', 'reply')) db.exec('ALTER TABLE comments ADD COLUMN reply TEXT');
if (!hasColumn('comments', 'replied_at')) db.exec('ALTER TABLE comments ADD COLUMN replied_at INTEGER');
// Blocking ends a friendship; these remember it so unblocking can bring it back.
if (!hasColumn('blocks', 'friend_since')) db.exec('ALTER TABLE blocks ADD COLUMN friend_since INTEGER');
if (!hasColumn('blocks', 'memo')) db.exec('ALTER TABLE blocks ADD COLUMN memo TEXT');
if (!hasColumn('blocks', 'their_memo')) db.exec('ALTER TABLE blocks ADD COLUMN their_memo TEXT');
// Who scanned whose code, so only the other person is told "X added you".
if (!hasColumn('friendships', 'added_by')) db.exec('ALTER TABLE friendships ADD COLUMN added_by TEXT');
if (!hasColumn('reports', 'resolved_at')) db.exec('ALTER TABLE reports ADD COLUMN resolved_at INTEGER');
db.exec(`
CREATE TABLE IF NOT EXISTS identities (
  provider TEXT NOT NULL,
  subject TEXT NOT NULL,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  email TEXT,
  created_at INTEGER NOT NULL,
  PRIMARY KEY (provider, subject)
);
CREATE INDEX IF NOT EXISTS identities_user ON identities(user_id);
CREATE TABLE IF NOT EXISTS admin_log (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  action TEXT NOT NULL,
  target TEXT,
  detail TEXT,
  ip TEXT,
  created_at INTEGER NOT NULL
);
`);

if (!hasColumn('identities', 'refresh_token')) db.exec('ALTER TABLE identities ADD COLUMN refresh_token TEXT');

// Push notification targets. env = which APNs gateway issued the token.
db.exec(`
CREATE TABLE IF NOT EXISTS device_tokens (
  token TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  env TEXT NOT NULL DEFAULT 'production',
  lang TEXT NOT NULL DEFAULT 'vi',
  updated_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS device_tokens_user ON device_tokens(user_id);
`);

// 'ios' (APNs) or 'android' (FCM).
if (!hasColumn('device_tokens', 'platform')) db.exec("ALTER TABLE device_tokens ADD COLUMN platform TEXT NOT NULL DEFAULT 'ios'");

// A friend may open someone else's photo exactly once.
db.exec(`
CREATE TABLE IF NOT EXISTS photo_views (
  moment_id TEXT NOT NULL REFERENCES moments(id) ON DELETE CASCADE,
  viewer_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  opened_at INTEGER NOT NULL,
  PRIMARY KEY (moment_id, viewer_id)
);
`);

export const one = (sql, ...p) => db.prepare(sql).get(...p);
export const all = (sql, ...p) => db.prepare(sql).all(...p);
export const run = (sql, ...p) => db.prepare(sql).run(...p);

export function tx(fn) {
  db.exec('BEGIN');
  try {
    const r = fn();
    db.exec('COMMIT');
    return r;
  } catch (e) {
    db.exec('ROLLBACK');
    throw e;
  }
}
