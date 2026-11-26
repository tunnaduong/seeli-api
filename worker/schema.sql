-- SEELI D1 schema (same as the old SQLite database after all migrations).
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
, suspended_at INTEGER);
CREATE TABLE IF NOT EXISTS friendships (
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  friend_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  memo TEXT NOT NULL DEFAULT '',
  created_at INTEGER NOT NULL, added_by TEXT,
  PRIMARY KEY (user_id, friend_id)
);
CREATE TABLE IF NOT EXISTS blocks (
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  blocked_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  created_at INTEGER NOT NULL, friend_since INTEGER, memo TEXT, their_memo TEXT,
  PRIMARY KEY (user_id, blocked_id)
);
CREATE TABLE IF NOT EXISTS reports (
  id TEXT PRIMARY KEY,
  reporter_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  target_id TEXT NOT NULL,
  reason TEXT NOT NULL DEFAULT '',
  created_at INTEGER NOT NULL
, status TEXT NOT NULL DEFAULT 'open', resolved_at INTEGER);
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
CREATE TABLE IF NOT EXISTS comments (
  id TEXT PRIMARY KEY,
  moment_id TEXT NOT NULL REFERENCES moments(id) ON DELETE CASCADE,
  author_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  text TEXT NOT NULL,
  created_at INTEGER NOT NULL, reply TEXT, replied_at INTEGER,
  UNIQUE (moment_id, author_id)
);
CREATE TABLE IF NOT EXISTS admin_log (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  action TEXT NOT NULL,
  target TEXT,
  detail TEXT,
  ip TEXT,
  created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS identities (
  provider TEXT NOT NULL,
  subject TEXT NOT NULL,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  email TEXT,
  created_at INTEGER NOT NULL, refresh_token TEXT,
  PRIMARY KEY (provider, subject)
);
CREATE TABLE IF NOT EXISTS photo_views (
  moment_id TEXT NOT NULL REFERENCES moments(id) ON DELETE CASCADE,
  viewer_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  opened_at INTEGER NOT NULL,
  PRIMARY KEY (moment_id, viewer_id)
);
CREATE TABLE IF NOT EXISTS device_tokens (
  token TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  env TEXT NOT NULL DEFAULT 'production',
  lang TEXT NOT NULL DEFAULT 'vi',
  updated_at INTEGER NOT NULL
, platform TEXT NOT NULL DEFAULT 'ios');
CREATE INDEX IF NOT EXISTS moments_user ON moments(user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS identities_user ON identities(user_id);
CREATE INDEX IF NOT EXISTS device_tokens_user ON device_tokens(user_id);
