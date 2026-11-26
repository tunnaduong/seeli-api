-- SEELI D1 schema: the current state after every file in migrations/.
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
  close INTEGER NOT NULL DEFAULT 0,
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
  parent_id TEXT,
  text TEXT NOT NULL,
  visibility TEXT NOT NULL DEFAULT 'owner',  -- 'owner' | 'circle'
  status TEXT NOT NULL DEFAULT 'approved',   -- 'pending' | 'approved' | 'rejected' (for 'circle')
  created_at INTEGER NOT NULL,
  edited_at INTEGER
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
CREATE INDEX IF NOT EXISTS comments_moment ON comments(moment_id, created_at);
CREATE INDEX IF NOT EXISTS comments_author ON comments(author_id, created_at);
CREATE INDEX IF NOT EXISTS comments_parent ON comments(parent_id);
CREATE TABLE IF NOT EXISTS moment_recipients (
  moment_id TEXT NOT NULL REFERENCES moments(id) ON DELETE CASCADE,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  PRIMARY KEY (moment_id, user_id)
);
CREATE INDEX IF NOT EXISTS moment_recipients_user ON moment_recipients(user_id);
CREATE TABLE IF NOT EXISTS friend_requests (
  from_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  to_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  created_at INTEGER NOT NULL,
  PRIMARY KEY (from_id, to_id)
);
CREATE INDEX IF NOT EXISTS friend_requests_to ON friend_requests(to_id, created_at);
