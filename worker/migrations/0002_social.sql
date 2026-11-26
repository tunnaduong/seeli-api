-- 2026-11-27: shared comment threads, close friends, per-post recipients, friend requests.
PRAGMA defer_foreign_keys = true;

-- Comments: many per person, replies (parent_id), and who may see each one.
--   visibility 'owner'  → only the photo's owner (and the author) see it.
--   visibility 'circle' → everyone who can see the post, once the owner approves (status).
CREATE TABLE comments_new (
  id TEXT PRIMARY KEY,
  moment_id TEXT NOT NULL REFERENCES moments(id) ON DELETE CASCADE,
  author_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  parent_id TEXT,
  text TEXT NOT NULL,
  visibility TEXT NOT NULL DEFAULT 'owner',
  status TEXT NOT NULL DEFAULT 'approved',
  created_at INTEGER NOT NULL,
  edited_at INTEGER
);

-- Old perspectives become private top-level comments…
INSERT INTO comments_new (id, moment_id, author_id, parent_id, text, visibility, status, created_at)
  SELECT id, moment_id, author_id, NULL, text, 'owner', 'approved', created_at FROM comments;

-- …and the owner's single reply becomes a private reply under it.
INSERT INTO comments_new (id, moment_id, author_id, parent_id, text, visibility, status, created_at)
  SELECT c.id || 'r', c.moment_id, m.user_id, c.id, c.reply, 'owner', 'approved', COALESCE(c.replied_at, c.created_at)
    FROM comments c JOIN moments m ON m.id = c.moment_id
   WHERE c.reply IS NOT NULL AND c.reply <> '';

DROP TABLE comments;
ALTER TABLE comments_new RENAME TO comments;
CREATE INDEX IF NOT EXISTS comments_moment ON comments(moment_id, created_at);
CREATE INDEX IF NOT EXISTS comments_author ON comments(author_id, created_at);
CREATE INDEX IF NOT EXISTS comments_parent ON comments(parent_id);

-- Close friends: set on the owner's own row (user_id = owner, friend_id = the friend).
ALTER TABLE friendships ADD COLUMN close INTEGER NOT NULL DEFAULT 0;

-- audience 'selected': exactly these friends.
CREATE TABLE IF NOT EXISTS moment_recipients (
  moment_id TEXT NOT NULL REFERENCES moments(id) ON DELETE CASCADE,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  PRIMARY KEY (moment_id, user_id)
);
CREATE INDEX IF NOT EXISTS moment_recipients_user ON moment_recipients(user_id);

-- Scanning a code sends a request; the other person accepts it.
CREATE TABLE IF NOT EXISTS friend_requests (
  from_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  to_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  created_at INTEGER NOT NULL,
  PRIMARY KEY (from_id, to_id)
);
CREATE INDEX IF NOT EXISTS friend_requests_to ON friend_requests(to_id, created_at);
