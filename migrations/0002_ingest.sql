CREATE TABLE IF NOT EXISTS ingest_keys (
  token_hash TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  last_used INTEGER
);
CREATE INDEX IF NOT EXISTS ingest_user ON ingest_keys(user_id);
