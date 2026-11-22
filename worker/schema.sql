
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS keys (
  id TEXT PRIMARY KEY,
  key_hash TEXT NOT NULL UNIQUE,

  provider TEXT NOT NULL
    CHECK (provider IN ('lootlabs', 'linkvertise')),

  status TEXT NOT NULL DEFAULT 'active'
    CHECK (
      status IN (
        'active',
        'redeemed',
        'revoked',
        'expired'
      )
    ),

  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  redeemed_at INTEGER
);

CREATE INDEX IF NOT EXISTS idx_keys_status
ON keys(status);

CREATE INDEX IF NOT EXISTS idx_keys_expires_at
ON keys(expires_at);

CREATE TABLE IF NOT EXISTS verification_sessions (
  id TEXT PRIMARY KEY,

  provider TEXT NOT NULL
    CHECK (provider IN ('lootlabs', 'linkvertise')),

  status TEXT NOT NULL DEFAULT 'pending'
    CHECK (
      status IN (
        'pending',
        'completed',
        'expired',
        'failed'
      )
    ),

  key_id TEXT REFERENCES keys(id),
  external_transaction_id TEXT UNIQUE,

  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  completed_at INTEGER
);

CREATE INDEX IF NOT EXISTS idx_sessions_status_expires
ON verification_sessions(status, expires_at);
