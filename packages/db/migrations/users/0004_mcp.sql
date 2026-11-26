CREATE TABLE watch_packages (
  user_id TEXT NOT NULL, ecosystem TEXT NOT NULL, name TEXT NOT NULL,
  created_at TEXT NOT NULL, alerts_on INTEGER NOT NULL DEFAULT 1,
  PRIMARY KEY (user_id, ecosystem, name)
) WITHOUT ROWID;
CREATE INDEX watch_packages_by_package ON watch_packages (ecosystem, name);

CREATE TABLE package_usage (
  user_id TEXT NOT NULL, day TEXT NOT NULL,          -- day = YYYY-MM-DD (UTC)
  packages INTEGER NOT NULL DEFAULT 0, calls INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (user_id, day)
) WITHOUT ROWID;

-- Users and OAuth clients refused on every MCP request, even with an unexpired token.
CREATE TABLE mcp_blocks (
  kind TEXT NOT NULL CHECK (kind IN ('user','client')),
  id TEXT NOT NULL,                                  -- Clerk user ID, or OAuth client_id
  reason TEXT NOT NULL CHECK (reason IN ('deleted','abuse','security','request')),
  created_at TEXT NOT NULL, expires_at TEXT,         -- NULL = until removed
  PRIMARY KEY (kind, id)
) WITHOUT ROWID;
