-- Optional per-administrator permissions. NULL-by-absence keeps role defaults.
PRAGMA foreign_keys = ON;

BEGIN IMMEDIATE;

CREATE TABLE IF NOT EXISTS admin_permission_overrides (
    admin_id         TEXT PRIMARY KEY REFERENCES admins(id) ON DELETE CASCADE,
    permissions_json TEXT NOT NULL CHECK (json_valid(permissions_json)),
    updated_by       TEXT REFERENCES admins(id) ON DELETE SET NULL,
    updated_at       INTEGER NOT NULL
);

PRAGMA user_version = 11;

COMMIT;
