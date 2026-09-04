ALTER TABLE app_users ADD COLUMN IF NOT EXISTS password_hash varchar(256);
