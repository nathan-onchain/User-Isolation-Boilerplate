-- migrations/20250925120000_create_failed_logins.sql

-- Create table to track failed login attempts
CREATE TABLE failed_logins (
    id SERIAL PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    attempt_time TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

-- Index for quick lookups by user & time (important for rate limiting)
CREATE INDEX idx_failed_logins_user_time
    ON failed_logins (user_id, attempt_time);
