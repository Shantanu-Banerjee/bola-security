CREATE TABLE IF NOT EXISTS refresh_tokens (
    id BIGINT NOT NULL AUTO_INCREMENT,
    user_id BIGINT NOT NULL,
    username VARCHAR(80) NOT NULL,
    token_hash VARCHAR(88) NOT NULL,
    created_at TIMESTAMP NOT NULL,
    expires_at TIMESTAMP NOT NULL,
    revoked_at TIMESTAMP NULL,
    replaced_by_token_hash VARCHAR(88),
    PRIMARY KEY (id),
    CONSTRAINT uk_refresh_tokens_hash UNIQUE (token_hash),
    CONSTRAINT fk_refresh_tokens_user FOREIGN KEY (user_id) REFERENCES users(id)
);

CREATE INDEX idx_refresh_tokens_user_expiry ON refresh_tokens(user_id, expires_at);
CREATE INDEX idx_refresh_tokens_revoked ON refresh_tokens(revoked_at);
CREATE INDEX idx_access_logs_user_resource_time ON access_logs(user_id, resource_id, timestamp);
CREATE INDEX idx_incidents_resolved_created ON security_incidents(resolved, created_at);
