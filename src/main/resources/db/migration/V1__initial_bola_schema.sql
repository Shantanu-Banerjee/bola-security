CREATE TABLE IF NOT EXISTS users (
    id BIGINT NOT NULL AUTO_INCREMENT,
    username VARCHAR(80) NOT NULL,
    password VARCHAR(255) NOT NULL,
    role VARCHAR(30) NOT NULL,
    department VARCHAR(80) NOT NULL,
    account_locked BOOLEAN NOT NULL DEFAULT FALSE,
    failed_bola_attempts INT NOT NULL DEFAULT 0,
    PRIMARY KEY (id),
    CONSTRAINT uk_users_username UNIQUE (username)
);

CREATE TABLE IF NOT EXISTS resources (
    id BIGINT NOT NULL AUTO_INCREMENT,
    name VARCHAR(120) NOT NULL,
    owner_id BIGINT NOT NULL,
    department VARCHAR(80) NOT NULL,
    description VARCHAR(500),
    PRIMARY KEY (id)
);

CREATE TABLE IF NOT EXISTS access_logs (
    id BIGINT NOT NULL AUTO_INCREMENT,
    user_id BIGINT NOT NULL,
    resource_id BIGINT NOT NULL,
    resource_owner_id BIGINT NOT NULL,
    result VARCHAR(30) NOT NULL,
    reason VARCHAR(200) NOT NULL,
    timestamp TIMESTAMP NOT NULL,
    username VARCHAR(80),
    user_department VARCHAR(80),
    resource_department VARCHAR(80),
    user_role VARCHAR(30),
    owner_match BOOLEAN NOT NULL,
    same_department BOOLEAN NOT NULL,
    ip_address VARCHAR(80),
    user_agent VARCHAR(500),
    session_id VARCHAR(120),
    http_method VARCHAR(20),
    request_path VARCHAR(250),
    access_hour INT NOT NULL,
    recent_distinct_resource_count BIGINT NOT NULL,
    risk_score INT NOT NULL,
    PRIMARY KEY (id)
);

CREATE TABLE IF NOT EXISTS security_incidents (
    id BIGINT NOT NULL AUTO_INCREMENT,
    user_id BIGINT NOT NULL,
    username VARCHAR(80) NOT NULL,
    resource_id BIGINT NOT NULL,
    incident_type VARCHAR(80) NOT NULL,
    severity VARCHAR(30) NOT NULL,
    risk_score INT NOT NULL,
    description VARCHAR(250) NOT NULL,
    created_at TIMESTAMP NOT NULL,
    resolved BOOLEAN NOT NULL DEFAULT FALSE,
    PRIMARY KEY (id)
);

CREATE INDEX idx_resources_owner ON resources(owner_id);
CREATE INDEX idx_resources_department ON resources(department);
CREATE INDEX idx_access_logs_user_time ON access_logs(user_id, timestamp);
CREATE INDEX idx_access_logs_resource ON access_logs(resource_id);
CREATE INDEX idx_incidents_user_time ON security_incidents(user_id, created_at);
CREATE INDEX idx_incidents_severity ON security_incidents(severity);
