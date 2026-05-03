ALTER TABLE users
    ADD COLUMN tenant_id VARCHAR(80) NOT NULL DEFAULT 'default';

ALTER TABLE resources
    ADD COLUMN tenant_id VARCHAR(80) NOT NULL DEFAULT 'default';

ALTER TABLE refresh_tokens
    ADD COLUMN tenant_id VARCHAR(80) NOT NULL DEFAULT 'default';

ALTER TABLE access_logs
    ADD COLUMN user_tenant_id VARCHAR(80) NULL,
    ADD COLUMN resource_tenant_id VARCHAR(80) NULL,
    ADD COLUMN tenant_match BOOLEAN NOT NULL DEFAULT TRUE;

ALTER TABLE security_incidents
    ADD COLUMN tenant_id VARCHAR(80) NOT NULL DEFAULT 'default',
    ADD COLUMN resource_tenant_id VARCHAR(80) NOT NULL DEFAULT 'default';

CREATE INDEX idx_users_tenant ON users(tenant_id);
CREATE INDEX idx_resources_tenant ON resources(tenant_id);
CREATE INDEX idx_incidents_tenant ON security_incidents(tenant_id);

CREATE TABLE IF NOT EXISTS security_alerts (
    id BIGINT NOT NULL AUTO_INCREMENT,
    tenant_id VARCHAR(80) NOT NULL,
    user_id BIGINT NULL,
    resource_id BIGINT NULL,
    security_incident_id BIGINT NULL,
    severity VARCHAR(30) NOT NULL,
    alert_type VARCHAR(80) NOT NULL,
    message VARCHAR(250) NOT NULL,
    created_at TIMESTAMP NOT NULL,
    acknowledged BOOLEAN NOT NULL DEFAULT FALSE,
    PRIMARY KEY (id),
    CONSTRAINT fk_security_alerts_user FOREIGN KEY (user_id) REFERENCES users(id),
    CONSTRAINT fk_security_alerts_resource FOREIGN KEY (resource_id) REFERENCES resources(id),
    CONSTRAINT fk_security_alerts_incident FOREIGN KEY (security_incident_id) REFERENCES security_incidents(id)
);

CREATE INDEX idx_alerts_tenant_created ON security_alerts(tenant_id, created_at);
CREATE INDEX idx_alerts_ack_created ON security_alerts(acknowledged, created_at);
