ALTER TABLE resources
    ADD CONSTRAINT fk_resources_owner
    FOREIGN KEY (owner_id) REFERENCES users(id);

ALTER TABLE access_logs
    ADD CONSTRAINT fk_access_logs_user
    FOREIGN KEY (user_id) REFERENCES users(id),
    ADD CONSTRAINT fk_access_logs_resource
    FOREIGN KEY (resource_id) REFERENCES resources(id);

ALTER TABLE security_incidents
    ADD CONSTRAINT fk_incidents_user
    FOREIGN KEY (user_id) REFERENCES users(id),
    ADD CONSTRAINT fk_incidents_resource
    FOREIGN KEY (resource_id) REFERENCES resources(id);
