ALTER TABLE users
    ADD COLUMN last_failed_bola_attempt_at TIMESTAMP NULL,
    ADD COLUMN last_risk_decay_at TIMESTAMP NULL;
