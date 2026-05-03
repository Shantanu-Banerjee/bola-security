package com.example.bola_security.model;

import jakarta.persistence.*;

import java.time.LocalDateTime;

@Entity
@Table(name = "security_alerts", indexes = {
        @Index(name = "idx_alerts_tenant_created", columnList = "tenantId,createdAt"),
        @Index(name = "idx_alerts_ack_created", columnList = "acknowledged,createdAt")
})
public class SecurityAlert {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, length = 80)
    private String tenantId;

    private Long userId;

    private Long resourceId;

    private Long securityIncidentId;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 30)
    private IncidentSeverity severity;

    @Column(nullable = false, length = 80)
    private String alertType;

    @Column(nullable = false, length = 250)
    private String message;

    @Column(nullable = false)
    private LocalDateTime createdAt;

    @Column(nullable = false)
    private boolean acknowledged = false;

    public Long getId() {
        return id;
    }

    public String getTenantId() {
        return tenantId;
    }

    public void setTenantId(String tenantId) {
        this.tenantId = tenantId;
    }

    public Long getUserId() {
        return userId;
    }

    public void setUserId(Long userId) {
        this.userId = userId;
    }

    public Long getResourceId() {
        return resourceId;
    }

    public void setResourceId(Long resourceId) {
        this.resourceId = resourceId;
    }

    public Long getSecurityIncidentId() {
        return securityIncidentId;
    }

    public void setSecurityIncidentId(Long securityIncidentId) {
        this.securityIncidentId = securityIncidentId;
    }

    public IncidentSeverity getSeverity() {
        return severity;
    }

    public void setSeverity(IncidentSeverity severity) {
        this.severity = severity;
    }

    public String getAlertType() {
        return alertType;
    }

    public void setAlertType(String alertType) {
        this.alertType = alertType;
    }

    public String getMessage() {
        return message;
    }

    public void setMessage(String message) {
        this.message = message;
    }

    public LocalDateTime getCreatedAt() {
        return createdAt;
    }

    public void setCreatedAt(LocalDateTime createdAt) {
        this.createdAt = createdAt;
    }

    public boolean isAcknowledged() {
        return acknowledged;
    }

    public void setAcknowledged(boolean acknowledged) {
        this.acknowledged = acknowledged;
    }
}
