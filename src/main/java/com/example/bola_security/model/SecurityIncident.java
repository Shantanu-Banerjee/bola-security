package com.example.bola_security.model;

import jakarta.persistence.*;

import java.time.LocalDateTime;

@Entity
@Table(name = "security_incidents", indexes = {
        @Index(name = "idx_incidents_user_time", columnList = "userId,createdAt"),
        @Index(name = "idx_incidents_severity", columnList = "severity"),
        @Index(name = "idx_incidents_tenant", columnList = "tenantId")
})
public class SecurityIncident {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false)
    private Long userId;

    @Column(nullable = false, length = 80)
    private String username;

    @Column(nullable = false, length = 80)
    private String tenantId = "default";

    @Column(nullable = false, length = 80)
    private String resourceTenantId = "default";

    @Column(nullable = false)
    private Long resourceId;

    @Column(nullable = false, length = 80)
    private String incidentType;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 30)
    private IncidentSeverity severity;

    @Column(nullable = false)
    private int riskScore;

    @Column(nullable = false, length = 250)
    private String description;

    @Column(nullable = false)
    private LocalDateTime createdAt;

    @Column(nullable = false)
    private boolean resolved = false;

    public Long getId() {
        return id;
    }

    public Long getUserId() {
        return userId;
    }

    public void setUserId(Long userId) {
        this.userId = userId;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getTenantId() {
        return tenantId;
    }

    public void setTenantId(String tenantId) {
        this.tenantId = tenantId;
    }

    public String getResourceTenantId() {
        return resourceTenantId;
    }

    public void setResourceTenantId(String resourceTenantId) {
        this.resourceTenantId = resourceTenantId;
    }

    public Long getResourceId() {
        return resourceId;
    }

    public void setResourceId(Long resourceId) {
        this.resourceId = resourceId;
    }

    public String getIncidentType() {
        return incidentType;
    }

    public void setIncidentType(String incidentType) {
        this.incidentType = incidentType;
    }

    public IncidentSeverity getSeverity() {
        return severity;
    }

    public void setSeverity(IncidentSeverity severity) {
        this.severity = severity;
    }

    public int getRiskScore() {
        return riskScore;
    }

    public void setRiskScore(int riskScore) {
        this.riskScore = riskScore;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    public LocalDateTime getCreatedAt() {
        return createdAt;
    }

    public void setCreatedAt(LocalDateTime createdAt) {
        this.createdAt = createdAt;
    }

    public boolean isResolved() {
        return resolved;
    }

    public void setResolved(boolean resolved) {
        this.resolved = resolved;
    }
}
