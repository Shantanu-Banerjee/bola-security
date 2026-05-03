package com.example.bola_security.dto;

import com.example.bola_security.model.SecurityIncident;

import java.time.LocalDateTime;

public record SecurityIncidentResponse(
        Long id,
        Long userId,
        String username,
        String tenantId,
        String resourceTenantId,
        Long resourceId,
        String incidentType,
        String severity,
        int riskScore,
        String description,
        LocalDateTime createdAt,
        boolean resolved
) {
    public static SecurityIncidentResponse from(SecurityIncident incident) {
        return new SecurityIncidentResponse(
                incident.getId(),
                incident.getUserId(),
                incident.getUsername(),
                incident.getTenantId(),
                incident.getResourceTenantId(),
                incident.getResourceId(),
                incident.getIncidentType(),
                incident.getSeverity().name(),
                incident.getRiskScore(),
                incident.getDescription(),
                incident.getCreatedAt(),
                incident.isResolved()
        );
    }
}
