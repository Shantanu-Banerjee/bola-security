package com.example.bola_security.dto;

import com.example.bola_security.model.SecurityAlert;

import java.time.LocalDateTime;

public record SecurityAlertResponse(
        Long id,
        String tenantId,
        Long userId,
        Long resourceId,
        Long securityIncidentId,
        String severity,
        String alertType,
        String message,
        LocalDateTime createdAt,
        boolean acknowledged
) {
    public static SecurityAlertResponse from(SecurityAlert alert) {
        return new SecurityAlertResponse(
                alert.getId(),
                alert.getTenantId(),
                alert.getUserId(),
                alert.getResourceId(),
                alert.getSecurityIncidentId(),
                alert.getSeverity().name(),
                alert.getAlertType(),
                alert.getMessage(),
                alert.getCreatedAt(),
                alert.isAcknowledged()
        );
    }
}
