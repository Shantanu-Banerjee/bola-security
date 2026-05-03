package com.example.bola_security.dto;

public record GatewayAuthorizationResponse(
        boolean allowed,
        String reason,
        Long resourceId,
        String tenantId,
        int riskScore,
        String sourceService
) {
}
