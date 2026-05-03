package com.example.bola_security.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;

public record GatewayAuthorizationRequest(
        @NotNull Long resourceId,
        @NotBlank String httpMethod,
        @NotBlank String requestPath,
        String ipAddress,
        String userAgent,
        String sourceService
) {
}
