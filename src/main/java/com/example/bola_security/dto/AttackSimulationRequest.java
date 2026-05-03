package com.example.bola_security.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;

import java.util.List;

public record AttackSimulationRequest(
        @NotBlank String attackType,
        @NotNull Long actorUserId,
        @NotEmpty List<Long> resourceIds,
        String httpMethod,
        String requestPathPrefix,
        String sourceIp,
        String userAgent
) {
}
