package com.example.bola_security.dto;

import java.util.List;

public record AttackSimulationResponse(
        String attackType,
        Long actorUserId,
        String tenantId,
        int attemptedCount,
        int blockedCount,
        List<AttackSimulationStepResponse> steps
) {
}
