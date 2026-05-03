package com.example.bola_security.dto;

public record AttackSimulationStepResponse(
        int step,
        Long resourceId,
        boolean allowed,
        String reason,
        int riskScore
) {
}
