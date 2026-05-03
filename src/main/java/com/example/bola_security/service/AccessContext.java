package com.example.bola_security.service;

import com.example.bola_security.model.Resource;
import com.example.bola_security.model.Role;
import com.example.bola_security.model.User;

import java.time.LocalDateTime;

public record AccessContext(
        Long userId,
        String username,
        Role userRole,
        String userTenantId,
        String userDepartment,
        Long resourceId,
        Long resourceOwnerId,
        String resourceTenantId,
        String resourceDepartment,
        boolean tenantMatch,
        boolean ownerMatch,
        boolean sameDepartment,
        String ipAddress,
        String userAgent,
        String sessionId,
        String httpMethod,
        String requestPath,
        LocalDateTime accessTime,
        int accessHour,
        long recentDistinctResourceCount,
        boolean sequentialProbingLikely,
        int sequentialRunLength,
        int riskScore
) {
    public static AccessContext from(
            User user,
            Resource resource,
            RequestContext requestContext,
            long recentDistinctResourceCount
    ) {
        return from(
                user,
                resource,
                requestContext,
                new BehavioralAnalysisResult(false, false, recentDistinctResourceCount, 0)
        );
    }

    public static AccessContext from(
            User user,
            Resource resource,
            RequestContext requestContext,
            BehavioralAnalysisResult behavioralAnalysis
    ) {
        boolean ownerMatch = user.getId().equals(resource.getOwnerId());
        boolean sameDepartment = user.getDepartment().equals(resource.getDepartment());
        boolean tenantMatch = user.getTenantId().equals(resource.getTenantId());
        int riskScore = calculateRiskScore(
                requestContext,
                behavioralAnalysis,
                tenantMatch,
                ownerMatch,
                sameDepartment
        );

        return new AccessContext(
                user.getId(),
                user.getUsername(),
                user.getRole(),
                user.getTenantId(),
                user.getDepartment(),
                resource.getId(),
                resource.getOwnerId(),
                resource.getTenantId(),
                resource.getDepartment(),
                tenantMatch,
                ownerMatch,
                sameDepartment,
                requestContext.ipAddress(),
                requestContext.userAgent(),
                requestContext.sessionId(),
                requestContext.httpMethod(),
                requestContext.requestPath(),
                requestContext.accessTime(),
                requestContext.accessTime().getHour(),
                behavioralAnalysis.recentDistinctResourceCount(),
                behavioralAnalysis.sequentialProbingLikely(),
                behavioralAnalysis.sequentialRunLength(),
                riskScore
        );
    }

    private static int calculateRiskScore(
            RequestContext requestContext,
            BehavioralAnalysisResult behavioralAnalysis,
            boolean tenantMatch,
            boolean ownerMatch,
            boolean sameDepartment
    ) {
        int score = 0;
        if (!tenantMatch) {
            score += 50;
        }
        if (!ownerMatch) {
            score += 40;
        }
        if (!sameDepartment) {
            score += 20;
        }
        if (behavioralAnalysis.recentDistinctResourceCount() >= 3) {
            score += 20;
        }
        if (behavioralAnalysis.sequentialProbingLikely()) {
            score += 25;
        }
        if (requestContext.userAgent() == null || requestContext.userAgent().isBlank()) {
            score += 15;
        }
        return Math.min(score, 100);
    }
}
