package com.example.bola_security.controller;

import com.example.bola_security.audit.AuditTrailService;
import com.example.bola_security.observability.SecurityObservabilityService;
import com.example.bola_security.security.ThreatModelingService;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

/**
 * Production-grade security management controller.
 * Provides security insights, audit trails, and threat intelligence.
 */
@RestController
@RequestMapping("/api/v1/security")
public class SecurityManagementController {

    private final AuditTrailService auditTrailService;
    private final SecurityObservabilityService observabilityService;
    private final ThreatModelingService threatModelingService;

    public SecurityManagementController(AuditTrailService auditTrailService,
                                       SecurityObservabilityService observabilityService,
                                       ThreatModelingService threatModelingService) {
        this.auditTrailService = auditTrailService;
        this.observabilityService = observabilityService;
        this.threatModelingService = threatModelingService;
    }

    /**
     * Get comprehensive security metrics
     */
    @GetMapping("/metrics")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<SecurityObservabilityService.SecurityMetrics> getSecurityMetrics() {
        return ResponseEntity.ok(observabilityService.getSecurityMetrics());
    }

    /**
     * Get recent audit events
     */
    @GetMapping("/audit/recent")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<Map<String, Object>> getRecentAuditEvents(
            @RequestParam(defaultValue = "100") int limit) {
        return ResponseEntity.ok(auditTrailService.getRecentAuditEvents(limit));
    }

    /**
     * Get audit statistics
     */
    @GetMapping("/audit/statistics")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<Map<String, Object>> getAuditStatistics() {
        return ResponseEntity.ok(auditTrailService.getAuditStatistics());
    }

    /**
     * Get threat model report
     */
    @GetMapping("/threat-model")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<String> getThreatModelReport() {
        return ResponseEntity.ok(threatModelingService.generateThreatModelReport());
    }

    /**
     * Get attack simulation results
     */
    @GetMapping("/attack-simulation")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<java.util.List<ThreatModelingService.AttackSimulationResult>> getAttackSimulationResults() {
        return ResponseEntity.ok(threatModelingService.simulateAttacks());
    }

    /**
     * Get security health check
     */
    @GetMapping("/health")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<Map<String, Object>> getSecurityHealth() {
        SecurityObservabilityService.SecurityMetrics metrics = observabilityService.getSecurityMetrics();
        
        Map<String, Object> health = Map.of(
            "status", "HEALTHY",
            "timestamp", java.time.LocalDateTime.now(),
            "metrics", metrics,
            "recommendations", getSecurityRecommendations(metrics)
        );
        
        return ResponseEntity.ok(health);
    }

    /**
     * Get security recommendations based on metrics
     */
    private java.util.List<String> getSecurityRecommendations(SecurityObservabilityService.SecurityMetrics metrics) {
        java.util.List<String> recommendations = new java.util.ArrayList<>();
        
        if (metrics.totalAccessDenied() > metrics.totalAccessGranted() * 0.1) {
            recommendations.add("High denial rate detected - review authorization policies");
        }
        
        if (metrics.totalBruteForceAttempts() > 100) {
            recommendations.add("High brute force activity - consider strengthening rate limits");
        }
        
        if (metrics.averageAuthorizationTime() > 100) {
            recommendations.add("Slow authorization decisions - optimize policy evaluation");
        }
        
        if (metrics.lockedAccounts() > 10) {
            recommendations.add("Multiple locked accounts - investigate potential attacks");
        }
        
        if (recommendations.isEmpty()) {
            recommendations.add("Security posture is optimal");
        }
        
        return recommendations;
    }
}
