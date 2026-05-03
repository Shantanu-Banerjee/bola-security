package com.example.bola_security.audit;

import com.example.bola_security.model.User;
import com.example.bola_security.service.AccessContext;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentLinkedQueue;

/**
 * Comprehensive audit trail service for security events.
 * Tracks who accessed what, when, and the outcome.
 */
@Service
public class AuditTrailService {

    private static final Logger logger = LoggerFactory.getLogger(AuditTrailService.class);
    private final ObjectMapper objectMapper;
    private final ConcurrentLinkedQueue<AuditEvent> auditEvents;

    public AuditTrailService(ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
        this.auditEvents = new ConcurrentLinkedQueue<>();
    }

    /**
     * Record successful resource access
     */
    public void recordAccessSuccess(User user, Long resourceId, String action, AccessContext context) {
        AuditEvent event = AuditEvent.builder()
            .timestamp(LocalDateTime.now())
            .userId(user.getId())
            .username(user.getUsername())
            .userRole(user.getRole().name())
            .userDepartment(user.getDepartment())
            .resourceId(resourceId)
            .action(action)
            .result("SUCCESS")
            .ipAddress(context.ipAddress())
            .userAgent(context.userAgent())
            .sessionId(context.sessionId())
            .requestPath(context.requestPath())
            .httpMethod(context.httpMethod())
            .riskScore(context.riskScore())
            .build();

        logAuditEvent(event);
        addToAuditQueue(event);
    }

    /**
     * Record failed resource access
     */
    public void recordAccessDenied(User user, Long resourceId, String action, String reason, AccessContext context) {
        AuditEvent event = AuditEvent.builder()
            .timestamp(LocalDateTime.now())
            .userId(user != null ? user.getId() : null)
            .username(user != null ? user.getUsername() : "ANONYMOUS")
            .userRole(user != null ? user.getRole().name() : "ANONYMOUS")
            .userDepartment(user != null ? user.getDepartment() : null)
            .resourceId(resourceId)
            .action(action)
            .result("DENIED")
            .reason(reason)
            .ipAddress(context.ipAddress())
            .userAgent(context.userAgent())
            .sessionId(context.sessionId())
            .requestPath(context.requestPath())
            .httpMethod(context.httpMethod())
            .riskScore(context.riskScore())
            .build();

        logAuditEvent(event);
        addToAuditQueue(event);
    }

    /**
     * Record security incident
     */
    public void recordSecurityIncident(String incidentType, String description, int severity, 
                                       Long userId, String ipAddress, String userAgent) {
        AuditEvent event = AuditEvent.builder()
            .timestamp(LocalDateTime.now())
            .userId(userId)
            .username(userId != null ? "USER_" + userId : "SYSTEM")
            .action(incidentType)
            .result("INCIDENT")
            .reason(description)
            .severity(severity)
            .ipAddress(ipAddress)
            .userAgent(userAgent)
            .build();

        logAuditEvent(event);
        addToAuditQueue(event);
    }

    /**
     * Record authentication event
     */
    public void recordAuthEvent(String username, String result, String reason, String ipAddress, String userAgent) {
        AuditEvent event = AuditEvent.builder()
            .timestamp(LocalDateTime.now())
            .username(username)
            .action("AUTHENTICATION")
            .result(result)
            .reason(reason)
            .ipAddress(ipAddress)
            .userAgent(userAgent)
            .build();

        logAuditEvent(event);
        addToAuditQueue(event);
    }

    /**
     * Record privileged operation
     */
    public void recordPrivilegedOperation(User user, String operation, String details, String ipAddress) {
        AuditEvent event = AuditEvent.builder()
            .timestamp(LocalDateTime.now())
            .userId(user.getId())
            .username(user.getUsername())
            .userRole(user.getRole().name())
            .userDepartment(user.getDepartment())
            .action(operation)
            .result("EXECUTED")
            .reason(details)
            .ipAddress(ipAddress)
            .severity(user.getRole().name().equals("ADMIN") ? 70 : 40)
            .build();

        logAuditEvent(event);
        addToAuditQueue(event);
    }

    /**
     * Get recent audit events
     */
    public Map<String, Object> getRecentAuditEvents(int limit) {
        Map<String, Object> response = new HashMap<>();
        response.put("events", auditEvents.stream().limit(limit).toList());
        response.put("totalEvents", auditEvents.size());
        response.put("timestamp", LocalDateTime.now());
        return response;
    }

    /**
     * Get audit statistics
     */
    public Map<String, Object> getAuditStatistics() {
        Map<String, Object> stats = new HashMap<>();
        
        long totalEvents = auditEvents.size();
        long successfulAccess = auditEvents.stream()
            .filter(e -> "SUCCESS".equals(e.result()))
            .count();
        long deniedAccess = auditEvents.stream()
            .filter(e -> "DENIED".equals(e.result()))
            .count();
        long securityIncidents = auditEvents.stream()
            .filter(e -> "INCIDENT".equals(e.result()))
            .count();

        stats.put("totalEvents", totalEvents);
        stats.put("successfulAccess", successfulAccess);
        stats.put("deniedAccess", deniedAccess);
        stats.put("securityIncidents", securityIncidents);
        stats.put("successRate", totalEvents > 0 ? (successfulAccess * 100.0 / totalEvents) : 0);
        stats.put("denialRate", totalEvents > 0 ? (deniedAccess * 100.0 / totalEvents) : 0);

        return stats;
    }

    /**
     * Log audit event to structured logs
     */
    private void logAuditEvent(AuditEvent event) {
        try {
            String auditJson = objectMapper.writeValueAsString(event);
            
            if ("INCIDENT".equals(event.result()) || event.severity() > 70) {
                logger.error("AUDIT_EVENT: {}", auditJson);
            } else if ("DENIED".equals(event.result()) || event.severity() > 40) {
                logger.warn("AUDIT_EVENT: {}", auditJson);
            } else {
                logger.info("AUDIT_EVENT: {}", auditJson);
            }
        } catch (Exception e) {
            logger.error("Failed to serialize audit event", e);
        }
    }

    /**
     * Add event to audit queue (in production, would persist to database)
     */
    private void addToAuditQueue(AuditEvent event) {
        // Keep only last 1000 events in memory
        auditEvents.offer(event);
        while (auditEvents.size() > 1000) {
            auditEvents.poll();
        }
        
        // In production, would also write to database or log aggregation system
    }

    /**
     * Audit event record
     */
    public static class AuditEvent {
        private final LocalDateTime timestamp;
        private final Long userId;
        private final String username;
        private final String userRole;
        private final String userDepartment;
        private final Long resourceId;
        private final String action;
        private final String result;
        private final String reason;
        private final String ipAddress;
        private final String userAgent;
        private final String sessionId;
        private final String requestPath;
        private final String httpMethod;
        private final int riskScore;
        private final int severity;

        private AuditEvent(Builder builder) {
            this.timestamp = builder.timestamp;
            this.userId = builder.userId;
            this.username = builder.username;
            this.userRole = builder.userRole;
            this.userDepartment = builder.userDepartment;
            this.resourceId = builder.resourceId;
            this.action = builder.action;
            this.result = builder.result;
            this.reason = builder.reason;
            this.ipAddress = builder.ipAddress;
            this.userAgent = builder.userAgent;
            this.sessionId = builder.sessionId;
            this.requestPath = builder.requestPath;
            this.httpMethod = builder.httpMethod;
            this.riskScore = builder.riskScore;
            this.severity = builder.severity;
        }

        public static Builder builder() {
            return new Builder();
        }

        // Getters
        public LocalDateTime timestamp() { return timestamp; }
        public Long userId() { return userId; }
        public String username() { return username; }
        public String userRole() { return userRole; }
        public String userDepartment() { return userDepartment; }
        public Long resourceId() { return resourceId; }
        public String action() { return action; }
        public String result() { return result; }
        public String reason() { return reason; }
        public String ipAddress() { return ipAddress; }
        public String userAgent() { return userAgent; }
        public String sessionId() { return sessionId; }
        public String requestPath() { return requestPath; }
        public String httpMethod() { return httpMethod; }
        public int riskScore() { return riskScore; }
        public int severity() { return severity; }

        public static class Builder {
            private LocalDateTime timestamp;
            private Long userId;
            private String username;
            private String userRole;
            private String userDepartment;
            private Long resourceId;
            private String action;
            private String result;
            private String reason;
            private String ipAddress;
            private String userAgent;
            private String sessionId;
            private String requestPath;
            private String httpMethod;
            private int riskScore;
            private int severity;

            public Builder timestamp(LocalDateTime timestamp) { this.timestamp = timestamp; return this; }
            public Builder userId(Long userId) { this.userId = userId; return this; }
            public Builder username(String username) { this.username = username; return this; }
            public Builder userRole(String userRole) { this.userRole = userRole; return this; }
            public Builder userDepartment(String userDepartment) { this.userDepartment = userDepartment; return this; }
            public Builder resourceId(Long resourceId) { this.resourceId = resourceId; return this; }
            public Builder action(String action) { this.action = action; return this; }
            public Builder result(String result) { this.result = result; return this; }
            public Builder reason(String reason) { this.reason = reason; return this; }
            public Builder ipAddress(String ipAddress) { this.ipAddress = ipAddress; return this; }
            public Builder userAgent(String userAgent) { this.userAgent = userAgent; return this; }
            public Builder sessionId(String sessionId) { this.sessionId = sessionId; return this; }
            public Builder requestPath(String requestPath) { this.requestPath = requestPath; return this; }
            public Builder httpMethod(String httpMethod) { this.httpMethod = httpMethod; return this; }
            public Builder riskScore(int riskScore) { this.riskScore = riskScore; return this; }
            public Builder severity(int severity) { this.severity = severity; return this; }

            public AuditEvent build() {
                return new AuditEvent(this);
            }
        }
    }
}
