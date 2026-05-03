package com.example.bola_security.gateway;

import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Gateway Request Logger - Comprehensive logging system for security events
 */
@Service
public class GatewayRequestLogger {

    private static final Logger logger = LoggerFactory.getLogger(GatewayRequestLogger.class);
    private static final DateTimeFormatter TIMESTAMP_FORMATTER = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss.SSS");
    
    // In-memory log storage (in production, would use database)
    private final ConcurrentLinkedQueue<SecurityLogEntry> securityLogs = new ConcurrentLinkedQueue<>();
    private final ConcurrentLinkedQueue<AccessLogEntry> accessLogs = new ConcurrentLinkedQueue<>();
    private final ConcurrentLinkedQueue<AttackLogEntry> attackLogs = new ConcurrentLinkedQueue<>();
    
    // Statistics
    private final AtomicLong totalRequests = new AtomicLong(0);
    private final AtomicLong blockedRequests = new AtomicLong(0);
    private final AtomicLong attackAttempts = new AtomicLong(0);
    
    /**
     * Log incoming request
     */
    public void logIncomingRequest(GatewayRequestContext context) {
        totalRequests.incrementAndGet();
        
        AccessLogEntry entry = AccessLogEntry.builder()
            .timestamp(LocalDateTime.now())
            .requestId(context.getRequestId())
            .clientIp(context.getClientIp())
            .userAgent(context.getUserAgent())
            .sessionId(context.getSessionId())
            .method(context.getMethod())
            .path(context.getPath())
            .query(context.getQuery())
            .headers(context.getHeaders())
            .status("INCOMING")
            .build();
        
        accessLogs.offer(entry);
        maintainLogSize();
        
        // Structured logging for monitoring
        logger.info("GATEWAY_REQUEST_IN: requestId={}, ip={}, method={}, path={}, sessionId={}", 
            context.getRequestId(), context.getClientIp(), context.getMethod(), 
            context.getPath(), maskSessionId(context.getSessionId()));
    }
    
    /**
     * Log successful response
     */
    public void logSuccessfulResponse(GatewayRequestContext context, HttpServletResponse response) {
        AccessLogEntry entry = AccessLogEntry.builder()
            .timestamp(LocalDateTime.now())
            .requestId(context.getRequestId())
            .clientIp(context.getClientIp())
            .method(context.getMethod())
            .path(context.getPath())
            .status("SUCCESS")
            .httpStatus(response.getStatus())
            .build();
        
        accessLogs.offer(entry);
        maintainLogSize();
        
        logger.info("GATEWAY_REQUEST_SUCCESS: requestId={}, ip={}, path={}, status={}", 
            context.getRequestId(), context.getClientIp(), context.getPath(), response.getStatus());
    }
    
    /**
     * Log blocked request
     */
    public void logBlockedRequest(GatewayRequestContext context, GatewaySecurityResult result) {
        blockedRequests.incrementAndGet();
        
        if (result.getRiskScore() > 60) {
            attackAttempts.incrementAndGet();
            logAttackAttempt(context, result);
        }
        
        SecurityLogEntry entry = SecurityLogEntry.builder()
            .timestamp(LocalDateTime.now())
            .requestId(context.getRequestId())
            .clientIp(context.getClientIp())
            .userAgent(context.getUserAgent())
            .sessionId(context.getSessionId())
            .method(context.getMethod())
            .path(context.getPath())
            .violationType(result.getViolationType())
            .reason(result.getReason())
            .riskScore(result.getRiskScore())
            .httpStatus(result.getHttpStatus())
            .userId(result.getUserId())
            .objectId(result.getObjectId())
            .processingTimeMs(result.getProcessingTimeMs())
            .build();
        
        securityLogs.offer(entry);
        maintainLogSize();
        
        logger.warn("GATEWAY_REQUEST_BLOCKED: requestId={}, ip={}, path={}, violation={}, reason={}, riskScore={}", 
            context.getRequestId(), context.getClientIp(), context.getPath(), 
            result.getViolationType(), result.getReason(), result.getRiskScore());
    }
    
    /**
     * Log processing error
     */
    public void logProcessingError(GatewayRequestContext context, Exception e) {
        SecurityLogEntry entry = SecurityLogEntry.builder()
            .timestamp(LocalDateTime.now())
            .requestId(context.getRequestId())
            .clientIp(context.getClientIp())
            .method(context.getMethod())
            .path(context.getPath())
            .violationType("PROCESSING_ERROR")
            .reason(e.getMessage())
            .httpStatus(500)
            .processingTimeMs(0)
            .build();
        
        securityLogs.offer(entry);
        maintainLogSize();
        
        logger.error("GATEWAY_PROCESSING_ERROR: requestId={}, ip={}, path={}, error={}", 
            context.getRequestId(), context.getClientIp(), context.getPath(), e.getMessage(), e);
    }
    
    /**
     * Log attack attempt with detailed information
     */
    private void logAttackAttempt(GatewayRequestContext context, GatewaySecurityResult result) {
        AttackLogEntry entry = AttackLogEntry.builder()
            .timestamp(LocalDateTime.now())
            .requestId(context.getRequestId())
            .clientIp(context.getClientIp())
            .userAgent(context.getUserAgent())
            .sessionId(context.getSessionId())
            .method(context.getMethod())
            .path(context.getPath())
            .attackType(result.getViolationType())
            .attackDescription(result.getReason())
            .severity(getAttackSeverity(result.getRiskScore()))
            .userId(result.getUserId())
            .targetObjectId(result.getObjectId())
            .riskScore(result.getRiskScore())
            .blocked(true)
            .build();
        
        attackLogs.offer(entry);
        maintainLogSize();
        
        // High-severity attack logging
        if (result.getRiskScore() >= 80) {
            logger.error("HIGH_SEVERITY_ATTACK: requestId={}, ip={}, attack={}, userId={}, target={}, description={}", 
                context.getRequestId(), context.getClientIp(), result.getViolationType(), 
                result.getUserId(), result.getObjectId(), result.getReason());
        }
    }
    
    /**
     * Get security logs
     */
    public List<SecurityLogEntry> getSecurityLogs(int limit) {
        return securityLogs.stream()
            .limit(limit)
            .toList();
    }
    
    /**
     * Get access logs
     */
    public List<AccessLogEntry> getAccessLogs(int limit) {
        return accessLogs.stream()
            .limit(limit)
            .toList();
    }
    
    /**
     * Get attack logs
     */
    public List<AttackLogEntry> getAttackLogs(int limit) {
        return attackLogs.stream()
            .limit(limit)
            .toList();
    }
    
    /**
     * Get gateway statistics
     */
    public GatewayStatistics getStatistics() {
        return GatewayStatistics.builder()
            .totalRequests(totalRequests.get())
            .blockedRequests(blockedRequests.get())
            .attackAttempts(attackAttempts.get())
            .blockRate(calculateBlockRate())
            .attackRate(calculateAttackRate())
            .topAttackers(getTopAttackers())
            .topAttackedEndpoints(getTopAttackedEndpoints())
            .recentAttacks(getRecentAttacks(10))
            .build();
    }
    
    /**
     * Get attack timeline for visualization
     */
    public List<AttackTimelineEntry> getAttackTimeline() {
        return attackLogs.stream()
            .collect(java.util.stream.Collectors.groupingBy(
                entry -> entry.getTimestamp().format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm")),
                java.util.stream.Collectors.counting()
            ))
            .entrySet().stream()
            .map(entry -> new AttackTimelineEntry(entry.getKey(), entry.getValue()))
            .sorted(Comparator.comparing(AttackTimelineEntry::getTimestamp))
            .toList();
    }
    
    /**
     * Get IP reputation data
     */
    public Map<String, IpReputationData> getIpReputation() {
        Map<String, IpReputationData> reputationMap = new HashMap<>();
        
        // Analyze IP behavior from logs
        Map<String, Long> ipRequestCounts = new HashMap<>();
        Map<String, Long> ipBlockCounts = new HashMap<>();
        
        securityLogs.forEach(log -> {
            ipRequestCounts.merge(log.getClientIp(), 1L, Long::sum);
            if (log.getHttpStatus() >= 400) {
                ipBlockCounts.merge(log.getClientIp(), 1L, Long::sum);
            }
        });
        
        ipRequestCounts.forEach((ip, requestCount) -> {
            long blockCount = ipBlockCounts.getOrDefault(ip, 0L);
            double blockRate = requestCount > 0 ? (double) blockCount / requestCount : 0;
            
            int reputation = 100;
            if (blockRate > 0.5) reputation = 0;
            else if (blockRate > 0.3) reputation = 25;
            else if (blockRate > 0.1) reputation = 50;
            else if (blockRate > 0.05) reputation = 75;
            
            reputationMap.put(ip, new IpReputationData(ip, requestCount, blockCount, blockRate, reputation));
        });
        
        return reputationMap;
    }
    
    /**
     * Export logs to CSV format
     */
    public String exportLogsToCsv(String logType) {
        StringBuilder csv = new StringBuilder();
        
        switch (logType.toLowerCase()) {
            case "security":
                csv.append("Timestamp,RequestID,ClientIP,Method,Path,ViolationType,Reason,RiskScore,HttpStatus\n");
                securityLogs.forEach(entry -> 
                    csv.append(String.format("%s,%s,%s,%s,%s,%s,%s,%d,%d\n",
                        entry.getTimestamp().format(TIMESTAMP_FORMATTER),
                        entry.getRequestId(),
                        entry.getClientIp(),
                        entry.getMethod(),
                        entry.getPath(),
                        entry.getViolationType(),
                        entry.getReason(),
                        entry.getRiskScore(),
                        entry.getHttpStatus()
                    ))
                );
                break;
                
            case "attack":
                csv.append("Timestamp,RequestID,ClientIP,AttackType,Severity,UserID,TargetID,RiskScore\n");
                attackLogs.forEach(entry ->
                    csv.append(String.format("%s,%s,%s,%s,%s,%s,%s,%d\n",
                        entry.getTimestamp().format(TIMESTAMP_FORMATTER),
                        entry.getRequestId(),
                        entry.getClientIp(),
                        entry.getAttackType(),
                        entry.getSeverity(),
                        entry.getUserId(),
                        entry.getTargetObjectId(),
                        entry.getRiskScore()
                    ))
                );
                break;
                
            default:
                csv.append("Timestamp,RequestID,ClientIP,Method,Path,Status,HttpStatus\n");
                accessLogs.forEach(entry ->
                    csv.append(String.format("%s,%s,%s,%s,%s,%s,%d\n",
                        entry.getTimestamp().format(TIMESTAMP_FORMATTER),
                        entry.getRequestId(),
                        entry.getClientIp(),
                        entry.getMethod(),
                        entry.getPath(),
                        entry.getStatus(),
                        entry.getHttpStatus()
                    ))
                );
        }
        
        return csv.toString();
    }
    
    // Helper methods
    private void maintainLogSize() {
        // Keep only last 1000 entries of each type
        while (securityLogs.size() > 1000) securityLogs.poll();
        while (accessLogs.size() > 1000) accessLogs.poll();
        while (attackLogs.size() > 1000) attackLogs.poll();
    }
    
    private String maskSessionId(String sessionId) {
        if (sessionId == null || sessionId.length() < 8) return "***";
        return sessionId.substring(0, 4) + "***" + sessionId.substring(sessionId.length() - 4);
    }
    
    private String getAttackSeverity(int riskScore) {
        if (riskScore >= 80) return "CRITICAL";
        if (riskScore >= 60) return "HIGH";
        if (riskScore >= 40) return "MEDIUM";
        return "LOW";
    }
    
    private double calculateBlockRate() {
        long total = totalRequests.get();
        return total > 0 ? (double) blockedRequests.get() / total : 0;
    }
    
    private double calculateAttackRate() {
        long total = totalRequests.get();
        return total > 0 ? (double) attackAttempts.get() / total : 0;
    }
    
    private List<String> getTopAttackers() {
        return securityLogs.stream()
            .collect(java.util.stream.Collectors.groupingBy(
                SecurityLogEntry::getClientIp,
                java.util.stream.Collectors.counting()
            ))
            .entrySet().stream()
            .sorted(Map.Entry.<String, Long>comparingByValue().reversed())
            .limit(5)
            .map(Map.Entry::getKey)
            .toList();
    }
    
    private List<String> getTopAttackedEndpoints() {
        return securityLogs.stream()
            .collect(java.util.stream.Collectors.groupingBy(
                SecurityLogEntry::getPath,
                java.util.stream.Collectors.counting()
            ))
            .entrySet().stream()
            .sorted(Map.Entry.<String, Long>comparingByValue().reversed())
            .limit(5)
            .map(Map.Entry::getKey)
            .toList();
    }
    
    private List<AttackLogEntry> getRecentAttacks(int limit) {
        return attackLogs.stream()
            .sorted(Comparator.comparing(AttackLogEntry::getTimestamp).reversed())
            .limit(limit)
            .toList();
    }
    
    // Data classes
    public static class SecurityLogEntry {
        private final LocalDateTime timestamp;
        private final String requestId;
        private final String clientIp;
        private final String userAgent;
        private final String sessionId;
        private final String method;
        private final String path;
        private final String violationType;
        private final String reason;
        private final int riskScore;
        private final int httpStatus;
        private final String userId;
        private final String objectId;
        private final long processingTimeMs;
        
        private SecurityLogEntry(Builder builder) {
            this.timestamp = builder.timestamp;
            this.requestId = builder.requestId;
            this.clientIp = builder.clientIp;
            this.userAgent = builder.userAgent;
            this.sessionId = builder.sessionId;
            this.method = builder.method;
            this.path = builder.path;
            this.violationType = builder.violationType;
            this.reason = builder.reason;
            this.riskScore = builder.riskScore;
            this.httpStatus = builder.httpStatus;
            this.userId = builder.userId;
            this.objectId = builder.objectId;
            this.processingTimeMs = builder.processingTimeMs;
        }
        
        public static Builder builder() { return new Builder(); }
        
        // Getters
        public LocalDateTime getTimestamp() { return timestamp; }
        public String getRequestId() { return requestId; }
        public String getClientIp() { return clientIp; }
        public String getUserAgent() { return userAgent; }
        public String getSessionId() { return sessionId; }
        public String getMethod() { return method; }
        public String getPath() { return path; }
        public String getViolationType() { return violationType; }
        public String getReason() { return reason; }
        public int getRiskScore() { return riskScore; }
        public int getHttpStatus() { return httpStatus; }
        public String getUserId() { return userId; }
        public String getObjectId() { return objectId; }
        public long getProcessingTimeMs() { return processingTimeMs; }
        
        public static class Builder {
            private LocalDateTime timestamp;
            private String requestId;
            private String clientIp;
            private String userAgent;
            private String sessionId;
            private String method;
            private String path;
            private String violationType;
            private String reason;
            private int riskScore;
            private int httpStatus;
            private String userId;
            private String objectId;
            private long processingTimeMs;
            
            public Builder timestamp(LocalDateTime timestamp) { this.timestamp = timestamp; return this; }
            public Builder requestId(String requestId) { this.requestId = requestId; return this; }
            public Builder clientIp(String clientIp) { this.clientIp = clientIp; return this; }
            public Builder userAgent(String userAgent) { this.userAgent = userAgent; return this; }
            public Builder sessionId(String sessionId) { this.sessionId = sessionId; return this; }
            public Builder method(String method) { this.method = method; return this; }
            public Builder path(String path) { this.path = path; return this; }
            public Builder violationType(String violationType) { this.violationType = violationType; return this; }
            public Builder reason(String reason) { this.reason = reason; return this; }
            public Builder riskScore(int riskScore) { this.riskScore = riskScore; return this; }
            public Builder httpStatus(int httpStatus) { this.httpStatus = httpStatus; return this; }
            public Builder userId(String userId) { this.userId = userId; return this; }
            public Builder objectId(String objectId) { this.objectId = objectId; return this; }
            public Builder processingTimeMs(long processingTimeMs) { this.processingTimeMs = processingTimeMs; return this; }
            
            public SecurityLogEntry build() { return new SecurityLogEntry(this); }
        }
    }
    
    public static class AccessLogEntry {
        private final LocalDateTime timestamp;
        private final String requestId;
        private final String clientIp;
        private final String userAgent;
        private final String sessionId;
        private final String method;
        private final String path;
        private final String query;
        private final Map<String, String> headers;
        private final String status;
        private final Integer httpStatus;
        
        private AccessLogEntry(Builder builder) {
            this.timestamp = builder.timestamp;
            this.requestId = builder.requestId;
            this.clientIp = builder.clientIp;
            this.userAgent = builder.userAgent;
            this.sessionId = builder.sessionId;
            this.method = builder.method;
            this.path = builder.path;
            this.query = builder.query;
            this.headers = builder.headers;
            this.status = builder.status;
            this.httpStatus = builder.httpStatus;
        }
        
        public static Builder builder() { return new Builder(); }
        
        // Getters
        public LocalDateTime getTimestamp() { return timestamp; }
        public String getRequestId() { return requestId; }
        public String getClientIp() { return clientIp; }
        public String getUserAgent() { return userAgent; }
        public String getSessionId() { return sessionId; }
        public String getMethod() { return method; }
        public String getPath() { return path; }
        public String getQuery() { return query; }
        public Map<String, String> getHeaders() { return headers; }
        public String getStatus() { return status; }
        public Integer getHttpStatus() { return httpStatus; }
        
        public static class Builder {
            private LocalDateTime timestamp;
            private String requestId;
            private String clientIp;
            private String userAgent;
            private String sessionId;
            private String method;
            private String path;
            private String query;
            private Map<String, String> headers;
            private String status;
            private Integer httpStatus;
            
            public Builder timestamp(LocalDateTime timestamp) { this.timestamp = timestamp; return this; }
            public Builder requestId(String requestId) { this.requestId = requestId; return this; }
            public Builder clientIp(String clientIp) { this.clientIp = clientIp; return this; }
            public Builder userAgent(String userAgent) { this.userAgent = userAgent; return this; }
            public Builder sessionId(String sessionId) { this.sessionId = sessionId; return this; }
            public Builder method(String method) { this.method = method; return this; }
            public Builder path(String path) { this.path = path; return this; }
            public Builder query(String query) { this.query = query; return this; }
            public Builder headers(Map<String, String> headers) { this.headers = headers; return this; }
            public Builder status(String status) { this.status = status; return this; }
            public Builder httpStatus(Integer httpStatus) { this.httpStatus = httpStatus; return this; }
            
            public AccessLogEntry build() { return new AccessLogEntry(this); }
        }
    }
    
    public static class AttackLogEntry {
        private final LocalDateTime timestamp;
        private final String requestId;
        private final String clientIp;
        private final String userAgent;
        private final String sessionId;
        private final String method;
        private final String path;
        private final String attackType;
        private final String attackDescription;
        private final String severity;
        private final String userId;
        private final String targetObjectId;
        private final int riskScore;
        private final boolean blocked;
        
        private AttackLogEntry(Builder builder) {
            this.timestamp = builder.timestamp;
            this.requestId = builder.requestId;
            this.clientIp = builder.clientIp;
            this.userAgent = builder.userAgent;
            this.sessionId = builder.sessionId;
            this.method = builder.method;
            this.path = builder.path;
            this.attackType = builder.attackType;
            this.attackDescription = builder.attackDescription;
            this.severity = builder.severity;
            this.userId = builder.userId;
            this.targetObjectId = builder.targetObjectId;
            this.riskScore = builder.riskScore;
            this.blocked = builder.blocked;
        }
        
        public static Builder builder() { return new Builder(); }
        
        // Getters
        public LocalDateTime getTimestamp() { return timestamp; }
        public String getRequestId() { return requestId; }
        public String getClientIp() { return clientIp; }
        public String getUserAgent() { return userAgent; }
        public String getSessionId() { return sessionId; }
        public String getMethod() { return method; }
        public String getPath() { return path; }
        public String getAttackType() { return attackType; }
        public String getAttackDescription() { return attackDescription; }
        public String getSeverity() { return severity; }
        public String getUserId() { return userId; }
        public String getTargetObjectId() { return targetObjectId; }
        public int getRiskScore() { return riskScore; }
        public boolean isBlocked() { return blocked; }
        
        public static class Builder {
            private LocalDateTime timestamp;
            private String requestId;
            private String clientIp;
            private String userAgent;
            private String sessionId;
            private String method;
            private String path;
            private String attackType;
            private String attackDescription;
            private String severity;
            private String userId;
            private String targetObjectId;
            private int riskScore;
            private boolean blocked;
            
            public Builder timestamp(LocalDateTime timestamp) { this.timestamp = timestamp; return this; }
            public Builder requestId(String requestId) { this.requestId = requestId; return this; }
            public Builder clientIp(String clientIp) { this.clientIp = clientIp; return this; }
            public Builder userAgent(String userAgent) { this.userAgent = userAgent; return this; }
            public Builder sessionId(String sessionId) { this.sessionId = sessionId; return this; }
            public Builder method(String method) { this.method = method; return this; }
            public Builder path(String path) { this.path = path; return this; }
            public Builder attackType(String attackType) { this.attackType = attackType; return this; }
            public Builder attackDescription(String attackDescription) { this.attackDescription = attackDescription; return this; }
            public Builder severity(String severity) { this.severity = severity; return this; }
            public Builder userId(String userId) { this.userId = userId; return this; }
            public Builder targetObjectId(String targetObjectId) { this.targetObjectId = targetObjectId; return this; }
            public Builder riskScore(int riskScore) { this.riskScore = riskScore; return this; }
            public Builder blocked(boolean blocked) { this.blocked = blocked; return this; }
            
            public AttackLogEntry build() { return new AttackLogEntry(this); }
        }
    }
    
    public static class GatewayStatistics {
        private final long totalRequests;
        private final long blockedRequests;
        private final long attackAttempts;
        private final double blockRate;
        private final double attackRate;
        private final List<String> topAttackers;
        private final List<String> topAttackedEndpoints;
        private final List<AttackLogEntry> recentAttacks;
        
        private GatewayStatistics(Builder builder) {
            this.totalRequests = builder.totalRequests;
            this.blockedRequests = builder.blockedRequests;
            this.attackAttempts = builder.attackAttempts;
            this.blockRate = builder.blockRate;
            this.attackRate = builder.attackRate;
            this.topAttackers = builder.topAttackers;
            this.topAttackedEndpoints = builder.topAttackedEndpoints;
            this.recentAttacks = builder.recentAttacks;
        }
        
        public static Builder builder() { return new Builder(); }
        
        // Getters
        public long getTotalRequests() { return totalRequests; }
        public long getBlockedRequests() { return blockedRequests; }
        public long getAttackAttempts() { return attackAttempts; }
        public double getBlockRate() { return blockRate; }
        public double getAttackRate() { return attackRate; }
        public List<String> getTopAttackers() { return topAttackers; }
        public List<String> getTopAttackedEndpoints() { return topAttackedEndpoints; }
        public List<AttackLogEntry> getRecentAttacks() { return recentAttacks; }
        
        public static class Builder {
            private long totalRequests;
            private long blockedRequests;
            private long attackAttempts;
            private double blockRate;
            private double attackRate;
            private List<String> topAttackers;
            private List<String> topAttackedEndpoints;
            private List<AttackLogEntry> recentAttacks;
            
            public Builder totalRequests(long totalRequests) { this.totalRequests = totalRequests; return this; }
            public Builder blockedRequests(long blockedRequests) { this.blockedRequests = blockedRequests; return this; }
            public Builder attackAttempts(long attackAttempts) { this.attackAttempts = attackAttempts; return this; }
            public Builder blockRate(double blockRate) { this.blockRate = blockRate; return this; }
            public Builder attackRate(double attackRate) { this.attackRate = attackRate; return this; }
            public Builder topAttackers(List<String> topAttackers) { this.topAttackers = topAttackers; return this; }
            public Builder topAttackedEndpoints(List<String> topAttackedEndpoints) { this.topAttackedEndpoints = topAttackedEndpoints; return this; }
            public Builder recentAttacks(List<AttackLogEntry> recentAttacks) { this.recentAttacks = recentAttacks; return this; }
            
            public GatewayStatistics build() { return new GatewayStatistics(this); }
        }
    }
    
    public static class AttackTimelineEntry {
        private final String timestamp;
        private final long count;
        
        public AttackTimelineEntry(String timestamp, long count) {
            this.timestamp = timestamp;
            this.count = count;
        }
        
        public String getTimestamp() { return timestamp; }
        public long getCount() { return count; }
    }
    
    public static class IpReputationData {
        private final String ipAddress;
        private final long requestCount;
        private final long blockCount;
        private final double blockRate;
        private final int reputation;
        
        public IpReputationData(String ipAddress, long requestCount, long blockCount, double blockRate, int reputation) {
            this.ipAddress = ipAddress;
            this.requestCount = requestCount;
            this.blockCount = blockCount;
            this.blockRate = blockRate;
            this.reputation = reputation;
        }
        
        public String getIpAddress() { return ipAddress; }
        public long getRequestCount() { return requestCount; }
        public long getBlockCount() { return blockCount; }
        public double getBlockRate() { return blockRate; }
        public int getReputation() { return reputation; }
    }
}
