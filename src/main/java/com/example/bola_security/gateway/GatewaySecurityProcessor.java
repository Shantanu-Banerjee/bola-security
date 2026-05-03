package com.example.bola_security.gateway;

import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Pattern;

/**
 * Real-time detection engine that tracks users, objects, sessions and detects anomalies
 */
@Service
public class GatewaySecurityProcessor {

    private static final Logger logger = LoggerFactory.getLogger(GatewaySecurityProcessor.class);
    
    // Tracking stores
    private final Map<String, UserSession> userSessions = new ConcurrentHashMap<>();
    private final Map<String, ObjectAccess> objectAccesses = new ConcurrentHashMap<>();
    private final Map<String, SessionActivity> sessionActivities = new ConcurrentHashMap<>();
    private final Map<String, IpReputation> ipReputations = new ConcurrentHashMap<>();
    
    // Detection patterns
    private static final Pattern RESOURCE_ID_PATTERN = Pattern.compile("/(\\d+)");
    private static final Set<String> SENSITIVE_ENDPOINTS = Set.of(
        "/api/v1/users", "/api/v1/admin", "/api/v1/delete", "/api/v1/bulk"
    );
    
    public GatewaySecurityResult processRequest(GatewayRequestContext context, HttpServletRequest request) {
        long startTime = System.currentTimeMillis();
        
        try {
            // Extract user and object information
            String userId = extractUserId(context, request);
            String objectId = extractObjectId(context.getPath());
            
            // Update tracking data
            updateUserTracking(userId, context);
            updateObjectTracking(objectId, userId, context);
            updateSessionTracking(context.getSessionId(), context);
            updateIpReputation(context.getClientIp(), context);
            
            // Perform security checks
            List<SecurityViolation> violations = detectViolations(context, userId, objectId);
            
            if (!violations.isEmpty()) {
                SecurityViolation mostSevere = violations.stream()
                    .max(Comparator.comparing(SecurityViolation::getSeverity))
                    .orElse(violations.get(0));
                
                return GatewaySecurityResult.builder()
                    .allowed(false)
                    .reason(mostSevere.getDescription())
                    .violationType(mostSevere.getType())
                    .httpStatus(mostSevere.getHttpStatus())
                    .userId(userId)
                    .objectId(objectId)
                    .riskScore(mostSevere.getSeverity())
                    .processingTimeMs(System.currentTimeMillis() - startTime)
                    .build();
            }
            
            return GatewaySecurityResult.builder()
                .allowed(true)
                .userId(userId)
                .objectId(objectId)
                .riskScore(calculateRiskScore(context, userId, objectId))
                .processingTimeMs(System.currentTimeMillis() - startTime)
                .build();
                
        } catch (Exception e) {
            logger.error("Security processing error for request: " + context.getRequestId(), e);
            return GatewaySecurityResult.builder()
                .allowed(false)
                .reason("Security processing error")
                .violationType("PROCESSING_ERROR")
                .httpStatus(500)
                .processingTimeMs(System.currentTimeMillis() - startTime)
                .build();
        }
    }
    
    private String extractUserId(GatewayRequestContext context, HttpServletRequest request) {
        // Try to extract user ID from various sources
        Map<String, String> headers = context.getHeaders() == null ? Map.of() : context.getHeaders();
        
        // 1. From JWT token (simplified)
        String authHeader = headers.get("Authorization");
        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            try {
                String token = authHeader.substring(7);
                // In real implementation, decode JWT properly
                if (token.contains("user")) {
                    return "user-" + token.hashCode() % 1000;
                }
            } catch (Exception e) {
                logger.debug("Failed to extract user from token");
            }
        }
        
        // 2. From session
        UserSession session = userSessions.get(sessionKey(context));
        if (session != null) {
            return session.getUserId();
        }
        
        // 3. From headers
        String userIdHeader = headers.get("X-User-ID");
        if (userIdHeader != null) {
            return userIdHeader;
        }
        
        // 4. Generate temporary ID for anonymous
        return "anon-" + Math.abs(clientIp(context).hashCode() % 1000);
    }
    
    private String extractObjectId(String path) {
        // Extract object ID from URL path
        java.util.regex.Matcher matcher = RESOURCE_ID_PATTERN.matcher(path);
        if (matcher.find()) {
            return matcher.group(1);
        }
        
        // For non-numeric resources, use path hash
        return "obj-" + (path.hashCode() % 1000);
    }
    
    private void updateUserTracking(String userId, GatewayRequestContext context) {
        UserSession session = userSessions.computeIfAbsent(sessionKey(context), k -> new UserSession());
        session.setUserId(userId);
        session.setLastActivity(context.getTimestamp());
        session.incrementRequestCount();
        session.addEndpoint(context.getPath());
        session.updateIp(clientIp(context));
    }
    
    private void updateObjectTracking(String objectId, String userId, GatewayRequestContext context) {
        ObjectAccess access = objectAccesses.computeIfAbsent(objectId, k -> new ObjectAccess());
        access.setObjectId(objectId);
        access.incrementAccessCount();
        access.addAccessingUser(userId);
        access.setLastAccess(context.getTimestamp());
        
        // Check for unusual access patterns
        if (access.getAccessingUsers().size() > 5) {
            access.setSuspicious(true);
            access.setSuspicionReason("Multiple users accessing same object");
        }
    }
    
    private void updateSessionTracking(String sessionId, GatewayRequestContext context) {
        String safeSessionId = sessionKey(context);
        SessionActivity activity = sessionActivities.computeIfAbsent(safeSessionId, k -> new SessionActivity());
        activity.setSessionId(safeSessionId);
        activity.setStartTime(context.getTimestamp());
        activity.setLastActivity(context.getTimestamp());
        activity.incrementRequestCount();
        activity.addEndpoint(context.getPath());
        
        // Check for session anomalies
        if (activity.getRequestCount() > 100) {
            activity.setSuspicious(true);
            activity.setSuspicionReason("High activity session");
        }
        
        if (activity.getEndpoints().size() > 20) {
            activity.setSuspicious(true);
            activity.setSuspicionReason("Wide endpoint access");
        }
    }
    
    private void updateIpReputation(String clientIp, GatewayRequestContext context) {
        String safeClientIp = clientIp == null || clientIp.isBlank() ? clientIp(context) : clientIp;
        IpReputation reputation = ipReputations.computeIfAbsent(safeClientIp, k -> new IpReputation());
        reputation.setIpAddress(safeClientIp);
        reputation.incrementRequestCount();
        reputation.setLastSeen(context.getTimestamp());
        
        // Update reputation based on behavior
        if (reputation.getRequestCount() > 1000) {
            reputation.setReputation(-50); // Poor reputation
            reputation.setReason("High request volume");
        } else if (reputation.getRequestCount() > 100) {
            reputation.setReputation(Math.max(-10, reputation.getReputation() - 10));
        }
    }
    
    private List<SecurityViolation> detectViolations(GatewayRequestContext context, String userId, String objectId) {
        List<SecurityViolation> violations = new ArrayList<>();
        
        // 1. Check IP reputation
        IpReputation ipRep = ipReputations.get(clientIp(context));
        if (ipRep != null && ipRep.getReputation() < -30) {
            violations.add(new SecurityViolation(
                "POOR_IP_REPUTATION",
                "IP has poor reputation: " + ipRep.getReason(),
                80, 403
            ));
        }
        
        // 2. Check session anomalies
        SessionActivity session = sessionActivities.get(sessionKey(context));
        if (session != null && session.isSuspicious()) {
            violations.add(new SecurityViolation(
                "SUSPICIOUS_SESSION",
                "Session anomaly: " + session.getSuspicionReason(),
                70, 403
            ));
        }
        
        // 3. Check object access patterns
        ObjectAccess objectAccess = objectAccesses.get(objectId);
        if (objectAccess != null && objectAccess.isSuspicious()) {
            violations.add(new SecurityViolation(
                "SUSPICIOUS_OBJECT_ACCESS",
                "Object access anomaly: " + objectAccess.getSuspicionReason(),
                60, 403
            ));
        }
        
        // 4. Check for IDOR patterns
        if (isIdorAttempt(context, userId, objectId)) {
            violations.add(new SecurityViolation(
                "IDOR_ATTEMPT",
                "Potential IDOR attack: user accessing unauthorized object",
                90, 403
            ));
        }
        
        // 5. Check for sequential probing
        if (isSequentialProbing(context, userId)) {
            violations.add(new SecurityViolation(
                "SEQUENTIAL_PROBING",
                "Sequential resource probing detected",
                85, 429
            ));
        }
        
        // 6. Check sensitive endpoint access
        if (SENSITIVE_ENDPOINTS.stream().anyMatch(context.getPath()::startsWith)) {
            if (!isAuthorizedForSensitive(userId, context.getPath())) {
                violations.add(new SecurityViolation(
                    "UNAUTHORIZED_SENSITIVE_ACCESS",
                    "Unauthorized access to sensitive endpoint",
                    75, 403
                ));
            }
        }
        
        // 7. Check rate limiting
        if (isRateLimited(context.getClientIp(), userId)) {
            violations.add(new SecurityViolation(
                "RATE_LIMIT_EXCEEDED",
                "Request rate exceeded limit",
                50, 429
            ));
        }
        
        return violations;
    }
    
    private boolean isIdorAttempt(GatewayRequestContext context, String userId, String objectId) {
        // Simple IDOR detection: check if user is trying to access objects they don't own
        UserSession session = userSessions.get(sessionKey(context));
        if (session == null) return false;
        
        // Check if user has accessed this object before
        ObjectAccess objectAccess = objectAccesses.get(objectId);
        if (objectAccess == null) return false;
        
        // If object has many accessors and this user is new, it might be IDOR
        return objectAccess.getAccessingUsers().size() > 1 && 
               !objectAccess.getAccessingUsers().contains(userId);
    }
    
    private boolean isSequentialProbing(GatewayRequestContext context, String userId) {
        UserSession session = userSessions.get(sessionKey(context));
        if (session == null) return false;
        
        // Check if user is accessing sequential numeric IDs
        Set<String> endpoints = session.getEndpoints();
        List<Long> numericIds = new ArrayList<>();
        
        for (String endpoint : endpoints) {
            java.util.regex.Matcher matcher = RESOURCE_ID_PATTERN.matcher(endpoint);
            if (matcher.find()) {
                numericIds.add(Long.parseLong(matcher.group(1)));
            }
        }
        
        if (numericIds.size() < 5) return false;
        
        // Sort and check for sequential pattern
        Collections.sort(numericIds);
        int sequentialCount = 1;
        
        for (int i = 1; i < numericIds.size(); i++) {
            if (numericIds.get(i) == numericIds.get(i-1) + 1) {
                sequentialCount++;
                if (sequentialCount >= 5) return true;
            } else {
                sequentialCount = 1;
            }
        }
        
        return false;
    }
    
    private boolean isAuthorizedForSensitive(String userId, String path) {
        // Simple authorization check for sensitive endpoints
        // In real implementation, check user roles and permissions
        return userId != null && !userId.startsWith("anon-");
    }
    
    private boolean isRateLimited(String clientIp, String userId) {
        String safeClientIp = clientIp == null || clientIp.isBlank() ? "unknown" : clientIp;
        IpReputation ipRep = ipReputations.get(safeClientIp);
        if (ipRep != null && ipRep.getRequestCount() > 500) {
            return true;
        }
        
        UserSession session = userSessions.values().stream()
            .filter(s -> Objects.equals(s.getUserId(), userId))
            .findFirst()
            .orElse(null);
            
        return session != null && session.getRequestCount() > 200;
    }
    
    private int calculateRiskScore(GatewayRequestContext context, String userId, String objectId) {
        int score = 0;
        
        // IP reputation factor
        IpReputation ipRep = ipReputations.get(clientIp(context));
        if (ipRep != null) {
            score += Math.max(0, -ipRep.getReputation());
        }
        
        // Session activity factor
        SessionActivity session = sessionActivities.get(sessionKey(context));
        if (session != null && session.isSuspicious()) {
            score += 30;
        }
        
        // Object access factor
        ObjectAccess objectAccess = objectAccesses.get(objectId);
        if (objectAccess != null && objectAccess.isSuspicious()) {
            score += 20;
        }
        
        // Sensitive endpoint factor
        if (SENSITIVE_ENDPOINTS.stream().anyMatch(context.getPath()::startsWith)) {
            score += 25;
        }
        
        return Math.min(100, score);
    }

    private String sessionKey(GatewayRequestContext context) {
        String sessionId = context.getSessionId();
        if (sessionId == null || sessionId.isBlank()) {
            return "anonymous:" + clientIp(context);
        }
        return sessionId;
    }

    private String clientIp(GatewayRequestContext context) {
        String clientIp = context.getClientIp();
        return clientIp == null || clientIp.isBlank() ? "unknown" : clientIp;
    }
    
    // Data structures for tracking
    private static class UserSession {
        private String userId;
        private long lastActivity;
        private int requestCount;
        private Set<String> endpoints = new HashSet<>();
        private Set<String> ips = new HashSet<>();
        
        public void incrementRequestCount() { requestCount++; }
        public void addEndpoint(String endpoint) { endpoints.add(endpoint); }
        public void updateIp(String ip) { ips.add(ip); }
        
        // Getters and setters
        public String getUserId() { return userId; }
        public void setUserId(String userId) { this.userId = userId; }
        public long getLastActivity() { return lastActivity; }
        public void setLastActivity(long lastActivity) { this.lastActivity = lastActivity; }
        public int getRequestCount() { return requestCount; }
        public Set<String> getEndpoints() { return endpoints; }
        public Set<String> getIps() { return ips; }
    }
    
    private static class ObjectAccess {
        private String objectId;
        private int accessCount;
        private long lastAccess;
        private Set<String> accessingUsers = new HashSet<>();
        private boolean suspicious;
        private String suspicionReason;
        
        public void incrementAccessCount() { accessCount++; }
        public void addAccessingUser(String userId) { accessingUsers.add(userId); }
        
        // Getters and setters
        public String getObjectId() { return objectId; }
        public void setObjectId(String objectId) { this.objectId = objectId; }
        public int getAccessCount() { return accessCount; }
        public long getLastAccess() { return lastAccess; }
        public void setLastAccess(long lastAccess) { this.lastAccess = lastAccess; }
        public Set<String> getAccessingUsers() { return accessingUsers; }
        public boolean isSuspicious() { return suspicious; }
        public void setSuspicious(boolean suspicious) { this.suspicious = suspicious; }
        public String getSuspicionReason() { return suspicionReason; }
        public void setSuspicionReason(String suspicionReason) { this.suspicionReason = suspicionReason; }
    }
    
    private static class SessionActivity {
        private String sessionId;
        private long startTime;
        private long lastActivity;
        private int requestCount;
        private Set<String> endpoints = new HashSet<>();
        private boolean suspicious;
        private String suspicionReason;
        
        public void incrementRequestCount() { requestCount++; }
        public void addEndpoint(String endpoint) { endpoints.add(endpoint); }
        
        // Getters and setters
        public String getSessionId() { return sessionId; }
        public void setSessionId(String sessionId) { this.sessionId = sessionId; }
        public long getStartTime() { return startTime; }
        public void setStartTime(long startTime) { this.startTime = startTime; }
        public long getLastActivity() { return lastActivity; }
        public void setLastActivity(long lastActivity) { this.lastActivity = lastActivity; }
        public int getRequestCount() { return requestCount; }
        public Set<String> getEndpoints() { return endpoints; }
        public boolean isSuspicious() { return suspicious; }
        public void setSuspicious(boolean suspicious) { this.suspicious = suspicious; }
        public String getSuspicionReason() { return suspicionReason; }
        public void setSuspicionReason(String suspicionReason) { this.suspicionReason = suspicionReason; }
    }
    
    private static class IpReputation {
        private String ipAddress;
        private int reputation = 100; // Start with neutral reputation
        private int requestCount;
        private long lastSeen;
        private String reason;
        
        public void incrementRequestCount() { requestCount++; }
        
        // Getters and setters
        public String getIpAddress() { return ipAddress; }
        public void setIpAddress(String ipAddress) { this.ipAddress = ipAddress; }
        public int getReputation() { return reputation; }
        public void setReputation(int reputation) { this.reputation = reputation; }
        public int getRequestCount() { return requestCount; }
        public long getLastSeen() { return lastSeen; }
        public void setLastSeen(long lastSeen) { this.lastSeen = lastSeen; }
        public String getReason() { return reason; }
        public void setReason(String reason) { this.reason = reason; }
    }
    
    private static class SecurityViolation {
        private final String type;
        private final String description;
        private final int severity;
        private final int httpStatus;
        
        public SecurityViolation(String type, String description, int severity, int httpStatus) {
            this.type = type;
            this.description = description;
            this.severity = severity;
            this.httpStatus = httpStatus;
        }
        
        public String getType() { return type; }
        public String getDescription() { return description; }
        public int getSeverity() { return severity; }
        public int getHttpStatus() { return httpStatus; }
    }
}
