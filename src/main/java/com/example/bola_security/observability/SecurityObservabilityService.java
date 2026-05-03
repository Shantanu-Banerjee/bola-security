package com.example.bola_security.observability;

import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.Gauge;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.Timer;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.time.LocalDateTime;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Production-grade observability and metrics service.
 * Provides comprehensive monitoring for security events and system health.
 */
@Service
public class SecurityObservabilityService {

    private final MeterRegistry meterRegistry;
    
    // Security event counters
    private final Counter accessGrantedCounter;
    private final Counter accessDeniedCounter;
    private final Counter securityIncidentCounter;
    private final Counter bruteForceAttemptCounter;
    private final Counter idorAttemptCounter;
    private final Counter tokenReuseCounter;
    private final Counter rateLimitExceededCounter;
    
    // Performance timers
    private final Timer authorizationTimer;
    private final Timer requestTimer;
    private final Timer authenticationTimer;
    
    // System health gauges
    private final AtomicLong activeSessions;
    private final AtomicLong blockedIPs;
    private final AtomicLong lockedAccounts;
    private final AtomicLong highRiskUsers;
    
    // Risk score tracking
    private final ConcurrentHashMap<String, AtomicLong> riskScoreDistribution;
    
    // Attack pattern detection
    private final AtomicLong sequentialProbingEvents;
    private final AtomicLong distributedAttackEvents;
    private final AtomicLong crossTenantAttempts;

    public SecurityObservabilityService(MeterRegistry meterRegistry) {
        this.meterRegistry = meterRegistry;
        
        // Initialize counters
        this.accessGrantedCounter = Counter.builder("security.access.granted")
            .description("Number of successful access attempts")
            .register(meterRegistry);
            
        this.accessDeniedCounter = Counter.builder("security.access.denied")
            .description("Number of denied access attempts")
            .register(meterRegistry);
            
        this.securityIncidentCounter = Counter.builder("security.incident")
            .description("Number of security incidents")
            .register(meterRegistry);
            
        this.bruteForceAttemptCounter = Counter.builder("security.attack.brute_force")
            .description("Number of brute force attack attempts")
            .register(meterRegistry);
            
        this.idorAttemptCounter = Counter.builder("security.attack.idor")
            .description("Number of IDOR attack attempts")
            .register(meterRegistry);
            
        this.tokenReuseCounter = Counter.builder("security.attack.token_reuse")
            .description("Number of token reuse attempts")
            .register(meterRegistry);
            
        this.rateLimitExceededCounter = Counter.builder("security.rate_limit.exceeded")
            .description("Number of rate limit violations")
            .register(meterRegistry);
        
        // Initialize timers
        this.authorizationTimer = Timer.builder("security.authorization.duration")
            .description("Authorization decision time")
            .register(meterRegistry);
            
        this.requestTimer = Timer.builder("security.request.duration")
            .description("Request processing time")
            .register(meterRegistry);
            
        this.authenticationTimer = Timer.builder("security.authentication.duration")
            .description("Authentication processing time")
            .register(meterRegistry);
        
        // Initialize gauges
        this.activeSessions = new AtomicLong(0);
        this.blockedIPs = new AtomicLong(0);
        this.lockedAccounts = new AtomicLong(0);
        this.highRiskUsers = new AtomicLong(0);
        
        Gauge.builder("security.sessions.active", activeSessions, AtomicLong::get)
            .description("Number of active user sessions")
            .register(meterRegistry);
            
        Gauge.builder("security.ips.blocked", blockedIPs, AtomicLong::get)
            .description("Number of blocked IP addresses")
            .register(meterRegistry);
            
        Gauge.builder("security.accounts.locked", lockedAccounts, AtomicLong::get)
            .description("Number of locked accounts")
            .register(meterRegistry);
            
        Gauge.builder("security.users.high_risk", highRiskUsers, AtomicLong::get)
            .description("Number of high-risk users")
            .register(meterRegistry);
        
        // Risk score distribution
        this.riskScoreDistribution = new ConcurrentHashMap<>();
        initializeRiskScoreBuckets();
        
        // Attack pattern tracking
        this.sequentialProbingEvents = new AtomicLong(0);
        this.distributedAttackEvents = new AtomicLong(0);
        this.crossTenantAttempts = new AtomicLong(0);
        
        Gauge.builder("security.attack.sequential_probing", sequentialProbingEvents, AtomicLong::get)
            .description("Sequential probing events detected")
            .register(meterRegistry);
            
        Gauge.builder("security.attack.distributed", distributedAttackEvents, AtomicLong::get)
            .description("Distributed attack events detected")
            .register(meterRegistry);
            
        Gauge.builder("security.attack.cross_tenant", crossTenantAttempts, AtomicLong::get)
            .description("Cross-tenant access attempts")
            .register(meterRegistry);
    }

    /**
     * Record successful access
     */
    public void recordAccessGranted(String resourceType, String userId) {
        accessGrantedCounter.increment();
    }

    /**
     * Record denied access
     */
    public void recordAccessDenied(String resourceType, String userId, String reason) {
        accessDeniedCounter.increment();
    }

    /**
     * Record security incident
     */
    public void recordSecurityIncident(String incidentType, int severity, String userId) {
        securityIncidentCounter.increment();
        
        if (severity > 70) {
            recordHighSeverityAlert(incidentType, severity);
        }
    }

    /**
     * Record authorization decision time
     */
    public void recordAuthorizationTime(Duration duration, String result) {
        authorizationTimer.record(duration);
        
        // Additional metric for authorization result
        Counter.builder("security.authorization.decisions")
            .tag("result", result)
            .register(meterRegistry)
            .increment();
    }

    /**
     * Record request processing time
     */
    public void recordRequestTime(Duration duration, String endpoint, String result) {
        requestTimer.record(duration);
        
        Counter.builder("security.requests")
            .tag("endpoint", endpoint)
            .tag("result", result)
            .register(meterRegistry)
            .increment();
    }

    /**
     * Record authentication attempt
     */
    public void recordAuthenticationAttempt(String result, String method) {
        authenticationTimer.record(() -> {
            // Simulate authentication processing
            return 1;
        });
        
        Counter.builder("security.authentication.attempts")
            .tag("result", result)
            .tag("method", method)
            .register(meterRegistry)
            .increment();
    }

    /**
     * Record attack attempt
     */
    public void recordAttackAttempt(String attackType, String sourceIP, String userId) {
        switch (attackType) {
            case "BRUTE_FORCE":
                bruteForceAttemptCounter.increment();
                break;
            case "IDOR":
                idorAttemptCounter.increment();
                break;
            case "TOKEN_REUSE":
                tokenReuseCounter.increment();
                break;
        }
    }

    /**
     * Record rate limit violation
     */
    public void recordRateLimitExceeded(String limitType, String sourceIP, String userId) {
        rateLimitExceededCounter.increment();
    }

    /**
     * Record risk score
     */
    public void recordRiskScore(int score, String userId) {
        String bucket = getRiskScoreBucket(score);
        riskScoreDistribution.computeIfAbsent(bucket, k -> new AtomicLong(0)).incrementAndGet();
        
        // Track high-risk users
        if (score > 80) {
            highRiskUsers.incrementAndGet();
        }
    }

    /**
     * Update active sessions count
     */
    public void updateActiveSessions(int count) {
        activeSessions.set(count);
    }

    /**
     * Update blocked IPs count
     */
    public void updateBlockedIPs(int count) {
        blockedIPs.set(count);
    }

    /**
     * Update locked accounts count
     */
    public void updateLockedAccounts(int count) {
        lockedAccounts.set(count);
    }

    /**
     * Record attack pattern detection
     */
    public void recordAttackPattern(String patternType, String sourceIP) {
        switch (patternType) {
            case "SEQUENTIAL_PROBING":
                sequentialProbingEvents.incrementAndGet();
                break;
            case "DISTRIBUTED_ATTACK":
                distributedAttackEvents.incrementAndGet();
                break;
            case "CROSS_TENANT":
                crossTenantAttempts.incrementAndGet();
                break;
        }
        
        // Create alert for serious patterns
        if (patternType.equals("DISTRIBUTED_ATTACK")) {
            createSecurityAlert("DISTRIBUTED_ATTACK_DETECTED", 
                "Distributed attack pattern detected from IP: " + sourceIP, 85);
        }
    }

    /**
     * Get comprehensive security metrics
     */
    public SecurityMetrics getSecurityMetrics() {
        return SecurityMetrics.builder()
            .totalAccessGranted(accessGrantedCounter.count())
            .totalAccessDenied(accessDeniedCounter.count())
            .totalSecurityIncidents(securityIncidentCounter.count())
            .totalBruteForceAttempts(bruteForceAttemptCounter.count())
            .totalIdorAttempts(idorAttemptCounter.count())
            .totalTokenReuseAttempts(tokenReuseCounter.count())
            .totalRateLimitViolations(rateLimitExceededCounter.count())
            .activeSessions(activeSessions.get())
            .blockedIPs(blockedIPs.get())
            .lockedAccounts(lockedAccounts.get())
            .highRiskUsers(highRiskUsers.get())
            .averageAuthorizationTime(authorizationTimer.mean(java.util.concurrent.TimeUnit.MILLISECONDS))
            .averageRequestTime(requestTimer.mean(java.util.concurrent.TimeUnit.MILLISECONDS))
            .averageAuthenticationTime(authenticationTimer.mean(java.util.concurrent.TimeUnit.MILLISECONDS))
            .sequentialProbingEvents(sequentialProbingEvents.get())
            .distributedAttackEvents(distributedAttackEvents.get())
            .crossTenantAttempts(crossTenantAttempts.get())
            .riskScoreDistribution(getRiskScoreDistribution())
            .timestamp(LocalDateTime.now())
            .build();
    }

    /**
     * Create security alert for critical events
     */
    private void createSecurityAlert(String alertType, String message, int severity) {
        // In production, would integrate with alerting system (PagerDuty, Slack, etc.)
        System.out.println(String.format("SECURITY ALERT [%s]: %s (Severity: %d)", alertType, message, severity));
        
        // Also record as incident
        recordSecurityIncident(alertType, severity, null);
    }

    /**
     * Record high severity alert
     */
    private void recordHighSeverityAlert(String incidentType, int severity) {
        Counter.builder("security.alerts.high_severity")
            .tag("type", incidentType)
            .tag("severity", String.valueOf(severity))
            .register(meterRegistry)
            .increment();
    }

    /**
     * Initialize risk score buckets
     */
    private void initializeRiskScoreBuckets() {
        riskScoreDistribution.put("0-20", new AtomicLong(0));
        riskScoreDistribution.put("21-40", new AtomicLong(0));
        riskScoreDistribution.put("41-60", new AtomicLong(0));
        riskScoreDistribution.put("61-80", new AtomicLong(0));
        riskScoreDistribution.put("81-100", new AtomicLong(0));
    }

    /**
     * Get risk score bucket
     */
    private String getRiskScoreBucket(int score) {
        if (score <= 20) return "0-20";
        if (score <= 40) return "21-40";
        if (score <= 60) return "41-60";
        if (score <= 80) return "61-80";
        return "81-100";
    }

    /**
     * Get risk score distribution
     */
    private java.util.Map<String, Long> getRiskScoreDistribution() {
        return riskScoreDistribution.entrySet().stream()
            .collect(java.util.stream.Collectors.toMap(
                java.util.Map.Entry::getKey,
                entry -> entry.getValue().get()
            ));
    }

    /**
     * Security metrics data structure
     */
    public static class SecurityMetrics {
        private final double totalAccessGranted;
        private final double totalAccessDenied;
        private final double totalSecurityIncidents;
        private final double totalBruteForceAttempts;
        private final double totalIdorAttempts;
        private final double totalTokenReuseAttempts;
        private final double totalRateLimitViolations;
        private final long activeSessions;
        private final long blockedIPs;
        private final long lockedAccounts;
        private final long highRiskUsers;
        private final double averageAuthorizationTime;
        private final double averageRequestTime;
        private final double averageAuthenticationTime;
        private final long sequentialProbingEvents;
        private final long distributedAttackEvents;
        private final long crossTenantAttempts;
        private final java.util.Map<String, Long> riskScoreDistribution;
        private final LocalDateTime timestamp;

        private SecurityMetrics(Builder builder) {
            this.totalAccessGranted = builder.totalAccessGranted;
            this.totalAccessDenied = builder.totalAccessDenied;
            this.totalSecurityIncidents = builder.totalSecurityIncidents;
            this.totalBruteForceAttempts = builder.totalBruteForceAttempts;
            this.totalIdorAttempts = builder.totalIdorAttempts;
            this.totalTokenReuseAttempts = builder.totalTokenReuseAttempts;
            this.totalRateLimitViolations = builder.totalRateLimitViolations;
            this.activeSessions = builder.activeSessions;
            this.blockedIPs = builder.blockedIPs;
            this.lockedAccounts = builder.lockedAccounts;
            this.highRiskUsers = builder.highRiskUsers;
            this.averageAuthorizationTime = builder.averageAuthorizationTime;
            this.averageRequestTime = builder.averageRequestTime;
            this.averageAuthenticationTime = builder.averageAuthenticationTime;
            this.sequentialProbingEvents = builder.sequentialProbingEvents;
            this.distributedAttackEvents = builder.distributedAttackEvents;
            this.crossTenantAttempts = builder.crossTenantAttempts;
            this.riskScoreDistribution = builder.riskScoreDistribution;
            this.timestamp = builder.timestamp;
        }

        public static Builder builder() {
            return new Builder();
        }

        // Getters
        public double totalAccessGranted() { return totalAccessGranted; }
        public double totalAccessDenied() { return totalAccessDenied; }
        public double totalSecurityIncidents() { return totalSecurityIncidents; }
        public double totalBruteForceAttempts() { return totalBruteForceAttempts; }
        public double totalIdorAttempts() { return totalIdorAttempts; }
        public double totalTokenReuseAttempts() { return totalTokenReuseAttempts; }
        public double totalRateLimitViolations() { return totalRateLimitViolations; }
        public long activeSessions() { return activeSessions; }
        public long blockedIPs() { return blockedIPs; }
        public long lockedAccounts() { return lockedAccounts; }
        public long highRiskUsers() { return highRiskUsers; }
        public double averageAuthorizationTime() { return averageAuthorizationTime; }
        public double averageRequestTime() { return averageRequestTime; }
        public double averageAuthenticationTime() { return averageAuthenticationTime; }
        public long sequentialProbingEvents() { return sequentialProbingEvents; }
        public long distributedAttackEvents() { return distributedAttackEvents; }
        public long crossTenantAttempts() { return crossTenantAttempts; }
        public java.util.Map<String, Long> riskScoreDistribution() { return riskScoreDistribution; }
        public LocalDateTime timestamp() { return timestamp; }

        public static class Builder {
            private double totalAccessGranted;
            private double totalAccessDenied;
            private double totalSecurityIncidents;
            private double totalBruteForceAttempts;
            private double totalIdorAttempts;
            private double totalTokenReuseAttempts;
            private double totalRateLimitViolations;
            private long activeSessions;
            private long blockedIPs;
            private long lockedAccounts;
            private long highRiskUsers;
            private double averageAuthorizationTime;
            private double averageRequestTime;
            private double averageAuthenticationTime;
            private long sequentialProbingEvents;
            private long distributedAttackEvents;
            private long crossTenantAttempts;
            private java.util.Map<String, Long> riskScoreDistribution;
            private LocalDateTime timestamp;

            public Builder totalAccessGranted(double totalAccessGranted) { this.totalAccessGranted = totalAccessGranted; return this; }
            public Builder totalAccessDenied(double totalAccessDenied) { this.totalAccessDenied = totalAccessDenied; return this; }
            public Builder totalSecurityIncidents(double totalSecurityIncidents) { this.totalSecurityIncidents = totalSecurityIncidents; return this; }
            public Builder totalBruteForceAttempts(double totalBruteForceAttempts) { this.totalBruteForceAttempts = totalBruteForceAttempts; return this; }
            public Builder totalIdorAttempts(double totalIdorAttempts) { this.totalIdorAttempts = totalIdorAttempts; return this; }
            public Builder totalTokenReuseAttempts(double totalTokenReuseAttempts) { this.totalTokenReuseAttempts = totalTokenReuseAttempts; return this; }
            public Builder totalRateLimitViolations(double totalRateLimitViolations) { this.totalRateLimitViolations = totalRateLimitViolations; return this; }
            public Builder activeSessions(long activeSessions) { this.activeSessions = activeSessions; return this; }
            public Builder blockedIPs(long blockedIPs) { this.blockedIPs = blockedIPs; return this; }
            public Builder lockedAccounts(long lockedAccounts) { this.lockedAccounts = lockedAccounts; return this; }
            public Builder highRiskUsers(long highRiskUsers) { this.highRiskUsers = highRiskUsers; return this; }
            public Builder averageAuthorizationTime(double averageAuthorizationTime) { this.averageAuthorizationTime = averageAuthorizationTime; return this; }
            public Builder averageRequestTime(double averageRequestTime) { this.averageRequestTime = averageRequestTime; return this; }
            public Builder averageAuthenticationTime(double averageAuthenticationTime) { this.averageAuthenticationTime = averageAuthenticationTime; return this; }
            public Builder sequentialProbingEvents(long sequentialProbingEvents) { this.sequentialProbingEvents = sequentialProbingEvents; return this; }
            public Builder distributedAttackEvents(long distributedAttackEvents) { this.distributedAttackEvents = distributedAttackEvents; return this; }
            public Builder crossTenantAttempts(long crossTenantAttempts) { this.crossTenantAttempts = crossTenantAttempts; return this; }
            public Builder riskScoreDistribution(java.util.Map<String, Long> riskScoreDistribution) { this.riskScoreDistribution = riskScoreDistribution; return this; }
            public Builder timestamp(LocalDateTime timestamp) { this.timestamp = timestamp; return this; }

            public SecurityMetrics build() {
                return new SecurityMetrics(this);
            }
        }
    }
}
