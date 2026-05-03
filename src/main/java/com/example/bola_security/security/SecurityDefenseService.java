package com.example.bola_security.security;

import com.example.bola_security.model.User;
import com.example.bola_security.repository.UserRepository;
import com.example.bola_security.service.SecurityIncidentService;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Active security defense system with rate limiting and brute force protection.
 * Implements automated threat detection and response.
 */
@Service
public class SecurityDefenseService {

    private final UserRepository userRepository;
    private final SecurityIncidentService securityIncidentService;
    
    // Rate limiting stores
    private final ConcurrentHashMap<String, RateLimitInfo> ipRateLimits = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<Long, RateLimitInfo> userRateLimits = new ConcurrentHashMap<>();
    
    // Brute force protection
    private final ConcurrentHashMap<String, FailedLoginInfo> failedLogins = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<Long, FailedAccessInfo> failedAccesses = new ConcurrentHashMap<>();

    public SecurityDefenseService(UserRepository userRepository, SecurityIncidentService securityIncidentService) {
        this.userRepository = userRepository;
        this.securityIncidentService = securityIncidentService;
    }

    /**
     * Check if IP is rate limited for API requests
     */
    public boolean isIpRateLimited(String ipAddress) {
        RateLimitInfo rateLimit = ipRateLimits.computeIfAbsent(ipAddress, k -> new RateLimitInfo());
        
        return rateLimit.checkAndIncrement(100, 60); // 100 requests per minute per IP
    }

    /**
     * Check if user is rate limited for API requests
     */
    public boolean isUserRateLimited(Long userId) {
        RateLimitInfo rateLimit = userRateLimits.computeIfAbsent(userId, k -> new RateLimitInfo());
        
        return rateLimit.checkAndIncrement(50, 60); // 50 requests per minute per user
    }

    /**
     * Check if IP is rate limited for login attempts
     */
    public boolean isLoginRateLimited(String ipAddress) {
        RateLimitInfo rateLimit = ipRateLimits.computeIfAbsent("LOGIN:" + ipAddress, k -> new RateLimitInfo());
        
        return rateLimit.checkAndIncrement(5, 300); // 5 login attempts per 5 minutes per IP
    }

    /**
     * Record failed login attempt
     */
    public void recordFailedLogin(String username, String ipAddress, String userAgent) {
        FailedLoginInfo failedLogin = failedLogins.computeIfAbsent(ipAddress, k -> new FailedLoginInfo());
        failedLogin.increment(username, userAgent);
        
        // Check for brute force patterns
        if (failedLogin.getAttemptCount() >= 5) {
            handleBruteForceAttack(ipAddress, username, failedLogin);
        }
        
        // Check for distributed brute force (same username from multiple IPs)
        checkDistributedBruteForce(username, ipAddress);
    }

    /**
     * Record successful login (reset failed login counter)
     */
    public void recordSuccessfulLogin(String username, String ipAddress) {
        failedLogins.remove(ipAddress);
        
        // Reset user account lockout if applicable
        User user = userRepository.findByUsername(username).orElse(null);
        if (user != null && user.isAccountLocked()) {
            // Auto-unlock after successful login (if not security incident)
            user.setAccountLocked(false);
            user.setFailedBolaAttempts(0);
            userRepository.save(user);
        }
    }

    /**
     * Record failed resource access attempt
     */
    public void recordFailedAccess(Long userId, Long resourceId, String ipAddress, String reason) {
        FailedAccessInfo failedAccess = failedAccesses.computeIfAbsent(userId, k -> new FailedAccessInfo());
        failedAccess.increment(resourceId, ipAddress, reason);
        
        // Check for suspicious patterns
        if (failedAccess.getAttemptCount() >= 10) {
            handleSuspiciousAccessPattern(userId, failedAccess);
        }
    }

    /**
     * Check if user account should be locked due to failed attempts
     */
    public boolean shouldLockAccount(Long userId) {
        FailedAccessInfo failedAccess = failedAccesses.get(userId);
        return failedAccess != null && failedAccess.getAttemptCount() >= 10;
    }

    /**
     * Lock user account for security reasons
     */
    public void lockUserAccount(Long userId, String reason) {
        User user = userRepository.findById(userId).orElse(null);
        if (user != null) {
            user.setAccountLocked(true);
            userRepository.save(user);
            
            // Log security incident
            securityIncidentService.reportSecurityIncident(
                userId, user.getUsername(), null, "ACCOUNT_LOCKED", 
                "Account locked due to suspicious activity: " + reason, 90
            );
        }
    }

    /**
     * Block IP address temporarily
     */
    public void blockIpAddress(String ipAddress, String reason, int durationMinutes) {
        RateLimitInfo rateLimit = ipRateLimits.computeIfAbsent("BLOCKED:" + ipAddress, k -> new RateLimitInfo());
        rateLimit.block(durationMinutes);
        
        // Log security incident
        securityIncidentService.reportSecurityIncident(
            null, "SYSTEM", null, "IP_BLOCKED", 
            "IP blocked: " + reason, 80
        );
    }

    /**
     * Handle brute force attack detection
     */
    private void handleBruteForceAttack(String ipAddress, String username, FailedLoginInfo failedLogin) {
        // Block the IP
        blockIpAddress(ipAddress, "Brute force attack detected", 60);
        
        // Log security incident
        securityIncidentService.reportSecurityIncident(
            null, username, null, "BRUTE_FORCE_ATTACK", 
            "Brute force attack from IP: " + ipAddress + " - Attempts: " + failedLogin.getAttemptCount(), 95
        );
        
        // Consider locking the target account if attempts are concentrated
        if (failedLogin.getTargetUserCount() == 1) {
            User user = userRepository.findByUsername(username).orElse(null);
            if (user != null) {
                lockUserAccount(user.getId(), "Brute force attack target");
            }
        }
    }

    /**
     * Check for distributed brute force (same username from multiple IPs)
     */
    private void checkDistributedBruteForce(String username, String currentIp) {
        int ipCount = 0;
        for (FailedLoginInfo failedLogin : failedLogins.values()) {
            if (failedLogin.hasTargetUser(username) && !failedLogin.getIpAddress().equals(currentIp)) {
                ipCount++;
            }
        }
        
        if (ipCount >= 3) {
            // Multiple IPs trying same username - distributed brute force
            User user = userRepository.findByUsername(username).orElse(null);
            if (user != null) {
                lockUserAccount(user.getId(), "Distributed brute force attack");
                
                securityIncidentService.reportSecurityIncident(
                    user.getId(), username, null, "DISTRIBUTED_BRUTE_FORCE", 
                    "Distributed brute force attack from " + ipCount + " IPs", 95
                );
            }
        }
    }

    /**
     * Handle suspicious access patterns
     */
    private void handleSuspiciousAccessPattern(Long userId, FailedAccessInfo failedAccess) {
        // Lock user account temporarily
        lockUserAccount(userId, "Excessive failed access attempts: " + failedAccess.getAttemptCount());
        
        // Check for IDOR attack pattern
        if (failedAccess.isSequentialProbing()) {
            securityIncidentService.reportSecurityIncident(
                userId, null, null, "IDOR_ATTACK_DETECTED", 
                "Sequential resource probing detected - possible IDOR attack", 95
            );
        }
    }

    /**
     * Clean up old rate limiting and failed attempt data
     */
    public void cleanupOldData() {
        LocalDateTime cutoff = LocalDateTime.now().minusHours(24);
        
        // Clean up old rate limits
        ipRateLimits.entrySet().removeIf(entry -> entry.getValue().isExpired(cutoff));
        userRateLimits.entrySet().removeIf(entry -> entry.getValue().isExpired(cutoff));
        
        // Clean up old failed login attempts
        failedLogins.entrySet().removeIf(entry -> entry.getValue().isExpired(cutoff));
        failedAccesses.entrySet().removeIf(entry -> entry.getValue().isExpired(cutoff));
    }

    /**
     * Rate limiting information
     */
    private static class RateLimitInfo {
        private AtomicInteger requestCount = new AtomicInteger(0);
        private LocalDateTime windowStart = LocalDateTime.now();
        private LocalDateTime blockEnd = null;

        public boolean checkAndIncrement(int maxRequests, int windowSeconds) {
            // Check if blocked
            if (blockEnd != null && LocalDateTime.now().isBefore(blockEnd)) {
                return true; // Still blocked
            }
            
            // Reset window if expired
            if (LocalDateTime.now().isAfter(windowStart.plusSeconds(windowSeconds))) {
                requestCount.set(0);
                windowStart = LocalDateTime.now();
            }
            
            // Check limit
            if (requestCount.get() >= maxRequests) {
                return true; // Rate limited
            }
            
            requestCount.incrementAndGet();
            return false; // Not rate limited
        }

        public void block(int durationMinutes) {
            this.blockEnd = LocalDateTime.now().plusMinutes(durationMinutes);
        }

        public boolean isExpired(LocalDateTime cutoff) {
            return windowStart.isBefore(cutoff) && 
                   (blockEnd == null || blockEnd.isBefore(cutoff));
        }
    }

    /**
     * Failed login information
     */
    private static class FailedLoginInfo {
        private AtomicInteger attemptCount = new AtomicInteger(0);
        private LocalDateTime firstAttempt = LocalDateTime.now();
        private String lastUsername;
        private String lastUserAgent;
        private String ipAddress;
        private java.util.Set<String> targetUsers = new java.util.HashSet<>();

        public void increment(String username, String userAgent) {
            attemptCount.incrementAndGet();
            lastUsername = username;
            lastUserAgent = userAgent;
            targetUsers.add(username);
        }

        public int getAttemptCount() { return attemptCount.get(); }
        public int getTargetUserCount() { return targetUsers.size(); }
        public String getIpAddress() { return ipAddress; }
        public void setIpAddress(String ipAddress) { this.ipAddress = ipAddress; }
        public boolean hasTargetUser(String username) { return targetUsers.contains(username); }
        public boolean isExpired(LocalDateTime cutoff) { return firstAttempt.isBefore(cutoff); }
    }

    /**
     * Failed access information
     */
    private static class FailedAccessInfo {
        private AtomicInteger attemptCount = new AtomicInteger(0);
        private LocalDateTime firstAttempt = LocalDateTime.now();
        private java.util.List<Long> attemptedResources = new java.util.ArrayList<>();
        private java.util.Set<String> ipAddresses = new java.util.HashSet<>();

        public void increment(Long resourceId, String ipAddress, String reason) {
            attemptCount.incrementAndGet();
            attemptedResources.add(resourceId);
            ipAddresses.add(ipAddress);
        }

        public int getAttemptCount() { return attemptCount.get(); }
        public boolean isSequentialProbing() {
            if (attemptedResources.size() < 5) return false;
            
            // Check if resources are sequential (possible IDOR)
            java.util.List<Long> sorted = new java.util.ArrayList<>(attemptedResources);
            java.util.Collections.sort(sorted);
            
            int sequentialCount = 1;
            for (int i = 1; i < sorted.size(); i++) {
                if (sorted.get(i) == sorted.get(i-1) + 1) {
                    sequentialCount++;
                    if (sequentialCount >= 5) return true;
                } else {
                    sequentialCount = 1;
                }
            }
            return false;
        }
        public boolean isExpired(LocalDateTime cutoff) { return firstAttempt.isBefore(cutoff); }
    }
}
