package com.example.bola_security.middleware;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.LongAdder;

/**
 * STEP 6: Security Logging and Monitoring Service
 * 
 * Logs every request and security event. Maintains counters and
 * recent event history for the dashboard.
 * 
 * VIVA NOTE: This service provides audit trails for security events.
 * In production, you'd persist these to a database or send to a SIEM.
 * Here we use in-memory storage for simplicity and demo purposes.
 */
@Service
public class SecurityLogService {

    private static final Logger log = LoggerFactory.getLogger(SecurityLogService.class);

    // Counters
    private final LongAdder totalRequests = new LongAdder();
    private final LongAdder blockedAttacks = new LongAdder();
    private final LongAdder allowedRequests = new LongAdder();
    private final LongAdder rateLimitedRequests = new LongAdder();

    // Recent events (keep last 50)
    private final List<SecurityEvent> recentEvents = new ArrayList<>();
    private static final int MAX_EVENTS = 50;

    // Per-user attack tracking
    private final ConcurrentHashMap<Long, AtomicLong> userAttackCounts = new ConcurrentHashMap<>();

    /**
     * Log a request that passed BOLA authorization and reached the backend.
     */
    public void logAllowedRequest(Long userId, Long resourceId, String endpoint) {
        totalRequests.increment();
        allowedRequests.increment();

        log.info("REQUEST_ALLOWED userId={} endpoint={} resourceId={} timestamp={}",
                userId, endpoint, resourceId, Instant.now());

        addEvent("ACCESS_ALLOWED", userId, resourceId, endpoint, "ALLOWED");
    }

    /**
     * Backward-compatible name for older callers.
     */
    public void logAccessRequest(Long userId, Long resourceId, String endpoint) {
        logAllowedRequest(userId, resourceId, endpoint);
    }

    /**
     * Log a BOLA attack attempt.
     */
    public void logBolaAttack(Long userId, Long resourceId, String endpoint) {
        totalRequests.increment();
        blockedAttacks.increment();

        userAttackCounts.computeIfAbsent(userId, k -> new AtomicLong(0)).incrementAndGet();

        log.warn("BOLA_ATTACK_BLOCKED userId={} attemptedResourceId={} endpoint={} timestamp={}",
                userId, resourceId, endpoint, Instant.now());

        addEvent("BOLA_ATTACK", userId, resourceId, endpoint, "BLOCKED");
    }

    /**
     * Log a rate limit event.
     */
    public void logRateLimitEvent(Long userId, String endpoint) {
        totalRequests.increment();
        rateLimitedRequests.increment();

        log.warn("RATE_LIMIT_BLOCKED userId={} endpoint={} timestamp={}", userId, endpoint, Instant.now());

        addEvent("RATE_LIMITED", userId, null, endpoint, "BLOCKED");
    }

    /**
     * Get dashboard statistics.
     */
    public Map<String, Object> getStatistics() {
        return Map.of(
            "totalRequests", totalRequests.sum(),
            "allowedRequests", allowedRequests.sum(),
            "blockedAttacks", blockedAttacks.sum(),
            "rateLimitedRequests", rateLimitedRequests.sum(),
            "activeAttackers", userAttackCounts.size()
        );
    }

    /**
     * Get recent security events for the dashboard.
     */
    public List<SecurityEvent> getRecentEvents() {
        synchronized (recentEvents) {
            return List.copyOf(recentEvents);
        }
    }

    /**
     * Get per-user attack counts.
     */
    public Map<Long, Long> getUserAttackCounts() {
        Map<Long, Long> result = new ConcurrentHashMap<>();
        userAttackCounts.forEach((userId, count) -> result.put(userId, count.get()));
        return result;
    }

    public void reset() {
        totalRequests.reset();
        blockedAttacks.reset();
        allowedRequests.reset();
        rateLimitedRequests.reset();
        userAttackCounts.clear();
        synchronized (recentEvents) {
            recentEvents.clear();
        }
    }

    private void addEvent(String type, Long userId, Long resourceId, String endpoint, String status) {
        synchronized (recentEvents) {
            recentEvents.add(new SecurityEvent(
                Instant.now().toString(), type, userId, resourceId, endpoint, status
            ));
            // Keep only last MAX_EVENTS
            while (recentEvents.size() > MAX_EVENTS) {
                recentEvents.remove(0);
            }
        }
    }

    /**
     * Security event record for logging and dashboard display.
     */
    public record SecurityEvent(
        String timestamp,
        String type,
        Long userId,
        Long resourceId,
        String endpoint,
        String status
    ) {}
}
