package com.example.bola_security.middleware;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.util.LinkedList;
import java.util.concurrent.ConcurrentHashMap;

/**
 * STEP 5: Simple Rate Limiting Service
 * 
 * Limits each user to a maximum number of requests per time window.
 * Default: 5 requests per 60 seconds per user.
 * 
 * VIVA NOTE: Rate limiting prevents brute-force attacks where an attacker
 * tries to enumerate through many user IDs quickly. If a user makes
 * more than 5 requests per minute, they get HTTP 429.
 * 
 * Implementation uses a sliding window: we track the timestamp of each
 * request and count how many fall within the last 60 seconds.
 */
@Service
public class RateLimitService {

    private static final Logger log = LoggerFactory.getLogger(RateLimitService.class);

    private static final int MAX_REQUESTS_PER_WINDOW = 5;
    private static final long WINDOW_SIZE_MS = 60_000; // 1 minute

    // Tracks request timestamps per user: userId -> list of request timestamps.
    private final ConcurrentHashMap<Long, LinkedList<Long>> requestTimestamps = new ConcurrentHashMap<>();

    /**
     * Check if a request from this user is allowed.
     * Returns true if under the rate limit, false if exceeded.
     */
    public boolean isAllowed(Long userId) {
        long now = System.currentTimeMillis();
        LinkedList<Long> timestamps = requestTimestamps.computeIfAbsent(userId, k -> new LinkedList<>());

        synchronized (timestamps) {
            timestamps.removeIf(ts -> ts < now - WINDOW_SIZE_MS);

            if (timestamps.size() >= MAX_REQUESTS_PER_WINDOW) {
                log.warn("RATE_LIMIT_BLOCKED userId={} maxRequests={} windowSeconds={}",
                        userId, MAX_REQUESTS_PER_WINDOW, getWindowSizeSeconds());
                return false;
            }

            timestamps.addLast(now);
            return true;
        }
    }

    /**
     * Get current request count for a user in the current window.
     */
    public int getCurrentRequestCount(Long userId) {
        long now = System.currentTimeMillis();
        LinkedList<Long> timestamps = requestTimestamps.get(userId);
        if (timestamps == null) return 0;
        synchronized (timestamps) {
            timestamps.removeIf(ts -> ts < now - WINDOW_SIZE_MS);
            return timestamps.size();
        }
    }

    public void reset() {
        requestTimestamps.clear();
    }

    /**
     * Get the max requests per window (for dashboard display).
     */
    public int getMaxRequestsPerWindow() {
        return MAX_REQUESTS_PER_WINDOW;
    }

    /**
     * Get the window size in seconds (for dashboard display).
     */
    public long getWindowSizeSeconds() {
        return WINDOW_SIZE_MS / 1000;
    }
}
