package com.example.bola_security.service;

import com.example.bola_security.config.BolaSecurityProperties;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.data.redis.RedisConnectionFailureException;
import org.springframework.data.redis.core.ListOperations;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;

@Service
public class BehavioralAnalysisService {

    private static final Logger log = LoggerFactory.getLogger(BehavioralAnalysisService.class);

    private static final int MAX_TRACKED_EVENTS = 20;

    private final StringRedisTemplate redisTemplate;
    private final BolaSecurityProperties properties;
    private final Clock clock;
    private final ConcurrentHashMap<Long, ProbeWindow> localWindows = new ConcurrentHashMap<>();

    public BehavioralAnalysisService(
            ObjectProvider<StringRedisTemplate> redisTemplate,
            BolaSecurityProperties properties,
            Clock clock
    ) {
        this.redisTemplate = redisTemplate.getIfAvailable();
        this.properties = properties;
        this.clock = clock;
    }

    public BehavioralAnalysisResult inspect(Long userId, Long resourceId) {
        if (redisTemplate != null) {
            try {
                return inspectRedis(userId, resourceId);
            } catch (RedisConnectionFailureException exception) {
                log.warn("Redis behavior tracking unavailable; falling back to in-memory probe tracking");
            }
        }
        return inspectLocal(userId, resourceId);
    }

    private BehavioralAnalysisResult inspectRedis(Long userId, Long resourceId) {
        String key = "bola:behavior:" + userId;
        ListOperations<String, String> operations = redisTemplate.opsForList();
        operations.rightPush(key, resourceId.toString());
        Long size = operations.size(key);
        if (size != null && size > MAX_TRACKED_EVENTS) {
            operations.trim(key, size - MAX_TRACKED_EVENTS, -1);
        }
        redisTemplate.expire(key, Duration.ofSeconds(properties.enumerationWindowSeconds()));
        List<String> values = operations.range(key, 0, -1);
        List<Long> resourceIds = new ArrayList<>();
        if (values != null) {
            for (String value : values) {
                resourceIds.add(Long.parseLong(value));
            }
        }
        return analyze(resourceIds);
    }

    private BehavioralAnalysisResult inspectLocal(Long userId, Long resourceId) {
        Instant now = clock.instant();
        Instant cutoff = now.minusSeconds(properties.enumerationWindowSeconds());
        ProbeWindow probeWindow = localWindows.compute(userId, (ignored, existing) -> {
            ProbeWindow window = existing == null ? new ProbeWindow() : existing;
            window.prune(cutoff);
            window.record(resourceId, now);
            return window;
        });
        return analyze(probeWindow.snapshotResourceIds());
    }

    private BehavioralAnalysisResult analyze(List<Long> resourceIds) {
        long distinctCount = new LinkedHashSet<>(resourceIds).size();
        int sequentialRunLength = sequentialRunLength(resourceIds);
        boolean enumerationLikely = distinctCount >= properties.enumerationThreshold();
        boolean sequentialProbingLikely = sequentialRunLength >= properties.sequentialAccessThreshold();
        return new BehavioralAnalysisResult(
                enumerationLikely,
                sequentialProbingLikely,
                distinctCount,
                sequentialRunLength
        );
    }

    private int sequentialRunLength(List<Long> resourceIds) {
        if (resourceIds.isEmpty()) {
            return 0;
        }
        int longestRun = 1;
        int currentRun = 1;
        for (int index = 1; index < resourceIds.size(); index++) {
            long previous = resourceIds.get(index - 1);
            long current = resourceIds.get(index);
            if (current == previous + 1) {
                currentRun++;
            } else {
                currentRun = 1;
            }
            longestRun = Math.max(longestRun, currentRun);
        }
        return longestRun;
    }

    private static final class ProbeWindow {

        private final Deque<ProbeEvent> events = new ArrayDeque<>();

        void record(Long resourceId, Instant timestamp) {
            events.addLast(new ProbeEvent(resourceId, timestamp));
            while (events.size() > MAX_TRACKED_EVENTS) {
                events.removeFirst();
            }
        }

        void prune(Instant cutoff) {
            while (!events.isEmpty() && events.peekFirst().timestamp().isBefore(cutoff)) {
                events.removeFirst();
            }
        }

        List<Long> snapshotResourceIds() {
            return events.stream()
                    .map(ProbeEvent::resourceId)
                    .toList();
        }
    }

    private record ProbeEvent(Long resourceId, Instant timestamp) {
    }
}
