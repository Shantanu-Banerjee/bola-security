package com.example.bola_security.service;

import com.example.bola_security.config.BolaSecurityProperties;
import io.github.bucket4j.Bandwidth;
import io.github.bucket4j.Bucket;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.data.redis.RedisConnectionFailureException;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.concurrent.ConcurrentHashMap;

@Service
public class RateLimitingService {

    private static final Logger log = LoggerFactory.getLogger(RateLimitingService.class);

    private static final int API_CAPACITY = 20;
    private static final Duration API_WINDOW = Duration.ofSeconds(1);

    private static final int LOGIN_CAPACITY = 5;
    private static final Duration LOGIN_WINDOW = Duration.ofMinutes(1);

    private final ConcurrentHashMap<String, Bucket> apiBuckets = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, Bucket> loginBuckets = new ConcurrentHashMap<>();
    private final StringRedisTemplate redisTemplate;
    private final BolaSecurityProperties properties;
    private final Clock clock;

    public RateLimitingService(
            ObjectProvider<StringRedisTemplate> redisTemplate,
            BolaSecurityProperties properties,
            Clock clock
    ) {
        this.redisTemplate = redisTemplate.getIfAvailable();
        this.properties = properties;
        this.clock = clock;
    }

    public boolean allowApiRequest(String key) {
        return allow("api", key, API_CAPACITY, API_WINDOW, apiBuckets);
    }

    public boolean allowLoginRequest(String key) {
        return allow("login", key, LOGIN_CAPACITY, LOGIN_WINDOW, loginBuckets);
    }

    private boolean allow(
            String prefix,
            String key,
            int capacity,
            Duration window,
            ConcurrentHashMap<String, Bucket> localBuckets
    ) {
        if (properties.redisRateLimitingEnabled() && redisTemplate != null) {
            try {
                return allowRedis(prefix, key, capacity, window);
            } catch (RedisConnectionFailureException exception) {
                log.warn("Redis rate limiting unavailable; falling back to local bucket");
            }
        }
        Bucket bucket = localBuckets.computeIfAbsent(key, ignored -> createLocalBucket(capacity, window));
        return bucket.tryConsume(1);
    }

    private boolean allowRedis(String prefix, String key, int capacity, Duration window) {
        long windowId = Instant.now(clock).getEpochSecond() / window.toSeconds();
        String redisKey = "rate-limit:" + prefix + ":" + key + ":" + windowId;
        Long count = redisTemplate.opsForValue().increment(redisKey);
        if (count != null && count == 1L) {
            redisTemplate.expire(redisKey, window.plusSeconds(1));
        }
        return count != null && count <= capacity;
    }

    private Bucket createLocalBucket(int capacity, Duration window) {
        Bandwidth bandwidth = Bandwidth.builder()
                .capacity(capacity)
                .refillGreedy(capacity, window)
                .build();
        return Bucket.builder().addLimit(bandwidth).build();
    }
}
