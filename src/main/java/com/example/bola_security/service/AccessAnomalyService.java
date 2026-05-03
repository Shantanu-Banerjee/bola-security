package com.example.bola_security.service;

import com.example.bola_security.config.BolaSecurityProperties;
import com.example.bola_security.repository.AccessLogRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.time.Clock;
import java.time.LocalDateTime;

@Service
public class AccessAnomalyService {

    private static final Logger log = LoggerFactory.getLogger(AccessAnomalyService.class);

    private final AccessLogRepository accessLogRepository;
    private final BolaSecurityProperties properties;
    private final Clock clock;

    public AccessAnomalyService(AccessLogRepository accessLogRepository, BolaSecurityProperties properties, Clock clock) {
        this.accessLogRepository = accessLogRepository;
        this.properties = properties;
        this.clock = clock;
    }

    public boolean isEnumerationLikely(Long userId) {
        boolean likely = recentDistinctResourceCount(userId) >= properties.enumerationThreshold();
        if (likely) {
            log.warn("Enumeration likely detected for userId={}", userId);
        }
        return likely;
    }

    public long recentDistinctResourceCount(Long userId) {
        LocalDateTime windowStart = LocalDateTime.now(clock).minusSeconds(properties.enumerationWindowSeconds());
        return accessLogRepository.countDistinctResourceIdsSince(userId, windowStart);
    }
}
