package com.example.bola_security.service;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.support.StaticListableBeanFactory;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;

import static com.example.bola_security.TestSecurityProperties.properties;
import static org.assertj.core.api.Assertions.assertThat;

class BehavioralAnalysisServiceTest {

    @Test
    void flagsSequentialResourceProbing() {
        BehavioralAnalysisService service = new BehavioralAnalysisService(
                new StaticListableBeanFactory().getBeanProvider(org.springframework.data.redis.core.StringRedisTemplate.class),
                properties(5, 10, false, false, false, 9, 18, true, 80, 5),
                Clock.fixed(Instant.parse("2026-05-02T10:15:30Z"), ZoneOffset.UTC)
        );

        service.inspect(1L, 101L);
        service.inspect(1L, 102L);
        BehavioralAnalysisResult result = service.inspect(1L, 103L);

        assertThat(result.sequentialProbingLikely()).isTrue();
        assertThat(result.sequentialRunLength()).isEqualTo(3);
    }

    @Test
    void countsDistinctIdsForEnumerationDetection() {
        BehavioralAnalysisService service = new BehavioralAnalysisService(
                new StaticListableBeanFactory().getBeanProvider(org.springframework.data.redis.core.StringRedisTemplate.class),
                properties(3, 10, false, false, false, 9, 18, true, 80, 5),
                Clock.fixed(Instant.parse("2026-05-02T10:15:30Z"), ZoneOffset.UTC)
        );

        service.inspect(1L, 200L);
        service.inspect(1L, 201L);
        BehavioralAnalysisResult result = service.inspect(1L, 202L);

        assertThat(result.enumerationLikely()).isTrue();
        assertThat(result.recentDistinctResourceCount()).isEqualTo(3);
    }
}
