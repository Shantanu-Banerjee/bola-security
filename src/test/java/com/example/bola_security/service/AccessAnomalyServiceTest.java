package com.example.bola_security.service;

import com.example.bola_security.model.AccessLog;
import com.example.bola_security.repository.AccessLogRepository;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;

import java.time.Clock;
import java.time.LocalDateTime;

import static org.assertj.core.api.Assertions.assertThat;
import static com.example.bola_security.TestSecurityProperties.properties;

@DataJpaTest
class AccessAnomalyServiceTest {

    @Autowired
    private AccessLogRepository accessLogRepository;

    @Test
    void detectsEnumerationWhenDistinctResourceThresholdIsReached() {
        AccessAnomalyService service = new AccessAnomalyService(
                accessLogRepository,
                properties(3, 10, false, false, false, 9, 18, true, 80, 5),
                Clock.systemUTC()
        );

        saveLog(1L, 101L);
        saveLog(1L, 102L);
        saveLog(1L, 103L);

        assertThat(service.isEnumerationLikely(1L)).isTrue();
    }

    @Test
    void ignoresRepeatedAccessToSameResource() {
        AccessAnomalyService service = new AccessAnomalyService(
                accessLogRepository,
                properties(3, 10, false, false, false, 9, 18, true, 80, 5),
                Clock.systemUTC()
        );

        saveLog(1L, 101L);
        saveLog(1L, 101L);
        saveLog(1L, 101L);

        assertThat(service.isEnumerationLikely(1L)).isFalse();
    }

    private void saveLog(Long userId, Long resourceId) {
        AccessLog log = new AccessLog();
        log.setUserId(userId);
        log.setResourceId(resourceId);
        log.setResourceOwnerId(1L);
        log.setUsername("alice");
        log.setUserDepartment("Engineering");
        log.setResourceDepartment("Engineering");
        log.setUserRole("USER");
        log.setOwnerMatch(true);
        log.setSameDepartment(true);
        log.setIpAddress("127.0.0.1");
        log.setUserAgent("JUnit");
        log.setSessionId("test-session");
        log.setHttpMethod("GET");
        log.setRequestPath("/api/resources/" + resourceId);
        log.setAccessHour(LocalDateTime.now().getHour());
        log.setRecentDistinctResourceCount(0);
        log.setRiskScore(0);
        log.setResult("ALLOWED");
        log.setReason("TEST");
        log.setTimestamp(LocalDateTime.now());
        accessLogRepository.save(log);
    }
}
