package com.example.bola_security.service;

import com.example.bola_security.model.Resource;
import com.example.bola_security.model.Role;
import com.example.bola_security.model.User;
import com.example.bola_security.repository.SecurityIncidentRepository;
import com.example.bola_security.repository.UserRepository;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;

import java.time.Clock;
import java.time.LocalDateTime;

import static org.assertj.core.api.Assertions.assertThat;
import static com.example.bola_security.TestSecurityProperties.properties;
import static org.mockito.Mockito.mock;

@DataJpaTest
class SecurityIncidentServiceTest {

    @Autowired
    private SecurityIncidentRepository incidentRepository;

    @Autowired
    private UserRepository userRepository;

    @Test
    void locksUserAfterRepeatedDeniedBolaAttempts() {
        SecurityIncidentService service = new SecurityIncidentService(
                incidentRepository,
                userRepository,
                mock(SecurityAlertService.class),
                properties(5, 10, false, false, false, 9, 18, true, 80, 2),
                Clock.systemUTC()
        );
        User user = userRepository.save(user());
        Resource resource = resource();
        AccessContext context = AccessContext.from(
                user,
                resource,
                new RequestContext("127.0.0.1", "JUnit", "session", "GET", "/api/resources/99", LocalDateTime.now()),
                4
        );

        service.reportDeniedAccess(user, context, "OBJECT_LEVEL_AUTHORIZATION_FAILED");
        service.reportDeniedAccess(user, context, "OBJECT_LEVEL_AUTHORIZATION_FAILED");

        User updatedUser = userRepository.findById(user.getId()).orElseThrow();
        assertThat(updatedUser.isAccountLocked()).isTrue();
        assertThat(updatedUser.getFailedBolaAttempts()).isEqualTo(2);
        assertThat(incidentRepository.findAll()).hasSize(2);
    }

    private User user() {
        User user = new User();
        user.setUsername("attacker");
        user.setPassword("encoded");
        user.setRole(Role.USER);
        user.setTenantId("tenant-alpha");
        user.setDepartment("Engineering");
        return user;
    }

    private Resource resource() {
        Resource resource = new Resource();
        resource.setId(99L);
        resource.setName("Finance record");
        resource.setOwnerId(200L);
        resource.setTenantId("tenant-alpha");
        resource.setDepartment("Finance");
        return resource;
    }
}
