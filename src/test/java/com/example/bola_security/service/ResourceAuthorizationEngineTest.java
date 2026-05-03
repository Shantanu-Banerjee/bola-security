package com.example.bola_security.service;

import com.example.bola_security.exception.BolaAccessDeniedException;
import com.example.bola_security.model.Resource;
import com.example.bola_security.model.Role;
import com.example.bola_security.model.User;
import com.example.bola_security.repository.ResourceRepository;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.junit.jupiter.api.extension.ExtendWith;

import java.time.LocalDateTime;
import java.util.Optional;

import static com.example.bola_security.TestSecurityProperties.properties;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class ResourceAuthorizationEngineTest {

    @Mock private ResourceRepository resourceRepository;
    @Mock private BehavioralAnalysisService behavioralAnalysisService;
    @Mock private AuditLogService auditLogService;
    @Mock private SecurityIncidentService securityIncidentService;

    private AuthorizationService authorizationService;
    private ResourceAuthorizationEngine engine;
    private User alice;
    private Resource aliceResource;

    @BeforeEach
    void setUp() {
        var props = properties(5, 10, true, false, false, 9, 18, true, 80, 5);
        authorizationService = new AuthorizationService(props, new AccessPolicyEngine(props));
        engine = new ResourceAuthorizationEngine(
                resourceRepository,
                authorizationService,
                behavioralAnalysisService,
                auditLogService,
                securityIncidentService,
                new SimpleMeterRegistry()
        );

        alice = new User();
        alice.setId(1L);
        alice.setUsername("alice");
        alice.setRole(Role.USER);
        alice.setTenantId("tenant-alpha");
        alice.setDepartment("Engineering");

        aliceResource = new Resource();
        aliceResource.setId(10L);
        aliceResource.setOwnerId(1L);
        aliceResource.setTenantId("tenant-alpha");
        aliceResource.setDepartment("Engineering");
        aliceResource.setName("Payroll");

        when(resourceRepository.findById(10L)).thenReturn(Optional.of(aliceResource));
        when(behavioralAnalysisService.inspect(1L, 10L)).thenReturn(new BehavioralAnalysisResult(false, false, 0, 0));
    }

    @Test
    void allowsSameTenantOwnerAccess() {
        AuthorizationOutcome outcome = engine.authorize(
                alice,
                10L,
                new RequestContext("127.0.0.1", "JUnit", "session", "GET", "/api/v1/resources/10", LocalDateTime.now())
        );

        assertThat(outcome.decision().allowed()).isTrue();
        assertThat(outcome.context().tenantMatch()).isTrue();
        verify(auditLogService).record(eq(alice), eq(aliceResource), any(), eq("ALLOWED"), eq("OWNER_MATCH"));
    }

    @Test
    void blocksCrossTenantAccessEvenForAdminScope() {
        alice.setRole(Role.ADMIN);
        aliceResource.setOwnerId(99L);
        aliceResource.setTenantId("tenant-beta");

        assertThatThrownBy(() -> engine.authorize(
                alice,
                10L,
                new RequestContext("127.0.0.1", "JUnit", "session", "GET", "/api/v1/resources/10", LocalDateTime.now())
        )).isInstanceOf(BolaAccessDeniedException.class)
                .hasMessage("TENANT_BOUNDARY_VIOLATION");

        verify(securityIncidentService).reportDeniedAccess(eq(alice), any(), eq("TENANT_BOUNDARY_VIOLATION"));
    }

    @Test
    void blocksSequentialProbingBeforePolicyDecision() {
        when(behavioralAnalysisService.inspect(1L, 10L)).thenReturn(new BehavioralAnalysisResult(false, true, 3, 3));

        assertThatThrownBy(() -> engine.authorize(
                alice,
                10L,
                new RequestContext("127.0.0.1", "JUnit", "session", "GET", "/api/v1/resources/10", LocalDateTime.now())
        )).isInstanceOf(BolaAccessDeniedException.class)
                .hasMessage("SEQUENTIAL_RESOURCE_PROBING_DETECTED");
    }
}
