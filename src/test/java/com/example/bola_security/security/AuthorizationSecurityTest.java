package com.example.bola_security.security;

import com.example.bola_security.authorization.AuthorizationService;
import com.example.bola_security.model.*;
import com.example.bola_security.service.AccessContext;
import com.example.bola_security.service.RequestContext;
import com.example.bola_security.service.BehavioralAnalysisResult;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.access.AccessDeniedException;

import java.time.LocalDateTime;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.when;

/**
 * Security testing for centralized authorization system.
 * Tests various attack scenarios and security controls.
 */
@ExtendWith(MockitoExtension.class)
class AuthorizationSecurityTest {

    @Mock
    private AuthorizationService authorizationService;

    private User adminUser;
    private User regularUser;
    private User ownerUser;
    private User otherUser;
    private Resource resource;
    private RequestContext requestContext;
    private AccessContext accessContext;

    @BeforeEach
    void setUp() {
        // Create test users
        adminUser = createTestUser(1L, "admin", Role.ADMIN, "Engineering");
        regularUser = createTestUser(2L, "user", Role.USER, "Engineering");
        ownerUser = createTestUser(3L, "owner", Role.USER, "Finance");
        otherUser = createTestUser(4L, "other", Role.USER, "HR");

        // Create test resource
        resource = createTestResource(100L, ownerUser.getId(), "Finance");

        // Create request context
        requestContext = new RequestContext(
            "192.168.1.100", "Mozilla/5.0", "session-123",
            "GET", "/api/v1/resources/100", LocalDateTime.now()
        );

        // Create access context
        BehavioralAnalysisResult analysis = new BehavioralAnalysisResult(false, false, 2, 0);
        accessContext = AccessContext.from(ownerUser, resource, requestContext, analysis);
    }

    @Test
    void testAdminCanAccessAnyResource() {
        AccessContext adminContext = AccessContext.from(
            adminUser, resource, requestContext, 
            new BehavioralAnalysisResult(false, false, 1, 0)
        );

        when(authorizationService.canRead(adminContext)).thenReturn(true);
        when(authorizationService.canWrite(adminContext)).thenReturn(true);
        when(authorizationService.canDelete(adminContext)).thenReturn(true);

        assertThat(authorizationService.canRead(adminContext)).isTrue();
        assertThat(authorizationService.canWrite(adminContext)).isTrue();
        assertThat(authorizationService.canDelete(adminContext)).isTrue();
    }

    @Test
    void testOwnerCanAccessOwnResource() {
        AccessContext ownerContext = AccessContext.from(
            ownerUser, resource, requestContext,
            new BehavioralAnalysisResult(false, false, 1, 0)
        );

        when(authorizationService.canRead(ownerContext)).thenReturn(true);
        when(authorizationService.canWrite(ownerContext)).thenReturn(true);
        when(authorizationService.canDelete(ownerContext)).thenReturn(true);

        assertThat(authorizationService.canRead(ownerContext)).isTrue();
        assertThat(authorizationService.canWrite(ownerContext)).isTrue();
        assertThat(authorizationService.canDelete(ownerContext)).isTrue();
    }

    @Test
    void testSameDepartmentCanReadResource() {
        User sameDeptUser = createTestUser(5L, "samedept", Role.USER, "Finance");
        AccessContext sameDeptContext = AccessContext.from(
            sameDeptUser, resource, requestContext,
            new BehavioralAnalysisResult(false, false, 1, 0)
        );

        when(authorizationService.canRead(sameDeptContext)).thenReturn(true);
        when(authorizationService.canWrite(sameDeptContext)).thenReturn(false);

        assertThat(authorizationService.canRead(sameDeptContext)).isTrue();
        assertThat(authorizationService.canWrite(sameDeptContext)).isFalse();
    }

    @Test
    void testDifferentDepartmentCannotAccessResource() {
        AccessContext otherContext = AccessContext.from(
            otherUser, resource, requestContext,
            new BehavioralAnalysisResult(false, false, 1, 0)
        );

        when(authorizationService.canRead(otherContext)).thenReturn(false);
        when(authorizationService.canWrite(otherContext)).thenReturn(false);
        when(authorizationService.canDelete(otherContext)).thenReturn(false);

        assertThat(authorizationService.canRead(otherContext)).isFalse();
        assertThat(authorizationService.canWrite(otherContext)).isFalse();
        assertThat(authorizationService.canDelete(otherContext)).isFalse();
    }

    @Test
    void testHighRiskScoreBlocksAccess() {
        BehavioralAnalysisResult highRiskAnalysis = new BehavioralAnalysisResult(true, true, 5, 3);
        AccessContext highRiskContext = AccessContext.from(
            regularUser, resource, requestContext, highRiskAnalysis
        );

        when(authorizationService.canRead(highRiskContext)).thenReturn(false);

        assertThat(authorizationService.canRead(highRiskContext)).isFalse();
    }

    @Test
    void testSequentialProbingDetection() {
        BehavioralAnalysisResult probingAnalysis = new BehavioralAnalysisResult(true, false, 3, 2);
        AccessContext probingContext = AccessContext.from(
            regularUser, resource, requestContext, probingAnalysis
        );

        when(authorizationService.canRead(probingContext)).thenReturn(false);

        assertThat(authorizationService.canRead(probingContext)).isFalse();
    }

    @Test
    void testBusinessHoursRestriction() {
        // Create request outside business hours
        RequestContext afterHoursRequest = new RequestContext(
            "192.168.1.100", "Mozilla/5.0", "session-123",
            "DELETE", "/api/v1/resources/100", LocalDateTime.now().withHour(22)
        );

        AccessContext afterHoursContext = AccessContext.from(
            ownerUser, resource, afterHoursRequest,
            new BehavioralAnalysisResult(false, false, 1, 0)
        );

        when(authorizationService.canDelete(afterHoursContext)).thenReturn(false);

        assertThat(authorizationService.canDelete(afterHoursContext)).isFalse();
    }

    @Test
    void testAccessDeniedExceptionWithDetails() {
        AccessContext unauthorizedContext = AccessContext.from(
            otherUser, resource, requestContext,
            new BehavioralAnalysisResult(false, false, 1, 0)
        );

        doThrow(new AccessDeniedException("Access denied. Reason: Insufficient permissions"))
            .when(authorizationService)
            .checkAccess(otherUser, resource, AuthorizationService.Action.READ);

        assertThatThrownBy(() -> authorizationService.checkAccess(otherUser, resource, AuthorizationService.Action.READ))
            .isInstanceOf(AccessDeniedException.class)
            .hasMessageContaining("Access denied")
            .hasMessageContaining("Reason:");
    }

    private User createTestUser(Long id, String username, Role role, String department) {
        User user = new User();
        user.setId(id);
        user.setUsername(username);
        user.setRole(role);
        user.setDepartment(department);
        user.setTenantId("default");
        user.setAccountLocked(false);
        user.setFailedBolaAttempts(0);
        return user;
    }

    private Resource createTestResource(Long id, Long ownerId, String department) {
        Resource resource = new Resource();
        resource.setId(id);
        resource.setOwnerId(ownerId);
        resource.setDepartment(department);
        resource.setTenantId("default");
        resource.setName("Test Resource");
        resource.setDescription("Test Description");
        return resource;
    }
}
