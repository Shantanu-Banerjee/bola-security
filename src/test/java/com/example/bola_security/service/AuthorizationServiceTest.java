package com.example.bola_security.service;

import com.example.bola_security.model.Resource;
import com.example.bola_security.model.Role;
import com.example.bola_security.model.User;
import org.junit.jupiter.api.Test;

import java.time.LocalDateTime;

import static org.assertj.core.api.Assertions.assertThat;
import static com.example.bola_security.TestSecurityProperties.properties;

class AuthorizationServiceTest {

    @Test
    void allowsOwner() {
        AuthorizationService service = service(false);
        User user = user(1L, Role.USER, "tenant-alpha", "Engineering");
        Resource resource = resource(10L, 1L, "tenant-alpha", "Finance");

        AccessDecision decision = service.evaluate(context(user, resource));

        assertThat(decision.allowed()).isTrue();
        assertThat(decision.reason()).isEqualTo("OWNER_MATCH");
    }

    @Test
    void allowsAdmin() {
        AuthorizationService service = service(false);
        User user = user(1L, Role.ADMIN, "tenant-alpha", "Security");
        Resource resource = resource(10L, 99L, "tenant-alpha", "Finance");

        AccessDecision decision = service.evaluate(context(user, resource));

        assertThat(decision.allowed()).isTrue();
        assertThat(decision.reason()).isEqualTo("ADMIN_OVERRIDE");
    }

    @Test
    void blocksDifferentOwnerWhenDepartmentPolicyIsDisabled() {
        AuthorizationService service = service(false);
        User user = user(1L, Role.MANAGER, "tenant-alpha", "Finance");
        Resource resource = resource(10L, 99L, "tenant-alpha", "Finance");

        AccessDecision decision = service.evaluate(context(user, resource));

        assertThat(decision.allowed()).isFalse();
        assertThat(decision.reason()).isEqualTo("OBJECT_LEVEL_AUTHORIZATION_FAILED");
    }

    @Test
    void allowsManagerDepartmentAccessWhenPolicyIsEnabled() {
        AuthorizationService service = service(true);
        User user = user(1L, Role.MANAGER, "tenant-alpha", "Finance");
        Resource resource = resource(10L, 99L, "tenant-alpha", "Finance");

        AccessDecision decision = service.evaluate(context(user, resource));

        assertThat(decision.allowed()).isTrue();
        assertThat(decision.reason()).isEqualTo("MANAGER_DEPARTMENT_MATCH");
    }

    @Test
    void blocksCrossTenantAccess() {
        AuthorizationService service = service(true);
        User user = user(1L, Role.ADMIN, "tenant-alpha", "Security");
        Resource resource = resource(10L, 99L, "tenant-beta", "Finance");

        AccessDecision decision = service.evaluate(context(user, resource));

        assertThat(decision.allowed()).isFalse();
        assertThat(decision.reason()).isEqualTo("TENANT_BOUNDARY_VIOLATION");
    }

    private AuthorizationService service(boolean departmentAccessEnabled) {
        var properties = properties(5, 10, departmentAccessEnabled, false, false, 9, 18, true, 80, 5);
        return new AuthorizationService(properties, new AccessPolicyEngine(properties));
    }

    private AccessContext context(User user, Resource resource) {
        return AccessContext.from(
                user,
                resource,
                new RequestContext("127.0.0.1", "JUnit", "test-session", "GET", "/api/resources/" + resource.getId(), LocalDateTime.now()),
                0
        );
    }

    private User user(Long id, Role role, String tenantId, String department) {
        User user = new User();
        user.setId(id);
        user.setRole(role);
        user.setTenantId(tenantId);
        user.setDepartment(department);
        user.setUsername("user-" + id);
        user.setPassword("encoded");
        return user;
    }

    private Resource resource(Long id, Long ownerId, String tenantId, String department) {
        Resource resource = new Resource();
        resource.setId(id);
        resource.setOwnerId(ownerId);
        resource.setTenantId(tenantId);
        resource.setDepartment(department);
        resource.setName("resource-" + id);
        return resource;
    }
}
