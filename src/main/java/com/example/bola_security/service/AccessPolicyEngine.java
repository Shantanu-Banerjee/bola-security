package com.example.bola_security.service;

import com.example.bola_security.config.BolaSecurityProperties;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.stereotype.Service;

@Service
public class AccessPolicyEngine {

    private final BolaSecurityProperties properties;

    public AccessPolicyEngine(BolaSecurityProperties properties) {
        this.properties = properties;
    }

    @Cacheable(
            value = "accessPolicyDecisions",
            key = "T(java.lang.String).format('%s:%s:%s:%s:%s:%s:%s', #context.userRole().name(), #context.userTenantId(), #context.userId(), #context.userDepartment(), #context.resourceOwnerId(), #context.resourceTenantId(), #context.resourceDepartment())"
    )
    public AccessDecision evaluate(AccessContext context) {
        if (!context.tenantMatch()) {
            return new AccessDecision(false, "TENANT_BOUNDARY_VIOLATION");
        }

        if (context.ownerMatch()) {
            return new AccessDecision(true, "OWNER_MATCH");
        }

        return switch (properties.scopeFor(context.userRole())) {
            case ANY -> new AccessDecision(true, "ADMIN_OVERRIDE");
            case SAME_DEPARTMENT -> context.sameDepartment()
                    ? new AccessDecision(true, "MANAGER_DEPARTMENT_MATCH")
                    : new AccessDecision(false, "OBJECT_LEVEL_AUTHORIZATION_FAILED");
            case OWN, NONE -> new AccessDecision(false, "OBJECT_LEVEL_AUTHORIZATION_FAILED");
        };
    }
}
