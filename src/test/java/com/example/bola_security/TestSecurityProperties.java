package com.example.bola_security;

import com.example.bola_security.config.BolaSecurityProperties;
import com.example.bola_security.model.IncidentSeverity;
import com.example.bola_security.model.Role;
import com.example.bola_security.service.ResourceAccessScope;

import java.time.Duration;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;

public final class TestSecurityProperties {

    private TestSecurityProperties() {
    }

    public static BolaSecurityProperties properties(
            int enumerationThreshold,
            int enumerationWindowSeconds,
            boolean departmentAccessEnabled,
            boolean seedDemoData,
            boolean businessHoursOnly,
            int businessHourStart,
            int businessHourEnd,
            boolean blockMissingUserAgent,
            int highRiskThreshold,
            int accountLockThreshold
    ) {
        EnumMap<Role, ResourceAccessScope> roleScopes = new EnumMap<>(Role.class);
        roleScopes.put(Role.USER, ResourceAccessScope.OWN);
        roleScopes.put(Role.MANAGER, departmentAccessEnabled
                ? ResourceAccessScope.SAME_DEPARTMENT
                : ResourceAccessScope.OWN);
        roleScopes.put(Role.ADMIN, ResourceAccessScope.ANY);

        return new BolaSecurityProperties(
                enumerationThreshold,
                enumerationWindowSeconds,
                departmentAccessEnabled,
                seedDemoData,
                businessHoursOnly,
                businessHourStart,
                businessHourEnd,
                blockMissingUserAgent,
                highRiskThreshold,
                accountLockThreshold,
                "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
                "bola-security-test",
                Duration.ofMinutes(15),
                Duration.ofDays(7),
                List.of("127.0.0.1", "0:0:0:0:0:0:0:1", "::1"),
                false,
                3,
                Map.copyOf(roleScopes),
                "test-gateway-key",
                IncidentSeverity.HIGH
        );
    }
}
