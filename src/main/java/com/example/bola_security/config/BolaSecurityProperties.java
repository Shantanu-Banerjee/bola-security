package com.example.bola_security.config;

import com.example.bola_security.model.IncidentSeverity;
import com.example.bola_security.model.Role;
import com.example.bola_security.service.ResourceAccessScope;
import org.springframework.boot.context.properties.ConfigurationProperties;

import java.time.Duration;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;

@ConfigurationProperties(prefix = "bola.security")
public record BolaSecurityProperties(
        int enumerationThreshold,
        int enumerationWindowSeconds,
        boolean departmentAccessEnabled,
        boolean seedDemoData,
        boolean businessHoursOnly,
        int businessHourStart,
        int businessHourEnd,
        boolean blockMissingUserAgent,
        int highRiskThreshold,
        int accountLockThreshold,
        String jwtSecret,
        String jwtIssuer,
        Duration accessTokenTtl,
        Duration refreshTokenTtl,
        List<String> trustedProxies,
        boolean redisRateLimitingEnabled,
        int sequentialAccessThreshold,
        Map<Role, ResourceAccessScope> roleResourceScopes,
        String gatewayApiKey,
        IncidentSeverity alertSeverityThreshold
) {
    public BolaSecurityProperties {
        if (jwtSecret == null || jwtSecret.length() < 32) {
            throw new IllegalArgumentException("JWT secret must be at least 32 characters");
        }
        trustedProxies = trustedProxies == null ? List.of() : List.copyOf(trustedProxies);
        sequentialAccessThreshold = sequentialAccessThreshold <= 0 ? 3 : sequentialAccessThreshold;
        alertSeverityThreshold = alertSeverityThreshold == null ? IncidentSeverity.HIGH : alertSeverityThreshold;

        EnumMap<Role, ResourceAccessScope> scopes = new EnumMap<>(Role.class);
        scopes.put(Role.USER, ResourceAccessScope.OWN);
        scopes.put(Role.MANAGER, departmentAccessEnabled
                ? ResourceAccessScope.SAME_DEPARTMENT
                : ResourceAccessScope.OWN);
        scopes.put(Role.ADMIN, ResourceAccessScope.ANY);
        if (roleResourceScopes != null) {
            scopes.putAll(roleResourceScopes);
        }
        roleResourceScopes = Map.copyOf(scopes);
    }

    public ResourceAccessScope scopeFor(Role role) {
        return roleResourceScopes.getOrDefault(role, ResourceAccessScope.NONE);
    }
}
