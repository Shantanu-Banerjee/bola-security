package com.example.bola_security.config;

import com.example.bola_security.authorization.ResourcePermissionEvaluator;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.expression.method.DefaultMethodSecurityExpressionHandler;
import org.springframework.security.access.expression.method.MethodSecurityExpressionHandler;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;

/**
 * Spring Security method security configuration for centralized authorization.
 * Enables @PreAuthorize annotations with custom permission evaluation.
 */
@Configuration
@EnableMethodSecurity(prePostEnabled = true, securedEnabled = true, jsr250Enabled = true)
public class MethodSecurityConfig {

    /**
     * Custom method security expression handler that uses our ResourcePermissionEvaluator.
     * This enables @PreAuthorize("hasPermission(#resource, 'READ')") style annotations.
     */
    @Bean
    public MethodSecurityExpressionHandler methodSecurityExpressionHandler(
            ResourcePermissionEvaluator permissionEvaluator) {
        DefaultMethodSecurityExpressionHandler handler = new DefaultMethodSecurityExpressionHandler();
        handler.setPermissionEvaluator(permissionEvaluator);
        return handler;
    }
}
