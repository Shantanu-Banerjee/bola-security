package com.example.bola_security.authorization;

import com.example.bola_security.model.Resource;
import com.example.bola_security.model.User;
import com.example.bola_security.repository.ResourceRepository;
import com.example.bola_security.repository.UserRepository;
import com.example.bola_security.service.AccessContext;
import com.example.bola_security.service.RequestContext;
import org.springframework.security.access.PermissionEvaluator;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;

import java.io.Serializable;

/**
 * Centralized permission evaluator for all resource access decisions.
 * Replaces scattered ownership checks throughout the application.
 */
@Component
public class ResourcePermissionEvaluator implements PermissionEvaluator {

    private final com.example.bola_security.service.AuthorizationService authorizationService;
    private final ResourceRepository resourceRepository;
    private final UserRepository userRepository;

    public ResourcePermissionEvaluator(
            com.example.bola_security.service.AuthorizationService authorizationService,
            ResourceRepository resourceRepository,
            UserRepository userRepository
    ) {
        this.authorizationService = authorizationService;
        this.resourceRepository = resourceRepository;
        this.userRepository = userRepository;
    }

    @Override
    public boolean hasPermission(Authentication authentication, Object targetDomainObject, Object permission) {
        if (authentication == null || !authentication.isAuthenticated()) {
            return false;
        }

        if (targetDomainObject instanceof Resource) {
            Resource resource = (Resource) targetDomainObject;
            User user = resolveApplicationUser(authentication);
            if (user == null) {
                return false;
            }

            RequestContext requestContext = methodSecurityContext(resource.getId());
            AccessContext context = AccessContext.from(user, resource, requestContext, 0);

            return authorizationService.evaluate(context).allowed();
        }
        
        return false;
    }

    @Override
    public boolean hasPermission(Authentication authentication, Serializable targetId, String targetType, Object permission) {
        if (authentication == null || !authentication.isAuthenticated()) {
            return false;
        }

        // For ID-based permission checks (when we don't have the full object)
        // This requires loading the resource for evaluation
        return switch (targetType) {
            case "Resource" -> evaluateResourcePermission(authentication, (Long) targetId, permission.toString());
            default -> false;
        };
    }

    private boolean evaluateResourcePermission(Authentication authentication, Long resourceId, String permission) {
        User user = resolveApplicationUser(authentication);
        if (user == null) {
            return false;
        }

        return resourceRepository.findById(resourceId)
                .map(resource -> {
                    AccessContext context = AccessContext.from(
                            user,
                            resource,
                            methodSecurityContext(resourceId),
                            0
                    );
                    return authorizationService.evaluate(context).allowed();
                })
                .orElse(false);
    }

    private User resolveApplicationUser(Authentication authentication) {
        Object principal = authentication.getPrincipal();
        if (principal instanceof User user) {
            return user;
        }
        return userRepository.findByUsername(authentication.getName()).orElse(null);
    }

    private RequestContext methodSecurityContext(Long resourceId) {
        return new RequestContext(
                "127.0.0.1",
                "method-security",
                "method-security",
                "GET",
                "/api/v1/resources/" + resourceId,
                java.time.LocalDateTime.now()
        );
    }
}
