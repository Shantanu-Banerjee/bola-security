package com.example.bola_security.authorization;

import com.example.bola_security.model.*;
import com.example.bola_security.repository.ResourceRepository;
import com.example.bola_security.service.AccessContext;
import com.example.bola_security.service.RequestContext;
import com.example.bola_security.service.BehavioralAnalysisResult;
import com.example.bola_security.policy.PolicyEngine;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.stereotype.Service;

import java.util.Optional;

/**
 * Centralized authorization service that makes all access control decisions.
 * Replaces scattered authorization logic throughout the application.
 */
@Service
public class AuthorizationService {

    private final ResourceRepository resourceRepository;
    private final PolicyEngine policyEngine;

    public AuthorizationService(ResourceRepository resourceRepository, PolicyEngine policyEngine) {
        this.resourceRepository = resourceRepository;
        this.policyEngine = policyEngine;
    }

    /**
     * Evaluate if user can read the given resource
     */
    public boolean canRead(AccessContext context) {
        return evaluateAccess(context, Action.READ);
    }

    /**
     * Evaluate if user can write to the given resource
     */
    public boolean canWrite(AccessContext context) {
        return evaluateAccess(context, Action.WRITE);
    }

    /**
     * Evaluate if user can delete the given resource
     */
    public boolean canDelete(AccessContext context) {
        return evaluateAccess(context, Action.DELETE);
    }

    /**
     * Create AccessContext for evaluation
     */
    public AccessContext createContext(User user, Resource resource, RequestContext requestContext) {
        BehavioralAnalysisResult analysis = new BehavioralAnalysisResult(false, false, 0, 0);
        return AccessContext.from(user, resource, requestContext, analysis);
    }

    /**
     * Check permission by resource ID (for @PreAuthorize with ID-based checks)
     */
    public boolean hasPermission(User user, Long resourceId, String permission) {
        Optional<Resource> resourceOpt = resourceRepository.findById(resourceId);
        if (resourceOpt.isEmpty()) {
            return false;
        }

        Resource resource = resourceOpt.get();
        // Create minimal request context for permission checks
        RequestContext requestContext = new RequestContext(
            "127.0.0.1", "test-agent", "test-session", 
            "GET", "/test", java.time.LocalDateTime.now()
        );
        AccessContext context = createContext(user, resource, requestContext);
        
        return switch (permission) {
            case "READ" -> canRead(context);
            case "WRITE" -> canWrite(context);
            case "DELETE" -> canDelete(context);
            default -> false;
        };
    }

    /**
     * Central access evaluation logic using Policy Engine (ABAC)
     */
    private boolean evaluateAccess(AccessContext context, Action action) {
        PolicyEngine.PolicyDecision decision = policyEngine.evaluate(context, action.name());
        
        // Log the decision for audit purposes
        logPolicyDecision(context, action, decision);
        
        return decision.allowed();
    }

    /**
     * Log policy decisions for audit trail
     */
    private void logPolicyDecision(AccessContext context, Action action, PolicyEngine.PolicyDecision decision) {
        System.out.println(String.format(
            "Policy Decision: User=%s, Resource=%s, Action=%s, Allowed=%s, Reason=%s, Risk=%d",
            context.userId(),
            context.resourceId(),
            action,
            decision.allowed(),
            decision.reason(),
            context.riskScore()
        ));
    }

    /**
     * Context-aware access checks
     */
    private boolean isAccessAllowedByContext(AccessContext context, Action action) {
        // 1. Risk-based evaluation
        if (context.riskScore() > 80) {
            return false;
        }

        // 2. Time-based restrictions (business hours only for sensitive operations)
        if (action == Action.DELETE && !isBusinessHours()) {
            return false;
        }

        // 3. Sequential probing detection
        if (context.sequentialProbingLikely()) {
            return false;
        }

        return true;
    }

    private boolean isBusinessHours() {
        int hour = java.time.LocalDateTime.now().getHour();
        return hour >= 9 && hour <= 17;
    }

    /**
     * Throw access denied exception with detailed context
     */
    public void checkAccess(User user, Resource resource, Action action) {
        RequestContext requestContext = new RequestContext(
            "127.0.0.1", "test-agent", "test-session", 
            "GET", "/test", java.time.LocalDateTime.now()
        );
        AccessContext context = createContext(user, resource, requestContext);
        
        if (!evaluateAccess(context, action)) {
            throw new AccessDeniedException(
                String.format("Access denied for user %s to resource %s. Action: %s, Reason: %s",
                    user.getId(), resource.getId(), action, getDenialReason(context, action))
            );
        }
    }

    private String getDenialReason(AccessContext context, Action action) {
        if (context.riskScore() > 80) {
            return "High risk score";
        }
        
        if (action == Action.DELETE && !isBusinessHours()) {
            return "Outside business hours";
        }
        
        if (context.sequentialProbingLikely()) {
            return "Sequential probing detected";
        }

        return "Insufficient permissions";
    }

    public enum Action {
        READ, WRITE, DELETE
    }
}
