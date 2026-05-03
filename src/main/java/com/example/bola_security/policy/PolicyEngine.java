package com.example.bola_security.policy;

import com.example.bola_security.model.*;
import com.example.bola_security.service.AccessContext;
import com.example.bola_security.service.RequestContext;
import com.example.bola_security.service.BehavioralAnalysisResult;
import org.springframework.stereotype.Component;

import java.time.LocalDateTime;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

/**
 * Attribute-Based Access Control (ABAC) Policy Engine.
 * Evaluates access decisions based on user attributes, resource attributes,
 * environmental context, and action types.
 */
@Component
public class PolicyEngine {

    private final List<Policy> policies;

    public PolicyEngine() {
        this.policies = initializePolicies();
    }

    /**
     * Evaluate all policies and return the final access decision
     */
    public PolicyDecision evaluate(AccessContext context, String action) {
        PolicyDecision finalDecision = new PolicyDecision(true, "Access granted");

        for (Policy policy : policies) {
            if (!policy.isApplicable(context, action)) {
                continue;
            }

            PolicyDecision decision = policy.evaluate(context, action);
            
            // If any policy denies access, final decision is deny
            if (!decision.allowed()) {
                finalDecision = decision;
                break;
            }
        }

        return finalDecision;
    }

    /**
     * Initialize all security policies
     */
    private List<Policy> initializePolicies() {
        return Arrays.asList(
            // 1. Admin Override Policy
            new Policy() {
                @Override
                public boolean isApplicable(AccessContext context, String action) {
                    return true; // Always applicable
                }

                @Override
                public PolicyDecision evaluate(AccessContext context, String action) {
                    if (context.userRole() == Role.ADMIN) {
                        return new PolicyDecision(true, "Admin override granted");
                    }
                    return new PolicyDecision(true, "Not admin, continue evaluation");
                }
            },

            // 2. Account Status Policy
            new Policy() {
                @Override
                public boolean isApplicable(AccessContext context, String action) {
                    return true; // Always applicable
                }

                @Override
                public PolicyDecision evaluate(AccessContext context, String action) {
                    // This would typically check user account status
                    // For now, assume account is active
                    return new PolicyDecision(true, "Account is active");
                }
            },

            // 3. Ownership Policy
            new Policy() {
                @Override
                public boolean isApplicable(AccessContext context, String action) {
                    return Arrays.asList("READ", "WRITE", "DELETE").contains(action);
                }

                @Override
                public PolicyDecision evaluate(AccessContext context, String action) {
                    if (context.ownerMatch()) {
                        return new PolicyDecision(true, "Owner access granted");
                    }
                    return new PolicyDecision(true, "Not owner, continue evaluation");
                }
            },

            // 4. Department Access Policy
            new Policy() {
                @Override
                public boolean isApplicable(AccessContext context, String action) {
                    return "READ".equals(action);
                }

                @Override
                public PolicyDecision evaluate(AccessContext context, String action) {
                    if (context.sameDepartment()) {
                        return new PolicyDecision(true, "Same department read access granted");
                    }
                    return new PolicyDecision(true, "Different department, continue evaluation");
                }
            },

            // 5. Time-Based Policy
            new Policy() {
                @Override
                public boolean isApplicable(AccessContext context, String action) {
                    return Arrays.asList("DELETE", "WRITE").contains(action);
                }

                @Override
                public PolicyDecision evaluate(AccessContext context, String action) {
                    int hour = context.accessTime().getHour();
                    boolean businessHours = hour >= 9 && hour <= 17;
                    
                    if (!businessHours) {
                        return new PolicyDecision(false, 
                            "Sensitive operations restricted to business hours (9 AM - 5 PM)");
                    }
                    return new PolicyDecision(true, "Within business hours");
                }
            },

            // 6. Risk-Based Policy
            new Policy() {
                @Override
                public boolean isApplicable(AccessContext context, String action) {
                    return true; // Always applicable
                }

                @Override
                public PolicyDecision evaluate(AccessContext context, String action) {
                    int riskScore = context.riskScore();
                    
                    if (riskScore > 80) {
                        return new PolicyDecision(false, 
                            "High risk score detected: " + riskScore);
                    } else if (riskScore > 60) {
                        return new PolicyDecision(true, 
                            "Medium risk score: " + riskScore + " - access granted with monitoring");
                    }
                    return new PolicyDecision(true, "Low risk score: " + riskScore);
                }
            },

            // 7. Behavioral Analysis Policy
            new Policy() {
                @Override
                public boolean isApplicable(AccessContext context, String action) {
                    return true; // Always applicable
                }

                @Override
                public PolicyDecision evaluate(AccessContext context, String action) {
                    if (context.sequentialProbingLikely()) {
                        return new PolicyDecision(false, 
                            "Sequential probing detected - possible IDOR attack");
                    }
                    
                    if (context.recentDistinctResourceCount() > 10) {
                        return new PolicyDecision(false, 
                            "Excessive resource access detected");
                    }
                    
                    return new PolicyDecision(true, "Normal access pattern");
                }
            },

            // 8. Location-Based Policy
            new Policy() {
                @Override
                public boolean isApplicable(AccessContext context, String action) {
                    return true; // Always applicable
                }

                @Override
                public PolicyDecision evaluate(AccessContext context, String action) {
                    String ipAddress = context.ipAddress();
                    
                    // Block known malicious IPs (simplified)
                    if (isSuspiciousIP(ipAddress)) {
                        return new PolicyDecision(false, 
                            "Access from suspicious IP address: " + ipAddress);
                    }
                    
                    return new PolicyDecision(true, "IP address allowed");
                }

                private boolean isSuspiciousIP(String ip) {
                    // Simplified IP checking - in production, use threat intelligence feeds
                    List<String> suspiciousIPs = Arrays.asList(
                        "192.168.1.100", "10.0.0.50" // Example suspicious IPs
                    );
                    return suspiciousIPs.contains(ip);
                }
            },

            // 9. Resource Sensitivity Policy
            new Policy() {
                @Override
                public boolean isApplicable(AccessContext context, String action) {
                    return true; // Always applicable
                }

                @Override
                public PolicyDecision evaluate(AccessContext context, String action) {
                    // Check if resource is in sensitive department
                    String department = context.resourceDepartment();
                    
                    if ("Finance".equals(department) || "HR".equals(department)) {
                        // Require additional checks for sensitive departments
                        if (!context.ownerMatch() && context.userRole() != Role.ADMIN) {
                            return new PolicyDecision(false, 
                                "Access to sensitive department resources restricted to owners and admins");
                        }
                    }
                    
                    return new PolicyDecision(true, "Resource sensitivity check passed");
                }
            },

            // 10. Default Deny Policy
            new Policy() {
                @Override
                public boolean isApplicable(AccessContext context, String action) {
                    return true; // Always applicable as last resort
                }

                @Override
                public PolicyDecision evaluate(AccessContext context, String action) {
                    return new PolicyDecision(false, 
                        "No specific policy granted access - default deny");
                }
            }
        );
    }

    /**
     * Policy interface for defining access control rules
     */
    public interface Policy {
        boolean isApplicable(AccessContext context, String action);
        PolicyDecision evaluate(AccessContext context, String action);
    }

    /**
     * Policy decision result
     */
    public record PolicyDecision(boolean allowed, String reason) {}
}
