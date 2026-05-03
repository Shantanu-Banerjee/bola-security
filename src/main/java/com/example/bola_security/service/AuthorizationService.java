package com.example.bola_security.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import com.example.bola_security.config.BolaSecurityProperties;

@Service("legacyAuthorizationService")
public class AuthorizationService {

    private static final Logger log = LoggerFactory.getLogger(AuthorizationService.class);

    private final BolaSecurityProperties properties;
    private final AccessPolicyEngine accessPolicyEngine;

    @Autowired
    public AuthorizationService(BolaSecurityProperties properties, AccessPolicyEngine accessPolicyEngine) {
        this.properties = properties;
        this.accessPolicyEngine = accessPolicyEngine;
    }

    public AccessDecision evaluate(AccessContext context) {
        if (properties.blockMissingUserAgent()
                && (context.userAgent() == null || context.userAgent().isBlank())) {
            return new AccessDecision(false, "MISSING_USER_AGENT");
        }

        if (properties.businessHoursOnly()
                && (context.accessHour() < properties.businessHourStart()
                || context.accessHour() >= properties.businessHourEnd())) {
            return new AccessDecision(false, "OUTSIDE_ALLOWED_ACCESS_HOURS");
        }

        AccessDecision decision = accessPolicyEngine.evaluate(context);

        if (!decision.allowed()) {
            log.info("Authorization denied: userId={}, resourceId={}, reason={}",
                    context.userId(), context.resourceId(), decision.reason());
        }
        return decision;
    }

}
