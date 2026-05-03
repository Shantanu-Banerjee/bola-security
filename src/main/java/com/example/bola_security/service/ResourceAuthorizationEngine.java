package com.example.bola_security.service;

import com.example.bola_security.exception.BolaAccessDeniedException;
import com.example.bola_security.exception.ResourceNotFoundException;
import com.example.bola_security.model.Resource;
import com.example.bola_security.model.User;
import com.example.bola_security.repository.ResourceRepository;
import io.micrometer.core.instrument.MeterRegistry;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;
import org.springframework.security.authentication.LockedException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class ResourceAuthorizationEngine {

    private static final Logger log = LoggerFactory.getLogger(ResourceAuthorizationEngine.class);

    private final ResourceRepository resourceRepository;
    private final AuthorizationService authorizationService;
    private final BehavioralAnalysisService behavioralAnalysisService;
    private final AuditLogService auditLogService;
    private final SecurityIncidentService securityIncidentService;
    private final MeterRegistry meterRegistry;

    public ResourceAuthorizationEngine(
            ResourceRepository resourceRepository,
            AuthorizationService authorizationService,
            BehavioralAnalysisService behavioralAnalysisService,
            AuditLogService auditLogService,
            SecurityIncidentService securityIncidentService,
            MeterRegistry meterRegistry
    ) {
        this.resourceRepository = resourceRepository;
        this.authorizationService = authorizationService;
        this.behavioralAnalysisService = behavioralAnalysisService;
        this.auditLogService = auditLogService;
        this.securityIncidentService = securityIncidentService;
        this.meterRegistry = meterRegistry;
    }

    @Transactional
    public AuthorizationOutcome authorize(User user, Long resourceId, RequestContext requestContext) {
        if (user.isAccountLocked()) {
            throw new LockedException("Account is locked");
        }

        Resource resource = resourceRepository.findById(resourceId)
                .orElseThrow(() -> new ResourceNotFoundException(resourceId));
        BehavioralAnalysisResult behavioralAnalysis = behavioralAnalysisService.inspect(user.getId(), resourceId);
        AccessContext context = AccessContext.from(user, resource, requestContext, behavioralAnalysis);

        if (behavioralAnalysis.sequentialProbingLikely()) {
            log.warn("Sequential resource probing detected: userId={}, resourceId={}, runLength={}",
                    user.getId(), resourceId, behavioralAnalysis.sequentialRunLength());
            meterRegistry.counter("bola.behavior.signals", "type", "sequential_resource_probing").increment();
            block(user, resource, context, "SEQUENTIAL_RESOURCE_PROBING_DETECTED");
        }

        if (behavioralAnalysis.enumerationLikely()) {
            log.warn("ID enumeration detected: userId={}, distinctResourceCount={}",
                    user.getId(), behavioralAnalysis.recentDistinctResourceCount());
            meterRegistry.counter("bola.behavior.signals", "type", "id_enumeration").increment();
            block(user, resource, context, "ID_ENUMERATION_DETECTED");
        }

        AccessDecision decision = authorizationService.evaluate(context);
        if (!decision.allowed()) {
            block(user, resource, context, decision.reason());
        }

        MDC.put("decision", decision.reason());
        auditLogService.record(user, resource, context, "ALLOWED", decision.reason());
        meterRegistry.counter("bola.access.decisions", "outcome", "allowed", "reason", decision.reason()).increment();
        securityIncidentService.resetUserRisk(user);
        log.info("Resource access allowed: userId={}, resourceId={}, reason={}",
                user.getId(), resource.getId(), decision.reason());
        return new AuthorizationOutcome(user, resource, context, decision);
    }

    private void block(User user, Resource resource, AccessContext context, String reason) {
        MDC.put("decision", reason);
        auditLogService.record(user, resource, context, "BLOCKED", reason);
        meterRegistry.counter("bola.access.decisions", "outcome", "blocked", "reason", reason).increment();
        securityIncidentService.reportDeniedAccess(user, context, reason);
        throw new BolaAccessDeniedException(reason);
    }
}
