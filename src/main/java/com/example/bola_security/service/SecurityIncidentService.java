package com.example.bola_security.service;

import com.example.bola_security.config.BolaSecurityProperties;
import com.example.bola_security.model.IncidentSeverity;
import com.example.bola_security.model.SecurityIncident;
import com.example.bola_security.model.User;
import com.example.bola_security.repository.SecurityIncidentRepository;
import com.example.bola_security.repository.UserRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import java.time.Clock;
import java.time.LocalDateTime;
import java.util.List;

@Service
public class SecurityIncidentService {

    private static final Logger log = LoggerFactory.getLogger(SecurityIncidentService.class);

    private final SecurityIncidentRepository incidentRepository;
    private final UserRepository userRepository;
    private final SecurityAlertService securityAlertService;
    private final BolaSecurityProperties properties;
    private final Clock clock;

    public SecurityIncidentService(
            SecurityIncidentRepository incidentRepository,
            UserRepository userRepository,
            SecurityAlertService securityAlertService,
            BolaSecurityProperties properties,
            Clock clock
    ) {
        this.incidentRepository = incidentRepository;
        this.userRepository = userRepository;
        this.securityAlertService = securityAlertService;
        this.properties = properties;
        this.clock = clock;
    }

    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void reportDeniedAccess(User user, AccessContext context, String reason) {
        LocalDateTime now = LocalDateTime.now(clock);
        int failedAttempts = user.getFailedBolaAttempts() + 1;
        user.setFailedBolaAttempts(failedAttempts);
        user.setLastFailedBolaAttemptAt(now);

        if (failedAttempts >= properties.accountLockThreshold()) {
            user.setAccountLocked(true);
            log.warn("Account locked for userId={} after {} failed BOLA attempts", user.getId(), failedAttempts);
        }
        userRepository.save(user);

        SecurityIncident incident = new SecurityIncident();
        incident.setUserId(user.getId());
        incident.setUsername(user.getUsername());
        incident.setTenantId(user.getTenantId());
        incident.setResourceTenantId(context.resourceTenantId());
        incident.setResourceId(context.resourceId());
        incident.setIncidentType(reason);
        incident.setRiskScore(context.riskScore());
        incident.setSeverity(severityFor(context.riskScore(), failedAttempts));
        incident.setDescription(description(reason, context, failedAttempts, user.isAccountLocked()));
        incident.setCreatedAt(now);
        incident = incidentRepository.save(incident);
        securityAlertService.raiseForIncident(incident, user.isAccountLocked());
        log.info("Security incident reported: userId={}, reason={}, severity={}, riskScore={}",
                user.getId(), reason, incident.getSeverity(), context.riskScore());
    }

    @Transactional
    public void resetUserRisk(User user) {
        if (user.getFailedBolaAttempts() == 0 || user.getLastFailedBolaAttemptAt() == null) {
            return;
        }

        LocalDateTime now = LocalDateTime.now(clock);
        LocalDateTime nextEligibleDecay = user.getLastFailedBolaAttemptAt()
                .plusSeconds(properties.enumerationWindowSeconds());
        if (now.isBefore(nextEligibleDecay)) {
            return;
        }

        if (user.getLastRiskDecayAt() != null
                && now.isBefore(user.getLastRiskDecayAt().plusSeconds(properties.enumerationWindowSeconds()))) {
            return;
        }

        user.setFailedBolaAttempts(user.getFailedBolaAttempts() - 1);
        user.setLastRiskDecayAt(now);
        userRepository.save(user);
        log.debug("Decayed failed BOLA attempts for userId={} to {}", user.getId(), user.getFailedBolaAttempts());
    }

    /**
     * Simple method to report security incidents for defense system
     */
    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void reportSecurityIncident(Long userId, String username, Long resourceId, 
                                     String incidentType, String description, int riskScore) {
        LocalDateTime now = LocalDateTime.now(clock);
        
        SecurityIncident incident = new SecurityIncident();
        incident.setUserId(userId);
        incident.setUsername(username != null ? username : "SYSTEM");
        incident.setTenantId(userId != null ? "default" : "SYSTEM");
        incident.setResourceId(resourceId);
        incident.setIncidentType(incidentType);
        incident.setRiskScore(riskScore);
        incident.setSeverity(severityFor(riskScore, 1));
        incident.setDescription(description);
        incident.setCreatedAt(now);
        
        incidentRepository.save(incident);
        
        log.info("Security incident reported: userId={}, reason={}, severity={}, riskScore={}",
                userId, incidentType, incident.getSeverity(), riskScore);
    }

    @Transactional(readOnly = true)
    public List<SecurityIncident> latest() {
        return incidentRepository.findTop50ByOrderByCreatedAtDesc();
    }

    @Transactional(readOnly = true)
    public Page<SecurityIncident> latest(Pageable pageable) {
        return incidentRepository.findAllByOrderByCreatedAtDesc(pageable);
    }

    private IncidentSeverity severityFor(int riskScore, int failedAttempts) {
        if (failedAttempts >= properties.accountLockThreshold() || riskScore >= 90) {
            return IncidentSeverity.CRITICAL;
        }
        if (riskScore >= properties.highRiskThreshold()) {
            return IncidentSeverity.HIGH;
        }
        if (riskScore >= 50) {
            return IncidentSeverity.MEDIUM;
        }
        return IncidentSeverity.LOW;
    }

    private String description(String reason, AccessContext context, int failedAttempts, boolean locked) {
        String status = locked ? " Account locked." : "";
        return "Denied access due to " + reason
                + " from IP " + context.ipAddress()
                + " using " + context.httpMethod()
                + " " + context.requestPath()
                + ". Failed BOLA attempts=" + failedAttempts
                + ", riskScore=" + context.riskScore()
                + "." + status;
    }
}
