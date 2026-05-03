package com.example.bola_security.service;

import com.example.bola_security.config.BolaSecurityProperties;
import com.example.bola_security.model.SecurityAlert;
import com.example.bola_security.model.SecurityIncident;
import com.example.bola_security.repository.SecurityAlertRepository;
import io.micrometer.core.instrument.MeterRegistry;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Clock;
import java.time.LocalDateTime;
import java.util.List;

@Service
public class SecurityAlertService {

    private static final Logger log = LoggerFactory.getLogger(SecurityAlertService.class);

    private final SecurityAlertRepository securityAlertRepository;
    private final BolaSecurityProperties properties;
    private final MeterRegistry meterRegistry;
    private final Clock clock;

    public SecurityAlertService(
            SecurityAlertRepository securityAlertRepository,
            BolaSecurityProperties properties,
            MeterRegistry meterRegistry,
            Clock clock
    ) {
        this.securityAlertRepository = securityAlertRepository;
        this.properties = properties;
        this.meterRegistry = meterRegistry;
        this.clock = clock;
    }

    @Transactional
    public void raiseForIncident(SecurityIncident incident, boolean accountLocked) {
        if (incident.getSeverity().ordinal() < properties.alertSeverityThreshold().ordinal()
                && !accountLocked
                && !"TENANT_BOUNDARY_VIOLATION".equals(incident.getIncidentType())) {
            return;
        }

        SecurityAlert alert = new SecurityAlert();
        alert.setTenantId(incident.getTenantId());
        alert.setUserId(incident.getUserId());
        alert.setResourceId(incident.getResourceId());
        alert.setSecurityIncidentId(incident.getId());
        alert.setSeverity(incident.getSeverity());
        alert.setAlertType(accountLocked ? "ACCOUNT_LOCKED" : incident.getIncidentType());
        alert.setMessage(accountLocked
                ? "Account locked after repeated suspicious authorization attempts."
                : incident.getDescription());
        alert.setCreatedAt(LocalDateTime.now(clock));
        securityAlertRepository.save(alert);
        meterRegistry.counter("bola.alerts.raised", "severity", alert.getSeverity().name()).increment();
        log.warn("Security alert raised: tenantId={}, userId={}, type={}, severity={}",
                alert.getTenantId(), alert.getUserId(), alert.getAlertType(), alert.getSeverity());
    }

    @Transactional(readOnly = true)
    public List<SecurityAlert> latest() {
        return securityAlertRepository.findTop50ByOrderByCreatedAtDesc();
    }

    @Transactional(readOnly = true)
    public Page<SecurityAlert> latest(Pageable pageable) {
        return securityAlertRepository.findAllByOrderByCreatedAtDesc(pageable);
    }
}
