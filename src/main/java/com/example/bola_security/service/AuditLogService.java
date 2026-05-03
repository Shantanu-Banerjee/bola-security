package com.example.bola_security.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;
import com.example.bola_security.model.AccessLog;
import com.example.bola_security.model.Resource;
import com.example.bola_security.model.User;
import com.example.bola_security.repository.AccessLogRepository;
import org.springframework.stereotype.Service;

import java.time.Clock;
import java.time.LocalDateTime;
import java.util.List;

@Service
public class AuditLogService {

    private static final Logger log = LoggerFactory.getLogger(AuditLogService.class);

    private final AccessLogRepository accessLogRepository;
    private final Clock clock;

    public AuditLogService(AccessLogRepository accessLogRepository, Clock clock) {
        this.accessLogRepository = accessLogRepository;
        this.clock = clock;
    }

   @Transactional(propagation = Propagation.REQUIRES_NEW)
public void record(User user, Resource resource, AccessContext context, String result, String reason) {
    AccessLog accessLog = new AccessLog();
    accessLog.setUserId(user.getId());
    accessLog.setUsername(user.getUsername());
    accessLog.setUserTenantId(user.getTenantId());
    accessLog.setUserDepartment(user.getDepartment());
    accessLog.setResourceId(resource.getId());
    accessLog.setResourceTenantId(resource.getTenantId());
    accessLog.setResourceDepartment(resource.getDepartment());
    accessLog.setResourceOwnerId(resource.getOwnerId());
    accessLog.setUserRole(user.getRole().name());
    accessLog.setTenantMatch(context.tenantMatch());
    accessLog.setOwnerMatch(context.ownerMatch());
    accessLog.setSameDepartment(context.sameDepartment());
    accessLog.setIpAddress(context.ipAddress());
    accessLog.setUserAgent(context.userAgent());
    accessLog.setSessionId(context.sessionId());
    accessLog.setHttpMethod(context.httpMethod());
    accessLog.setRequestPath(context.requestPath());
    accessLog.setAccessHour(context.accessHour());
    accessLog.setRecentDistinctResourceCount(context.recentDistinctResourceCount());
    accessLog.setRiskScore(context.riskScore());
    accessLog.setResult(result);
    accessLog.setReason(reason);
    accessLog.setTimestamp(LocalDateTime.now(clock));
    accessLogRepository.save(accessLog);
    log.info("Access log recorded: userId={}, resourceId={}, result={}, reason={}", user.getId(), resource.getId(), result, reason);
}

    public List<AccessLog> latest() {
        return accessLogRepository.findTop50ByOrderByTimestampDesc();
    }
}
