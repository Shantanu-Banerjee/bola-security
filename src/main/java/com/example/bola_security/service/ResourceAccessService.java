package com.example.bola_security.service;

import com.example.bola_security.dto.ResourceAccessResponse;
import com.example.bola_security.dto.ResourceCreateRequest;
import com.example.bola_security.dto.ResourceResponse;
import com.example.bola_security.model.Resource;
import com.example.bola_security.model.User;
import com.example.bola_security.repository.ResourceRepository;
import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.MDC;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class ResourceAccessService {

    private final ResourceRepository resourceRepository;
    private final ResourceAuthorizationEngine resourceAuthorizationEngine;
    private final AuthenticatedUserService authenticatedUserService;
    private final RequestContextService requestContextService;

    public ResourceAccessService(
            ResourceRepository resourceRepository,
            ResourceAuthorizationEngine resourceAuthorizationEngine,
            AuthenticatedUserService authenticatedUserService,
            RequestContextService requestContextService
    ) {
        this.resourceRepository = resourceRepository;
        this.resourceAuthorizationEngine = resourceAuthorizationEngine;
        this.authenticatedUserService = authenticatedUserService;
        this.requestContextService = requestContextService;
    }

    @Transactional
    public ResourceAccessResponse access(Long resourceId, HttpServletRequest request) {
        User user = authenticatedUserService.currentUser();
        String previousUserId = MDC.get("userId");
        String previousResourceId = MDC.get("resourceId");
        String previousDecision = MDC.get("decision");
        MDC.put("userId", String.valueOf(user.getId()));
        MDC.put("resourceId", String.valueOf(resourceId));
        try {
            AuthorizationOutcome outcome = resourceAuthorizationEngine.authorize(
                    user,
                    resourceId,
                    requestContextService.extract(request)
            );
            return new ResourceAccessResponse(true, outcome.decision().reason(), ResourceResponse.from(outcome.resource()));
        } finally {
            restoreMdc("userId", previousUserId);
            restoreMdc("resourceId", previousResourceId);
            restoreMdc("decision", previousDecision);
        }
    }

    @Transactional(readOnly = true)
    public Page<ResourceResponse> myResources(Pageable pageable) {
        User user = authenticatedUserService.currentUser();
        return resourceRepository.findByOwnerIdAndTenantId(user.getId(), user.getTenantId(), pageable)
                .map(ResourceResponse::from);
    }

    @Transactional
    public ResourceResponse create(ResourceCreateRequest request) {
        User user = authenticatedUserService.currentUser();
        Resource resource = new Resource();
        resource.setName(sanitize(request.name()));
        resource.setDepartment(sanitize(request.department()));
        resource.setDescription(request.description() != null ? sanitize(request.description()) : null);
        resource.setOwnerId(user.getId());
        resource.setTenantId(user.getTenantId());
        return ResourceResponse.from(resourceRepository.save(resource));
    }

    private String sanitize(String value) {
        return value.trim().replaceAll("[\\p{Cntrl}&&[^\r\n\t]]", "");
    }

    private void restoreMdc(String key, String value) {
        if (value == null) {
            MDC.remove(key);
            return;
        }
        MDC.put(key, value);
    }
}
