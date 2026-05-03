package com.example.bola_security.service;

import com.example.bola_security.dto.GatewayAuthorizationRequest;
import com.example.bola_security.dto.GatewayAuthorizationResponse;
import com.example.bola_security.exception.BolaAccessDeniedException;
import com.example.bola_security.exception.ResourceNotFoundException;
import com.example.bola_security.model.User;
import org.springframework.security.authentication.LockedException;
import org.springframework.stereotype.Service;

import java.time.Clock;
import java.time.LocalDateTime;

@Service
public class GatewayAuthorizationService {

    private final AuthenticatedUserService authenticatedUserService;
    private final ResourceAuthorizationEngine resourceAuthorizationEngine;
    private final Clock clock;

    public GatewayAuthorizationService(
            AuthenticatedUserService authenticatedUserService,
            ResourceAuthorizationEngine resourceAuthorizationEngine,
            Clock clock
    ) {
        this.authenticatedUserService = authenticatedUserService;
        this.resourceAuthorizationEngine = resourceAuthorizationEngine;
        this.clock = clock;
    }

    public GatewayAuthorizationResponse authorize(GatewayAuthorizationRequest request) {
        User user = authenticatedUserService.currentUser();
        try {
            AuthorizationOutcome outcome = resourceAuthorizationEngine.authorize(
                    user,
                    request.resourceId(),
                    new RequestContext(
                            request.ipAddress() == null || request.ipAddress().isBlank() ? "gateway" : request.ipAddress(),
                            request.userAgent() == null || request.userAgent().isBlank() ? "gateway" : request.userAgent(),
                            "GATEWAY:" + (request.sourceService() == null || request.sourceService().isBlank() ? "unknown" : request.sourceService()),
                            request.httpMethod().trim().toUpperCase(),
                            request.requestPath(),
                            LocalDateTime.now(clock)
                    )
            );

            return new GatewayAuthorizationResponse(
                    true,
                    outcome.decision().reason(),
                    outcome.resource().getId(),
                    outcome.resource().getTenantId(),
                    outcome.context().riskScore(),
                    request.sourceService()
            );
        } catch (BolaAccessDeniedException exception) {
            return new GatewayAuthorizationResponse(false, exception.getMessage(), request.resourceId(), user.getTenantId(), 100, request.sourceService());
        } catch (ResourceNotFoundException exception) {
            return new GatewayAuthorizationResponse(false, "RESOURCE_NOT_FOUND", request.resourceId(), user.getTenantId(), 0, request.sourceService());
        } catch (LockedException exception) {
            return new GatewayAuthorizationResponse(false, "ACCOUNT_LOCKED", request.resourceId(), user.getTenantId(), 100, request.sourceService());
        }
    }
}
