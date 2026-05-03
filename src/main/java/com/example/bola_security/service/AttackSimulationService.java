package com.example.bola_security.service;

import com.example.bola_security.dto.AttackSimulationRequest;
import com.example.bola_security.dto.AttackSimulationResponse;
import com.example.bola_security.dto.AttackSimulationStepResponse;
import com.example.bola_security.exception.BolaAccessDeniedException;
import com.example.bola_security.exception.ResourceNotFoundException;
import com.example.bola_security.model.User;
import com.example.bola_security.repository.UserRepository;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.time.Clock;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;

@Service
public class AttackSimulationService {

    private final UserRepository userRepository;
    private final ResourceAuthorizationEngine resourceAuthorizationEngine;
    private final Clock clock;

    public AttackSimulationService(
            UserRepository userRepository,
            ResourceAuthorizationEngine resourceAuthorizationEngine,
            Clock clock
    ) {
        this.userRepository = userRepository;
        this.resourceAuthorizationEngine = resourceAuthorizationEngine;
        this.clock = clock;
    }

    public AttackSimulationResponse simulate(AttackSimulationRequest request) {
        User user = userRepository.findById(request.actorUserId())
                .orElseThrow(() -> new UsernameNotFoundException("User not found"));

        List<AttackSimulationStepResponse> steps = new ArrayList<>();
        int blockedCount = 0;
        for (int index = 0; index < request.resourceIds().size(); index++) {
            Long resourceId = request.resourceIds().get(index);
            try {
                AuthorizationOutcome outcome = resourceAuthorizationEngine.authorize(
                        user,
                        resourceId,
                        new RequestContext(
                                request.sourceIp() == null || request.sourceIp().isBlank() ? "simulation" : request.sourceIp(),
                                request.userAgent() == null || request.userAgent().isBlank() ? "attack-simulation" : request.userAgent(),
                                "SIMULATION:" + request.attackType(),
                                request.httpMethod() == null || request.httpMethod().isBlank() ? "GET" : request.httpMethod().trim().toUpperCase(),
                                buildPath(request.requestPathPrefix(), resourceId),
                                LocalDateTime.now(clock)
                        )
                );
                steps.add(new AttackSimulationStepResponse(index + 1, resourceId, true, outcome.decision().reason(), outcome.context().riskScore()));
            } catch (BolaAccessDeniedException exception) {
                blockedCount++;
                steps.add(new AttackSimulationStepResponse(index + 1, resourceId, false, exception.getMessage(), 100));
            } catch (LockedException exception) {
                blockedCount++;
                steps.add(new AttackSimulationStepResponse(index + 1, resourceId, false, "ACCOUNT_LOCKED", 100));
            } catch (ResourceNotFoundException exception) {
                blockedCount++;
                steps.add(new AttackSimulationStepResponse(index + 1, resourceId, false, "RESOURCE_NOT_FOUND", 0));
            }
        }

        return new AttackSimulationResponse(
                request.attackType(),
                user.getId(),
                user.getTenantId(),
                request.resourceIds().size(),
                blockedCount,
                steps
        );
    }

    private String buildPath(String prefix, Long resourceId) {
        String safePrefix = prefix == null || prefix.isBlank() ? "/api/v1/resources" : prefix.trim();
        return safePrefix.endsWith("/") ? safePrefix + resourceId : safePrefix + "/" + resourceId;
    }
}
