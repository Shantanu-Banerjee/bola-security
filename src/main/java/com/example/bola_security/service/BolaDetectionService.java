package com.example.bola_security.service;

import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;

import com.example.bola_security.authorization.AuthorizationService;
import com.example.bola_security.model.Resource;
import com.example.bola_security.model.User;
import com.example.bola_security.repository.ResourceRepository;
import com.example.bola_security.repository.UserRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import java.util.Optional;

import org.springframework.stereotype.Service;

@Service
public class BolaDetectionService {

    private static final Logger log = LoggerFactory.getLogger(BolaDetectionService.class);

    private final AuthorizationService authorizationService;
    private final UserRepository userRepository;
    private final ResourceRepository resourceRepository;
     public BolaDetectionService(AuthorizationService authorizationService,
                                UserRepository userRepository,
                                ResourceRepository resourceRepository) {
        this.authorizationService = authorizationService;
        this.userRepository = userRepository;
        this.resourceRepository = resourceRepository;
    }

    public boolean validateAccess(String userIdStr, String resourceIdStr, HttpServletRequest request) {
        try {
            Long userId = Long.parseLong(userIdStr);
            Long resourceId = Long.parseLong(resourceIdStr);

            Optional<User> userOpt = userRepository.findById(userId);
            if (userOpt.isEmpty()) {
                log.warn("User not found for BOLA check: {}", userIdStr);
                return false;
            }

            Optional<Resource> resourceOpt = resourceRepository.findById(resourceId);
            if (resourceOpt.isEmpty()) {
                log.warn("Resource not found for BOLA check: {}", resourceIdStr);
                return false;
            }

            User user = userOpt.get();

            boolean allowed = authorizationService.hasPermission(user, resourceId, "READ");
            if (!allowed) {
                log.warn("BOLA access denied: userId={}, resourceId={}", userId, resourceId);
            } else {
                log.debug("BOLA access allowed: userId={}, resourceId={}", userId, resourceId);
            }
            return allowed;
        } catch (NumberFormatException e) {
            log.error("Invalid ID format in BOLA check: user={}, resource={}", userIdStr, resourceIdStr);
            return false;
        } catch (Exception e) {
            log.error("BOLA validation error", e);
            return false;
        }
    }
}