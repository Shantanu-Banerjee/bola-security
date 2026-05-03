package com.example.bola_security.controller;

import com.example.bola_security.dto.SecurityIncidentResponse;
import com.example.bola_security.service.SecurityIncidentService;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/security/incidents")
public class SecurityIncidentApiController {

    private final SecurityIncidentService securityIncidentService;

    public SecurityIncidentApiController(SecurityIncidentService securityIncidentService) {
        this.securityIncidentService = securityIncidentService;
    }

    @GetMapping
    @PreAuthorize("hasRole('ADMIN')")
    public Page<SecurityIncidentResponse> latest(Pageable pageable) {
        return securityIncidentService.latest(pageable)
                .map(SecurityIncidentResponse::from);
    }
}
