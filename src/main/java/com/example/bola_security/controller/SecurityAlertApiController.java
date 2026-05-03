package com.example.bola_security.controller;

import com.example.bola_security.dto.SecurityAlertResponse;
import com.example.bola_security.service.SecurityAlertService;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/security/alerts")
public class SecurityAlertApiController {

    private final SecurityAlertService securityAlertService;

    public SecurityAlertApiController(SecurityAlertService securityAlertService) {
        this.securityAlertService = securityAlertService;
    }

    @GetMapping
    @PreAuthorize("hasRole('ADMIN')")
    public Page<SecurityAlertResponse> latest(Pageable pageable) {
        return securityAlertService.latest(pageable)
                .map(SecurityAlertResponse::from);
    }
}
