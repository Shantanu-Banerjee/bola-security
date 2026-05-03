package com.example.bola_security.controller;

import com.example.bola_security.service.AuditLogService;
import com.example.bola_security.service.SecurityIncidentService;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class PageController {

    private final AuditLogService auditLogService;
    private final SecurityIncidentService securityIncidentService;

    public PageController(AuditLogService auditLogService, SecurityIncidentService securityIncidentService) {
        this.auditLogService = auditLogService;
        this.securityIncidentService = securityIncidentService;
    }

    @GetMapping("/dashboard")
    public String dashboard(Model model) {
        model.addAttribute("myResourcesPath", "/api/v1/resources/mine");
        return "dashboard";
    }

    @GetMapping("/logs")
    public String logs(Model model) {
        model.addAttribute("logs", auditLogService.latest());
        model.addAttribute("incidents", securityIncidentService.latest());
        return "logs";
    }
}
