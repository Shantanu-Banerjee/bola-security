package com.example.bola_security.dto;

import com.example.bola_security.model.Resource;

public record ResourceResponse(
        Long id,
        String name,
        Long ownerId,
        String tenantId,
        String department,
        String description
) {
    public static ResourceResponse from(Resource resource) {
        return new ResourceResponse(
                resource.getId(),
                resource.getName(),
                resource.getOwnerId(),
                resource.getTenantId(),
                resource.getDepartment(),
                resource.getDescription()
        );
    }
}
