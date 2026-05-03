package com.example.bola_security.service;

import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class BolaDetectionService {

    // TEMP logic (we’ll upgrade to DB later)
    public boolean validateAccess(String userId, String resourceId, HttpServletRequest request) {

        // Example rule:
        // user1 → can access resource 101
        // user2 → can access resource 102

        if (userId == null || resourceId == null) return false;

        if (userId.equals("user1") && resourceId.equals("101")) return true;
        if (userId.equals("user2") && resourceId.equals("102")) return true;

        return false; // block everything else
    }
}