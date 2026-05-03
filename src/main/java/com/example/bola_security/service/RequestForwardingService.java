package com.example.bola_security.service;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.*;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

import java.io.BufferedReader;
import java.util.stream.Collectors;

@Service
public class RequestForwardingService {

    private final RestTemplate restTemplate = new RestTemplate();

    // 🔥 CHANGE THIS to your actual backend
    private final String TARGET_API = "http://localhost:9090";

    public void forward(HttpServletRequest request, HttpServletResponse response) {

        try {
            // Read request body
            String body = new BufferedReader(request.getReader())
                    .lines()
                    .collect(Collectors.joining("\n"));

            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_JSON);

            HttpEntity<String> entity = new HttpEntity<>(body, headers);

            String url = TARGET_API + request.getRequestURI();

            ResponseEntity<String> apiResponse =
                    restTemplate.exchange(
                            url,
                            HttpMethod.valueOf(request.getMethod()),
                            entity,
                            String.class
                    );

            response.setStatus(apiResponse.getStatusCodeValue());
            response.getWriter().write(apiResponse.getBody());

        } catch (Exception e) {
            throw new RuntimeException("Forwarding failed", e);
        }
    }
}