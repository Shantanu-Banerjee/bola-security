package com.example.bola_security.exception;

public class ResourceNotFoundException extends RuntimeException {

    public ResourceNotFoundException(Long resourceId) {
        super("Resource not found: " + resourceId);
    }
}
