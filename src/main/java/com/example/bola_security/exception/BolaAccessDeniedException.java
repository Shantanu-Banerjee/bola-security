package com.example.bola_security.exception;

public class BolaAccessDeniedException extends RuntimeException {

    public BolaAccessDeniedException(String reason) {
        super(reason);
    }
}
