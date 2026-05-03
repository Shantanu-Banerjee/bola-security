package com.example.bola_security.exception;

public class InvalidRefreshTokenException extends RuntimeException {

    public InvalidRefreshTokenException() {
        super("Refresh token is invalid, expired, or revoked");
    }
}
