package com.example.bola_security.controller;

import com.example.bola_security.dto.ErrorResponse;
import com.example.bola_security.exception.BolaAccessDeniedException;
import com.example.bola_security.exception.InvalidRefreshTokenException;
import com.example.bola_security.exception.ResourceNotFoundException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.authentication.LockedException;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.time.LocalDateTime;

@RestControllerAdvice
public class GlobalExceptionHandler {

    @ExceptionHandler(BolaAccessDeniedException.class)
    public ResponseEntity<ErrorResponse> bolaDenied(BolaAccessDeniedException exception) {
        return ResponseEntity.status(HttpStatus.FORBIDDEN)
                .body(new ErrorResponse("BOLA_BLOCKED", exception.getMessage(), LocalDateTime.now()));
    }

    @ExceptionHandler(ResourceNotFoundException.class)
    public ResponseEntity<ErrorResponse> notFound(ResourceNotFoundException exception) {
        return ResponseEntity.status(HttpStatus.NOT_FOUND)
                .body(new ErrorResponse("RESOURCE_NOT_FOUND", exception.getMessage(), LocalDateTime.now()));
    }

    @ExceptionHandler(IllegalArgumentException.class)
    public ResponseEntity<ErrorResponse> badRequest(IllegalArgumentException exception) {
        return ResponseEntity.badRequest()
                .body(new ErrorResponse("BAD_REQUEST", exception.getMessage(), LocalDateTime.now()));
    }

    @ExceptionHandler({AuthenticationException.class, InvalidRefreshTokenException.class})
    public ResponseEntity<ErrorResponse> unauthorized(RuntimeException exception) {
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                .body(new ErrorResponse("UNAUTHORIZED", "Authentication failed.", LocalDateTime.now()));
    }

    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<ErrorResponse> validation(MethodArgumentNotValidException exception) {
        String message = exception.getBindingResult()
                .getFieldErrors()
                .stream()
                .findFirst()
                .map(this::fieldMessage)
                .orElse("Request validation failed");
        return ResponseEntity.badRequest()
                .body(new ErrorResponse("VALIDATION_FAILED", message, LocalDateTime.now()));
    }

    @ExceptionHandler(LockedException.class)
    public ResponseEntity<ErrorResponse> locked(LockedException exception) {
        return ResponseEntity.status(HttpStatus.LOCKED)
                .body(new ErrorResponse("ACCOUNT_LOCKED", "Account is locked due to repeated suspicious access.", LocalDateTime.now()));
    }

    private String fieldMessage(FieldError error) {
        return error.getField() + ": " + error.getDefaultMessage();
    }
}
