package com.example.bola_security.service;

import java.io.Serializable;

public record AccessDecision(boolean allowed, String reason) implements Serializable {
}
