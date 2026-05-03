package com.example.bola_security.service;

public record BehavioralAnalysisResult(
        boolean enumerationLikely,
        boolean sequentialProbingLikely,
        long recentDistinctResourceCount,
        int sequentialRunLength
) {
}
