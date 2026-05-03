package com.example.bola_security.repository;

import com.example.bola_security.model.RefreshToken;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

@Repository
public interface RefreshTokenRepository extends JpaRepository<RefreshToken, Long> {

    Optional<RefreshToken> findByTokenHash(String tokenHash);
    
    List<RefreshToken> findByUserIdAndRevokedAtIsNull(Long userId);
    
    List<RefreshToken> findByExpiresAtBefore(LocalDateTime cutoff);
    
    @Query("SELECT rt FROM RefreshToken rt WHERE rt.userId = :userId AND rt.revokedAt IS NULL")
    List<RefreshToken> findActiveTokensByUserId(@Param("userId") Long userId);
}
