package com.example.bola_security.repository;

import com.example.bola_security.model.SecurityIncident;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface SecurityIncidentRepository extends JpaRepository<SecurityIncident, Long> {

    List<SecurityIncident> findTop50ByOrderByCreatedAtDesc();
    Page<SecurityIncident> findAllByOrderByCreatedAtDesc(Pageable pageable);
}
