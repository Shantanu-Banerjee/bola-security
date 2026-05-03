package com.example.bola_security.repository;

import com.example.bola_security.model.SecurityAlert;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface SecurityAlertRepository extends JpaRepository<SecurityAlert, Long> {

    Page<SecurityAlert> findAllByOrderByCreatedAtDesc(Pageable pageable);

    List<SecurityAlert> findTop50ByOrderByCreatedAtDesc();
}
