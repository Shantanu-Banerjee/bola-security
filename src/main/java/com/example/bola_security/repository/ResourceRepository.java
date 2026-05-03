package com.example.bola_security.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Repository;
import com.example.bola_security.model.Resource;

import java.util.List;

@Repository
public interface ResourceRepository extends JpaRepository<Resource, Long> {

    Page<Resource> findByOwnerId(Long ownerId, Pageable pageable);
    Page<Resource> findByOwnerIdAndTenantId(Long ownerId, String tenantId, Pageable pageable);

    List<Resource> findByOwnerId(Long ownerId);
    List<Resource> findByOwnerIdAndTenantId(Long ownerId, String tenantId);

    List<Resource> findByDepartment(String department);
    List<Resource> findByDepartmentAndTenantId(String department, String tenantId);
}
