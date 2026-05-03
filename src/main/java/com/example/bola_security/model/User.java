package com.example.bola_security.model;

import jakarta.persistence.*;

import java.time.LocalDateTime;

@Entity
@Table(name = "users", indexes = {
        @Index(name = "idx_users_username", columnList = "username", unique = true),
        @Index(name = "idx_users_tenant", columnList = "tenantId")
})
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, unique = true, length = 80)
    private String username;

    @Column(nullable = false)
    private String password;

    @Column(nullable = false, length = 80)
    private String tenantId = "default";

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 30)
    private Role role = Role.USER;

    @Column(nullable = false, length = 80)
    private String department;

    @Column(nullable = false)
    private boolean accountLocked = false;

    @Column(nullable = false)
    private int failedBolaAttempts = 0;

    private LocalDateTime lastFailedBolaAttemptAt;

    private LocalDateTime lastRiskDecayAt;

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public String getTenantId() {
        return tenantId;
    }

    public void setTenantId(String tenantId) {
        this.tenantId = tenantId;
    }

    public Role getRole() {
        return role;
    }

    public void setRole(Role role) {
        this.role = role;
    }

    public String getDepartment() {
        return department;
    }

    public void setDepartment(String department) {
        this.department = department;
    }

    public boolean isAccountLocked() {
        return accountLocked;
    }

    public void setAccountLocked(boolean accountLocked) {
        this.accountLocked = accountLocked;
    }

    public int getFailedBolaAttempts() {
        return failedBolaAttempts;
    }

    public void setFailedBolaAttempts(int failedBolaAttempts) {
        this.failedBolaAttempts = failedBolaAttempts;
    }

    public LocalDateTime getLastFailedBolaAttemptAt() {
        return lastFailedBolaAttemptAt;
    }

    public void setLastFailedBolaAttemptAt(LocalDateTime lastFailedBolaAttemptAt) {
        this.lastFailedBolaAttemptAt = lastFailedBolaAttemptAt;
    }

    public LocalDateTime getLastRiskDecayAt() {
        return lastRiskDecayAt;
    }

    public void setLastRiskDecayAt(LocalDateTime lastRiskDecayAt) {
        this.lastRiskDecayAt = lastRiskDecayAt;
    }
}
