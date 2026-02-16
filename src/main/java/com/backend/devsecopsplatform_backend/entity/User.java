package com.backend.devsecopsplatform_backend.entity;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import lombok.Data;
import java.util.List;
import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.NoArgsConstructor;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.UpdateTimestamp;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.UUID;

@Entity
@Table(name = "users", indexes = {
        @Index(name = "idx_user_email", columnList = "email"),
        @Index(name = "idx_user_status", columnList = "account_status"),

})
@Data
@NoArgsConstructor
@AllArgsConstructor
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    @Column(name = "id", updatable = false, nullable = false)
    private UUID id;

    @Column(name = "username", unique = true, nullable = false, length = 100)
    private String username;

    @Column(name = "email", unique = true, nullable = false, length = 255)
    private String email;

    @Column(name = "password_hash", nullable = false, length = 255)
    private String password;

    @ElementCollection(fetch = FetchType.EAGER)
    @CollectionTable(name = "user_roles", joinColumns = @JoinColumn(name = "user_id"))
    @Enumerated(EnumType.STRING)
    private List<Role> roles;


    @OneToMany(mappedBy = "requestedBy", cascade = CascadeType.ALL, orphanRemoval = true)
    @JsonIgnoreProperties("requestedBy") // Évite la boucle avec EphemeralEnvironment
    private List<EphemeralEnvironment> ephemeralEnvironments = new ArrayList<>();

    @Enumerated(EnumType.STRING)
    @Column(name = "account_status", nullable = false, length = 50)
    private AccountStatus accountStatus = AccountStatus.PENDING;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "validated_by")
    private User validatedBy;

    @Column(name = "validated_at")
    private LocalDateTime validatedAt;

    @Column(name = "rejection_reason", length = 500)
    private String rejectionReason;

    @CreationTimestamp
    @Column(name = "created_at", nullable = false, updatable = false)
    private LocalDateTime createdAt;

    @UpdateTimestamp
    @Column(name = "updated_at")
    private LocalDateTime updatedAt;

    @OneToMany(mappedBy = "createdBy", cascade = CascadeType.ALL, orphanRemoval = true)
    @JsonIgnoreProperties("createdBy") // Évite la boucle avec Application
    private List<Application> applications = new ArrayList<>();


    public boolean canLogin() {
        return accountStatus == AccountStatus.APPROVED;
    }
    public boolean isAdmin() {
        return roles != null && roles.contains(Role.ROLE_ADMIN);
    }
    public boolean isPending() {
        return accountStatus == AccountStatus.PENDING;
    }
    public void approve(User admin) {
        this.accountStatus = AccountStatus.APPROVED;
        this.validatedBy = admin;
        this.validatedAt = LocalDateTime.now();
        this.rejectionReason = null;
    }
    public void reject(User admin, String reason) {
        this.accountStatus = AccountStatus.REJECTED;
        this.validatedBy = admin;
        this.validatedAt = LocalDateTime.now();
        this.rejectionReason = reason;
    }
    public void suspend(String reason) {
        this.accountStatus = AccountStatus.SUSPENDED;
        this.rejectionReason = reason;
    }
}