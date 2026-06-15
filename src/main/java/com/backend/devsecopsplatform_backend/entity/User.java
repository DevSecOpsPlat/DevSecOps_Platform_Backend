package com.backend.devsecopsplatform_backend.entity;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
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

    /* WRITE_ONLY : accepté dans les requêtes (login), jamais exposé dans les réponses JSON. */
    @Column(name = "password_hash", nullable = false, length = 255)
    @JsonProperty(access = JsonProperty.Access.WRITE_ONLY)
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
    private AccountStatus accountStatus = AccountStatus.ACTIVE;

    @CreationTimestamp
    @Column(name = "created_at", nullable = false, updatable = false)
    private LocalDateTime createdAt;

    @UpdateTimestamp
    @Column(name = "updated_at")
    private LocalDateTime updatedAt;

    @Column(name = "last_login_at")
    private LocalDateTime lastLoginAt;

    @Column(name = "locked_until")
    private LocalDateTime lockedUntil;

    @Column(name = "must_change_password", nullable = false)
    private boolean mustChangePassword = false;

    @Column(name = "activation_token", length = 64)
    private String activationToken;

    @Column(name = "activation_token_expires_at")
    private LocalDateTime activationTokenExpiresAt;

    @Column(name = "activated_at")
    private LocalDateTime activatedAt;

    @OneToMany(mappedBy = "createdBy", cascade = CascadeType.ALL, orphanRemoval = true)
    @JsonIgnoreProperties("createdBy") // Évite la boucle avec Application
    private List<Application> applications = new ArrayList<>();


    public boolean isActive() {
        return accountStatus == AccountStatus.ACTIVE;
    }

    public boolean canLogin() {
        return isActive() && !isPendingActivation() && !isLocked();
    }

    public boolean isPendingActivation() {
        return activationToken != null && activatedAt == null;
    }

    public boolean isLocked() {
        return lockedUntil != null && lockedUntil.isAfter(LocalDateTime.now());
    }

    public boolean isAdmin() {
        return roles != null && roles.contains(Role.ROLE_ADMIN);
    }
}
