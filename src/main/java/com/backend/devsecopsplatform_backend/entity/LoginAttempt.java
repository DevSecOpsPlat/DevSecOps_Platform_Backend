package com.backend.devsecopsplatform_backend.entity;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.hibernate.annotations.CreationTimestamp;

import java.time.LocalDateTime;
import java.util.UUID;

/**
 * Historique des tentatives de connexion (réussies ou échouées).
 */
@Entity
@Table(name = "login_attempts", indexes = {
        @Index(name = "idx_login_user", columnList = "user_id"),
        @Index(name = "idx_login_attempted_at", columnList = "attempted_at")
})
@Data
@NoArgsConstructor
@AllArgsConstructor
public class LoginAttempt {

    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    @Column(name = "id", updatable = false, nullable = false)
    private UUID id;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "user_id", nullable = false)
    private User user;

    @Column(name = "success", nullable = false)
    private boolean success;

    @Column(name = "ip_address", length = 45)
    private String ipAddress;

    @CreationTimestamp
    @Column(name = "attempted_at", nullable = false, updatable = false)
    private LocalDateTime attemptedAt;
}
