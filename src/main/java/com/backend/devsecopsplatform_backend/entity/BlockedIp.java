package com.backend.devsecopsplatform_backend.entity;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.hibernate.annotations.CreationTimestamp;

import java.time.LocalDateTime;
import java.util.UUID;

/**
 * Blocages IP actifs — persistés en base pour survivre aux redémarrages.
 */
@Entity
@Table(name = "blocked_ips", indexes = {
        @Index(name = "idx_blocked_ip_address", columnList = "ip_address"),
        @Index(name = "idx_blocked_ip_until", columnList = "blocked_until"),
        @Index(name = "idx_blocked_ip_active", columnList = "active")
})
@Data
@NoArgsConstructor
@AllArgsConstructor
public class BlockedIp {

    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    private UUID id;

    @Column(name = "ip_address", nullable = false, length = 45)
    private String ipAddress;

    @Column(name = "reason", nullable = false, length = 500)
    private String reason;

    @Column(name = "blocked_until", nullable = false)
    private LocalDateTime blockedUntil;

    @Enumerated(EnumType.STRING)
    @Column(name = "source", nullable = false, length = 20)
    private BlockSource source = BlockSource.AUTO;

    @Column(name = "active", nullable = false)
    private boolean active = true;

    @CreationTimestamp
    @Column(name = "created_at", nullable = false, updatable = false)
    private LocalDateTime createdAt;
}
