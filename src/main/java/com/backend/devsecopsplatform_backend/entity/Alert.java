package com.backend.devsecopsplatform_backend.entity;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.hibernate.annotations.CreationTimestamp;

import java.time.LocalDateTime;
import java.util.UUID;

@Entity
@Table(name = "alerts", indexes = {
        @Index(name = "idx_alert_status", columnList = "status"),
        @Index(name = "idx_alert_type", columnList = "type"),
        @Index(name = "idx_alert_created", columnList = "created_at")
})
@Data
@NoArgsConstructor
@AllArgsConstructor
public class Alert {

    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    private UUID id;

    @Enumerated(EnumType.STRING)
    @Column(name = "type", nullable = false, length = 50)
    private AlertType type;

    @Column(name = "message", nullable = false, length = 1000)
    private String message;

    @Enumerated(EnumType.STRING)
    @Column(name = "status", nullable = false, length = 20)
    private AlertStatus status = AlertStatus.NON_LUE;

    @Column(name = "deleted", nullable = false)
    private boolean deleted = false;

    @Column(name = "related_user_id")
    private UUID relatedUserId;

    @Column(name = "related_username", length = 100)
    private String relatedUsername;

    @Column(name = "ip_address", length = 45)
    private String ipAddress;

    /** Contexte technique JSON (méthode, URL, headers, payload…) pour le modal détails. */
    @Column(name = "details_json", columnDefinition = "TEXT")
    private String detailsJson;

    @CreationTimestamp
    @Column(name = "created_at", nullable = false, updatable = false)
    private LocalDateTime createdAt;
}
