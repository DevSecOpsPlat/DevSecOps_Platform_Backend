package com.backend.devsecopsplatform_backend.entity;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.UpdateTimestamp;

import java.time.LocalDateTime;
import java.util.UUID;

@Entity
@Table(name = "ai_remediation_cache", indexes = {
        @Index(name = "idx_ai_remediation_cache_key", columnList = "cache_key", unique = true)
})
@Data
@NoArgsConstructor
@AllArgsConstructor
public class AiRemediationCache {

    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    @Column(name = "id", updatable = false, nullable = false)
    private UUID id;

    @Column(name = "cache_key", nullable = false, unique = true, length = 64)
    private String cacheKey;

    @Column(name = "response_json", nullable = false, columnDefinition = "TEXT")
    private String responseJson;

    @Column(name = "source_type", nullable = false, length = 32)
    private String sourceType;

    @Column(name = "provider", length = 32)
    private String provider;

    @Column(name = "model", length = 128)
    private String model;

    @Column(name = "hit_count", nullable = false)
    private int hitCount = 0;

    @CreationTimestamp
    @Column(name = "created_at", nullable = false, updatable = false)
    private LocalDateTime createdAt;

    @UpdateTimestamp
    @Column(name = "last_used_at")
    private LocalDateTime lastUsedAt;
}
