package com.backend.devsecopsplatform_backend.entity.appmgmt;

import com.backend.devsecopsplatform_backend.configuration.AppCryptoConverter;
import com.fasterxml.jackson.annotation.JsonIgnore;
import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.UpdateTimestamp;

import java.time.Instant;
import java.util.UUID;

/**
 * Ressource base de données managée (cf. architecture.md §2.3). Provisionnée par la
 * plateforme depuis une image officielle + volume persistant + Secret credentials.
 */
@Entity
@Table(name = "app_database", indexes = {
        @Index(name = "idx_appdb_application", columnList = "application_id")
})
@Data
@NoArgsConstructor
@AllArgsConstructor
public class AppDatabase {

    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    @Column(name = "id", updatable = false, nullable = false)
    private UUID id;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "application_id", nullable = false)
    @JsonIgnore
    private ManagedApplication application;

    @Column(name = "name", nullable = false, length = 120)
    private String name;

    @Enumerated(EnumType.STRING)
    @Column(name = "db_family", nullable = false, length = 20)
    private DbFamily dbFamily;

    @Enumerated(EnumType.STRING)
    @Column(name = "engine", nullable = false, length = 20)
    private DbEngine engine;

    @Column(name = "version", nullable = false, length = 40)
    private String version;

    @Column(name = "db_name", nullable = false, length = 120)
    private String dbName;

    @Column(name = "root_user", nullable = false, length = 120)
    private String rootUser;

    /** Chiffré au repos (AES-256-GCM), masqué dans l'API. */
    @Convert(converter = AppCryptoConverter.class)
    @Column(name = "root_password", nullable = false, length = 1000)
    private String rootPassword;

    @Column(name = "exposed_port", nullable = false)
    private Integer exposedPort;

    @Column(name = "storage_size", nullable = false, length = 20)
    private String storageSize = "1Gi";

    /** Rempli par la plateforme après déploiement, lecture seule côté UI. */
    @Column(name = "generated_connection_url", length = 1000)
    private String generatedConnectionUrl;

    @CreationTimestamp
    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt;

    @UpdateTimestamp
    @Column(name = "updated_at")
    private Instant updatedAt;
}
