package com.backend.devsecopsplatform_backend.entity.appmgmt;

import com.backend.devsecopsplatform_backend.configuration.AppCryptoConverter;
import com.backend.devsecopsplatform_backend.entity.AppService;
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
 * Variable d'environnement (optionnelle) d'un service, cf. architecture.md §2.4.
 * Table séparée = édition facile en base. La valeur est chiffrée au repos ;
 * elle est masquée dans l'API lorsque {@code isSecret} est vrai.
 */
@Entity
@Table(name = "service_env_var", indexes = {
        @Index(name = "idx_envvar_service", columnList = "app_service_id")
})
@Data
@NoArgsConstructor
@AllArgsConstructor
public class ServiceEnvVar {

    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    @Column(name = "id", updatable = false, nullable = false)
    private UUID id;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "app_service_id", nullable = false)
    @JsonIgnore
    private AppService appService;

    @Column(name = "var_key", nullable = false, length = 200)
    private String varKey;

    /** Chiffré au repos ; si isSecret → injecté via Secret K8s et masqué dans l'API. */
    @Convert(converter = AppCryptoConverter.class)
    @Column(name = "var_value", length = 4000)
    private String varValue;

    @Column(name = "is_secret", nullable = false)
    private boolean isSecret = false;

    @CreationTimestamp
    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt;

    @UpdateTimestamp
    @Column(name = "updated_at")
    private Instant updatedAt;
}
