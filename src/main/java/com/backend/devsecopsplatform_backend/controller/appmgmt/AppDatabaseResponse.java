package com.backend.devsecopsplatform_backend.controller.appmgmt;

import com.backend.devsecopsplatform_backend.entity.appmgmt.DbEngine;
import com.backend.devsecopsplatform_backend.entity.appmgmt.DbFamily;
import lombok.Builder;
import lombok.Data;

import java.time.Instant;
import java.util.UUID;

@Data
@Builder
public class AppDatabaseResponse {
    private UUID id;
    private String name;
    private DbFamily dbFamily;
    private DbEngine engine;
    private String version;
    private String dbName;
    private String rootUser;
    /** Toujours masqué (••••••) — jamais le mot de passe en clair. */
    private String rootPassword;
    private boolean hasRootPassword;
    private Integer exposedPort;
    private String storageSize;
    /** URL de connexion générée, avec le mot de passe masqué. */
    private String generatedConnectionUrl;
    private Instant createdAt;
    private Instant updatedAt;
}
