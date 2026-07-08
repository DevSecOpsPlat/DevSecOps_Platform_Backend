package com.backend.devsecopsplatform_backend.controller.appmgmt;

import com.backend.devsecopsplatform_backend.entity.appmgmt.DbEngine;
import com.backend.devsecopsplatform_backend.entity.appmgmt.DbFamily;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import lombok.Data;

/** Création / modification d'une base de données managée. */
@Data
public class AppDatabaseRequest {

    @NotBlank(message = "Le nom de la base est obligatoire")
    private String name;

    /**
     * Optionnel : dérivé de {@link #engine} côté service ({@code engine.family()}).
     * Conservé pour compatibilité clients existants.
     */
    private DbFamily dbFamily;

    @NotNull(message = "Le moteur est obligatoire")
    private DbEngine engine;

    @NotBlank(message = "La version est obligatoire")
    private String version;

    @NotBlank(message = "Le nom de la base à créer est obligatoire")
    private String dbName;

    /**
     * Optionnel selon le moteur (MySQL/MariaDB/Redis/Cassandra n'utilisent pas ce champ).
     */
    private String rootUser;

    /**
     * Mot de passe root en clair (chiffré au repos). Optionnel en modification :
     * si null/vide, l'ancien mot de passe est conservé.
     */
    private String rootPassword;

    /** Optionnel : pré-rempli selon le moteur si absent. */
    private Integer exposedPort;

    private String storageSize = "1Gi";
}
