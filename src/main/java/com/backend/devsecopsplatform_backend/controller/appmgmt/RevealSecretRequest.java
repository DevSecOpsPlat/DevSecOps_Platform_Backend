package com.backend.devsecopsplatform_backend.controller.appmgmt;

import jakarta.validation.constraints.NotNull;
import lombok.Data;

import java.util.UUID;

/** Révèle ponctuellement un secret précis (audit conseillé). */
@Data
public class RevealSecretRequest {

    public enum SecretType { GIT_TOKEN, DB_PASSWORD, ENV_VAR }

    @NotNull(message = "Le type de secret est obligatoire")
    private SecretType type;

    /** Id de l'entité concernée : app_service (GIT_TOKEN), app_database (DB_PASSWORD) ou service_env_var (ENV_VAR). */
    @NotNull(message = "L'identifiant cible est obligatoire")
    private UUID targetId;
}
