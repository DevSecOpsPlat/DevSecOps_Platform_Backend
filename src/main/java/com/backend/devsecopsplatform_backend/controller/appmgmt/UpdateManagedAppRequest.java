package com.backend.devsecopsplatform_backend.controller.appmgmt;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.Data;

@Data
public class UpdateManagedAppRequest {

    @NotBlank(message = "Le nom est obligatoire")
    @Size(max = 200)
    private String name;

    @Size(max = 5000)
    private String description;

    /** Hostname personnalisé (ex. demo.example.com). Vide = nip.io par défaut. */
    @Size(max = 253)
    private String customHostname;
}
