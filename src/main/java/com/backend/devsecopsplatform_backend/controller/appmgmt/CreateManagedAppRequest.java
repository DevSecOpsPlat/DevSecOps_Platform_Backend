package com.backend.devsecopsplatform_backend.controller.appmgmt;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.Data;

@Data
public class CreateManagedAppRequest {

    @NotBlank(message = "Le nom est obligatoire")
    @Size(max = 200)
    private String name;

    @Size(max = 5000)
    private String description;
}
