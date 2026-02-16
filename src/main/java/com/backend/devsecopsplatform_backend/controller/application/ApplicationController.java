package com.backend.devsecopsplatform_backend.controller.application;


import com.backend.devsecopsplatform_backend.service.application.ApplicationService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.UUID;

@RestController
@RequestMapping("/api/applications")
@RequiredArgsConstructor
@Slf4j
@CrossOrigin(origins = "http://localhost:4200")
public class ApplicationController {

    private final ApplicationService applicationService;

    /**
     * POST /api/applications
     * Crée une nouvelle application avec token GitHub chiffré
     */
    @PostMapping
    public ResponseEntity<ApplicationResponse> createApplication(
            @Valid @RequestBody CreateApplicationRequest request) {

        log.info("📥 Création application: {}", request.getName());

        try {
            ApplicationResponse response = applicationService.createApplication(request);
            return ResponseEntity.ok(response);

        } catch (Exception e) {
            log.error("❌ Erreur création application: {}", e.getMessage());
            return ResponseEntity.internalServerError().build();
        }
    }

    /**
     * GET /api/applications
     * Liste les applications de l'utilisateur connecté
     */
    @GetMapping
    public ResponseEntity<List<ApplicationResponse>> getMyApplications() {
        log.info("📋 Récupération de mes applications");

        List<ApplicationResponse> apps = applicationService.getMyApplications();
        return ResponseEntity.ok(apps);
    }

    /**
     * GET /api/applications/{id}
     * Récupère une application par ID
     */
    @GetMapping("/{id}")
    public ResponseEntity<ApplicationResponse> getApplication(@PathVariable UUID id) {
        log.info("🔍 Récupération application: {}", id);

        try {
            ApplicationResponse app = applicationService.getApplicationById(id);
            return ResponseEntity.ok(app);
        } catch (Exception e) {
            log.error("❌ Application non trouvée: {}", id);
            return ResponseEntity.notFound().build();
        }
    }
}