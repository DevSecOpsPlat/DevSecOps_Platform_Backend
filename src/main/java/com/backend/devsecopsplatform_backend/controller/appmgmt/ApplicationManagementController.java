package com.backend.devsecopsplatform_backend.controller.appmgmt;

import com.backend.devsecopsplatform_backend.service.appmgmt.ApplicationManagementService;
import com.backend.devsecopsplatform_backend.service.appmgmt.AppValidationException;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;
import java.util.UUID;

/**
 * Gestion des applications managées (services + bases + déploiement K8s multi-services).
 *
 * <p>Contrôleur <strong>nouveau et indépendant</strong>. Base d'URL distincte de l'ancien
 * {@code /api/applications} (repo unique + scan) pour éviter toute collision de mapping et
 * respecter la règle absolue de non-régression : aucun endpoint existant n'est modifié.</p>
 */
@RestController
@RequestMapping("/api/managed-applications")
@RequiredArgsConstructor
@Slf4j
@CrossOrigin(origins = {"http://localhost:4200", "http://envirotest.local", "http://envirotest.local:4200"})
public class ApplicationManagementController {

    private final ApplicationManagementService service;

    // ---------- Applications ----------

    @PostMapping
    public ResponseEntity<?> create(@Valid @RequestBody CreateManagedAppRequest request) {
        return handle(() -> ResponseEntity.ok(service.createApp(request)));
    }

    @GetMapping
    public ResponseEntity<List<ManagedAppResponse>> list() {
        return ResponseEntity.ok(service.listApps());
    }

    @GetMapping("/{id}")
    public ResponseEntity<?> get(@PathVariable UUID id) {
        return handle(() -> ResponseEntity.ok(service.getApp(id)));
    }

    @PutMapping("/{id}")
    public ResponseEntity<?> update(@PathVariable UUID id, @Valid @RequestBody UpdateManagedAppRequest request) {
        return handle(() -> ResponseEntity.ok(service.updateApp(id, request)));
    }

    @DeleteMapping("/{id}")
    public ResponseEntity<?> delete(@PathVariable UUID id) {
        return handle(() -> {
            service.deleteApp(id);
            return ResponseEntity.noContent().build();
        });
    }

    // ---------- Services ----------

    @PostMapping("/{id}/services")
    public ResponseEntity<?> addService(@PathVariable UUID id, @Valid @RequestBody AppServiceRequest request) {
        return handle(() -> ResponseEntity.ok(service.addService(id, request)));
    }

    @PutMapping("/{id}/services/{sid}")
    public ResponseEntity<?> updateService(@PathVariable UUID id, @PathVariable UUID sid,
                                           @Valid @RequestBody AppServiceRequest request) {
        return handle(() -> ResponseEntity.ok(service.updateService(id, sid, request)));
    }

    @DeleteMapping("/{id}/services/{sid}")
    public ResponseEntity<?> deleteService(@PathVariable UUID id, @PathVariable UUID sid) {
        return handle(() -> {
            service.deleteService(id, sid);
            return ResponseEntity.noContent().build();
        });
    }

    // ---------- Databases ----------

    @PostMapping("/{id}/databases")
    public ResponseEntity<?> addDatabase(@PathVariable UUID id, @Valid @RequestBody AppDatabaseRequest request) {
        return handle(() -> ResponseEntity.ok(service.addDatabase(id, request)));
    }

    @PutMapping("/{id}/databases/{dbid}")
    public ResponseEntity<?> updateDatabase(@PathVariable UUID id, @PathVariable UUID dbid,
                                            @Valid @RequestBody AppDatabaseRequest request) {
        return handle(() -> ResponseEntity.ok(service.updateDatabase(id, dbid, request)));
    }

    @DeleteMapping("/{id}/databases/{dbid}")
    public ResponseEntity<?> deleteDatabase(@PathVariable UUID id, @PathVariable UUID dbid) {
        return handle(() -> {
            service.deleteDatabase(id, dbid);
            return ResponseEntity.noContent().build();
        });
    }

    // ---------- Env vars ----------

    @GetMapping("/{id}/services/{sid}/env-vars")
    public ResponseEntity<?> listEnvVars(@PathVariable UUID id, @PathVariable UUID sid) {
        return handle(() -> ResponseEntity.ok(service.listEnvVars(id, sid)));
    }

    @PostMapping("/{id}/services/{sid}/env-vars")
    public ResponseEntity<?> addEnvVar(@PathVariable UUID id, @PathVariable UUID sid,
                                       @Valid @RequestBody EnvVarRequest request) {
        return handle(() -> ResponseEntity.ok(service.addEnvVar(id, sid, request)));
    }

    @PutMapping("/{id}/services/{sid}/env-vars/{vid}")
    public ResponseEntity<?> updateEnvVar(@PathVariable UUID id, @PathVariable UUID sid, @PathVariable UUID vid,
                                          @Valid @RequestBody EnvVarRequest request) {
        return handle(() -> ResponseEntity.ok(service.updateEnvVar(id, sid, vid, request)));
    }

    @DeleteMapping("/{id}/services/{sid}/env-vars/{vid}")
    public ResponseEntity<?> deleteEnvVar(@PathVariable UUID id, @PathVariable UUID sid, @PathVariable UUID vid) {
        return handle(() -> {
            service.deleteEnvVar(id, sid, vid);
            return ResponseEntity.noContent().build();
        });
    }

    // ---------- Déploiements ----------

    @PostMapping("/{id}/deploy")
    public ResponseEntity<?> deploy(@PathVariable UUID id) {
        return handle(() -> ResponseEntity.ok(service.deploy(id)));
    }

    @GetMapping("/{id}/deployments")
    public ResponseEntity<?> listDeployments(@PathVariable UUID id) {
        return handle(() -> ResponseEntity.ok(service.listDeployments(id)));
    }

    @GetMapping("/{id}/deployments/{did}")
    public ResponseEntity<?> getDeployment(@PathVariable UUID id, @PathVariable UUID did) {
        return handle(() -> ResponseEntity.ok(service.getDeployment(id, did)));
    }

    @DeleteMapping("/{id}/deployments/{did}")
    public ResponseEntity<?> teardown(@PathVariable UUID id, @PathVariable UUID did) {
        return handle(() -> ResponseEntity.ok(service.teardownDeployment(id, did)));
    }

    @PostMapping("/{id}/deployments/{did}/reveal-secret")
    public ResponseEntity<?> revealSecret(@PathVariable UUID id, @PathVariable UUID did,
                                          @Valid @RequestBody RevealSecretRequest request) {
        return handle(() -> ResponseEntity.ok(Map.of("value", service.revealSecret(id, request))));
    }

    // ---------- Gestion d'erreurs locale (n'introduit aucun advice global) ----------

    private ResponseEntity<?> handle(java.util.function.Supplier<ResponseEntity<?>> action) {
        try {
            return action.get();
        } catch (AppValidationException e) {
            log.warn("Validation refusée: {}", e.getMessage());
            return ResponseEntity.badRequest().body(Map.of("message", e.getMessage()));
        } catch (Exception e) {
            log.error("Erreur gestion application managée: {}", e.getMessage(), e);
            return ResponseEntity.internalServerError()
                    .body(Map.of("message", "Erreur interne: " + e.getMessage()));
        }
    }
}
