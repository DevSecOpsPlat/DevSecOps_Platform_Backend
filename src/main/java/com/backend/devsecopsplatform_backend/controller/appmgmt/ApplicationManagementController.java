package com.backend.devsecopsplatform_backend.controller.appmgmt;

import com.backend.devsecopsplatform_backend.service.appmgmt.ApplicationManagementService;
import com.backend.devsecopsplatform_backend.service.appmgmt.AppValidationException;
import com.backend.devsecopsplatform_backend.service.appmgmt.ManagedAppScanService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.MediaType;
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
    private final ManagedAppScanService managedAppScanService;

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
        return handle(() -> ResponseEntity.ok(service.deleteService(id, sid)));
    }

    /**
     * Aperçu ressources avant d'enregistrer une édition de service déjà déployé (quota namespace
     * + capacité nœud, sur l'état RÉEL du cluster) — même garde-fou que la modale Déployer, pour
     * le chemin d'édition qui la contournait jusqu'ici (audit-deploiement.md §8).
     */
    @PostMapping("/{id}/services/{sid}/resource-preview")
    public ResponseEntity<?> previewServiceResourceChange(@PathVariable UUID id, @PathVariable UUID sid,
                                                           @RequestBody AppServiceRequest request) {
        return handle(() -> ResponseEntity.ok(service.previewServiceResourceChange(id, sid, request)));
    }

    // ---------- Scan lot (Chantier 2) ----------

    @PostMapping("/{id}/scan")
    public ResponseEntity<?> scanApp(
            @PathVariable UUID id,
            @RequestBody(required = false) ManagedAppScanRequest request) {
        return handle(() -> ResponseEntity.ok(
                managedAppScanService.scanApplication(id, request != null ? request : new ManagedAppScanRequest())));
    }

    @GetMapping("/{id}/scan-batches")
    public ResponseEntity<?> listScanBatches(@PathVariable UUID id) {
        return handle(() -> ResponseEntity.ok(managedAppScanService.listBatches(id)));
    }

    @GetMapping("/{id}/scan-batches/{batchId}")
    public ResponseEntity<?> getScanBatch(@PathVariable UUID id, @PathVariable UUID batchId) {
        return handle(() -> ResponseEntity.ok(managedAppScanService.getBatch(id, batchId)));
    }

    @GetMapping("/{id}/security-posture")
    public ResponseEntity<?> securityPosture(
            @PathVariable UUID id,
            @RequestParam(required = false) UUID batchId) {
        return handle(() -> ResponseEntity.ok(batchId != null
                ? managedAppScanService.securityPosture(id, batchId)
                : managedAppScanService.securityPosture(id)));
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
        return handle(() -> ResponseEntity.ok(service.deleteDatabase(id, dbid)));
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

    @PostMapping("/{id}/deploy/preview")
    public ResponseEntity<?> deployPreview(
            @PathVariable UUID id,
            @RequestBody(required = false) ManagedDeployRequest request) {
        return handle(() -> ResponseEntity.ok(service.previewDeploy(id, request)));
    }

    @PostMapping("/{id}/deploy")
    public ResponseEntity<?> deploy(
            @PathVariable UUID id,
            @RequestBody(required = false) ManagedDeployRequest request) {
        return handle(() -> ResponseEntity.ok(service.deploy(id, request)));
    }

    @GetMapping("/{id}/deployments")
    public ResponseEntity<?> listDeployments(@PathVariable UUID id) {
        return handle(() -> ResponseEntity.ok(service.listDeployments(id)));
    }

    @GetMapping("/{id}/deployments/{did}")
    public ResponseEntity<?> getDeployment(@PathVariable UUID id, @PathVariable UUID did) {
        return handle(() -> ResponseEntity.ok(service.getDeployment(id, did)));
    }

    /** Temps-machine cumulé (approximatif) — audit-deploiement.md, chantier #10. */
    @GetMapping("/{id}/machine-time")
    public ResponseEntity<?> getMachineTime(@PathVariable UUID id) {
        return handle(() -> ResponseEntity.ok(service.getMachineTimeUsage(id)));
    }

    @DeleteMapping("/{id}/deployments/{did}")
    public ResponseEntity<?> teardown(@PathVariable UUID id, @PathVariable UUID did) {
        return handle(() -> ResponseEntity.ok(service.teardownDeployment(id, did)));
    }

    /** Prolonge le TTL de l'environnement (1–24 h, plafond 72 h depuis Ready). */
    @PostMapping("/{id}/deployments/{did}/extend-ttl")
    public ResponseEntity<?> extendTtl(
            @PathVariable UUID id,
            @PathVariable UUID did,
            @Valid @RequestBody ExtendTtlRequest request) {
        return handle(() -> ResponseEntity.ok(
                service.extendDeploymentTtl(id, did, request.getAdditionalHours())));
    }

    /**
     * Applique les variables d'env du service sur le cluster RUNNING (sans rebuild CI).
     */
    @PostMapping("/{id}/services/{sid}/sync-runtime")
    public ResponseEntity<?> syncServiceRuntime(@PathVariable UUID id, @PathVariable UUID sid) {
        return handle(() -> ResponseEntity.ok(service.syncServiceRuntime(id, sid)));
    }

    /**
     * Rebuild CI d'un seul service dans le namespace RUNNING (même déploiement).
     */
    @PostMapping("/{id}/services/{sid}/rebuild")
    public ResponseEntity<?> rebuildService(@PathVariable UUID id, @PathVariable UUID sid) {
        return handle(() -> ResponseEntity.ok(service.rebuildService(id, sid)));
    }

    /** Objectif 3 (post-deploy) : relance manuelle du smoke test, sans restriction. */
    @PostMapping("/{id}/services/{sid}/smoke-test/rerun")
    public ResponseEntity<?> rerunSmokeTest(@PathVariable UUID id, @PathVariable UUID sid) {
        return handle(() -> ResponseEntity.ok(service.rerunSmokeTest(id, sid)));
    }

    /** Pods du namespace (phase, ready, restarts). */
    @GetMapping("/{id}/deployments/{did}/pods")
    public ResponseEntity<?> listDeploymentPods(@PathVariable UUID id, @PathVariable UUID did) {
        return handle(() -> ResponseEntity.ok(service.listDeploymentPods(id, did)));
    }

    /** Monitoring léger : métriques, alertes, health URL. */
    @GetMapping("/{id}/deployments/{did}/monitoring")
    public ResponseEntity<?> getDeploymentMonitoring(@PathVariable UUID id, @PathVariable UUID did) {
        return handle(() -> ResponseEntity.ok(service.getDeploymentMonitoring(id, did)));
    }

    /** Alertes runtime live + historique (CrashLoop, OOM, Warning K8s FailedCreate…). */
    @GetMapping("/{id}/deployments/{did}/alerts")
    public ResponseEntity<?> getDeploymentAlerts(@PathVariable UUID id, @PathVariable UUID did) {
        return handle(() -> ResponseEntity.ok(service.listDeploymentAlerts(id, did)));
    }

    /**
     * Historique des alertes de l'application, tous environnements confondus.
     * Filtrable par plage de dates (from/to, ISO instant) et par namespace.
     */
    @GetMapping("/{id}/alerts/history")
    public ResponseEntity<?> getAppAlertsHistory(
            @PathVariable UUID id,
            @RequestParam(required = false) String from,
            @RequestParam(required = false) String to,
            @RequestParam(required = false) String namespace) {
        return handle(() -> {
            java.time.Instant fromInst = from != null && !from.isBlank() ? java.time.Instant.parse(from) : null;
            java.time.Instant toInst = to != null && !to.isBlank() ? java.time.Instant.parse(to) : null;
            return ResponseEntity.ok(service.listAppAlertsHistory(id, fromInst, toInst, namespace));
        });
    }

    /** Historique métriques long terme (échantillons CPU/MEM/net). */
    @GetMapping("/{id}/deployments/{did}/metrics/history")
    public ResponseEntity<?> getMetricsHistory(
            @PathVariable UUID id,
            @PathVariable UUID did,
            @RequestParam(required = false) String from,
            @RequestParam(required = false) String to) {
        return handle(() -> {
            java.time.Instant fromInst = from != null && !from.isBlank() ? java.time.Instant.parse(from) : null;
            java.time.Instant toInst = to != null && !to.isBlank() ? java.time.Instant.parse(to) : null;
            return ResponseEntity.ok(service.getDeploymentMetricsHistory(id, did, fromInst, toInst));
        });
    }

    /** Logs d'un workload (label app) ou d'un pod. */
    @GetMapping("/{id}/deployments/{did}/logs")
    public ResponseEntity<?> getDeploymentLogs(
            @PathVariable UUID id,
            @PathVariable UUID did,
            @RequestParam String workload,
            @RequestParam(required = false, defaultValue = "300") Integer tailLines) {
        return handle(() -> ResponseEntity.ok(service.getDeploymentLogs(id, did, workload, tailLines)));
    }

    /** Pipeline GitLab CI du déploiement (jobs + statut, live). */
    @GetMapping("/{id}/deployments/{did}/ci-pipeline")
    public ResponseEntity<?> getDeploymentCiPipeline(@PathVariable UUID id, @PathVariable UUID did) {
        return handle(() -> ResponseEntity.ok(service.getDeploymentCiPipeline(id, did)));
    }

    /** Logs texte d'un job GitLab du pipeline de déploiement. */
    @GetMapping(value = "/{id}/deployments/{did}/ci-jobs/{jobId}/logs", produces = MediaType.TEXT_PLAIN_VALUE)
    public ResponseEntity<?> getDeploymentCiJobLogs(
            @PathVariable UUID id,
            @PathVariable UUID did,
            @PathVariable Long jobId) {
        return handle(() -> ResponseEntity.ok(service.getDeploymentCiJobLogs(id, did, jobId)));
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
