package com.backend.devsecopsplatform_backend.controller.admin;

import com.backend.devsecopsplatform_backend.service.admin.AdminUserService;
import com.backend.devsecopsplatform_backend.service.admin.dto.AdminUserMetricsResponse;
import com.backend.devsecopsplatform_backend.service.admin.dto.UserActivityResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;
import java.util.UUID;

@RestController
@RequestMapping("/api/admin")
@RequiredArgsConstructor
@Slf4j
@CrossOrigin(origins = {"http://localhost:4200","http://envirotest.local", "http://envirotest.local:4200"})
public class AdminController {

    private final AdminUserService adminUserService;

    /**
     * POST /api/admin/users
     * Crée un compte utilisateur (approuvé immédiatement) — réservé à l'administrateur.
     */
    @PostMapping("/users")
    public ResponseEntity<?> createUser(@RequestBody CreateUserRequest request) {
        try {
            CreateUserResponse created = adminUserService.createUser(request);
            return ResponseEntity.status(HttpStatus.CREATED).body(created);
        } catch (IllegalArgumentException e) {
            return ResponseEntity.badRequest().body(Map.of("message", e.getMessage()));
        }
    }

    /**
     * GET /api/admin/users
     * Utilisateurs sans rôle admin : profil, agrégats pipelines / environnements, détail applications et historique des envs.
     */
    @GetMapping("/users")
    public ResponseEntity<List<AdminUserMetricsResponse>> getAllUsersWithMetrics() {
        return ResponseEntity.ok(adminUserService.getAllUsersWithMetrics());
    }

    /**
     * GET /api/admin/users/dashboard-stats
     * KPI connexions, graphique 30 jours, alertes sécurité (≥ 3 échecs consécutifs).
     */
    @GetMapping("/users/dashboard-stats")
    public ResponseEntity<?> getUsersDashboardStats() {
        return ResponseEntity.ok(adminUserService.getDashboardStats());
    }

    /**
     * GET /api/admin/users/{id}
     * Détail complet d'un utilisateur (profil + métriques + applications + environnements).
     */
    @GetMapping("/users/{id}")
    public ResponseEntity<?> getUser(@PathVariable("id") UUID id) {
        try {
            return ResponseEntity.ok(adminUserService.getUserMetrics(id));
        } catch (IllegalArgumentException e) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body(Map.of("message", e.getMessage()));
        }
    }

    /**
     * GET /api/admin/users/{id}/activity
     * Journal d'activité du compte : création, changements d'e-mail / mot de passe, activation / désactivation.
     */
    @GetMapping("/users/{id}/activity")
    public ResponseEntity<?> getUserActivity(@PathVariable("id") UUID id) {
        try {
            List<UserActivityResponse> activity = adminUserService.getUserActivity(id);
            return ResponseEntity.ok(activity);
        } catch (IllegalArgumentException e) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body(Map.of("message", e.getMessage()));
        }
    }

    /**
     * GET /api/admin/users/{id}/complaints
     * Discussions (réclamations) de l'utilisateur avec l'équipe d'administration.
     */
    @GetMapping("/users/{id}/complaints")
    public ResponseEntity<?> getUserComplaints(@PathVariable("id") UUID id) {
        try {
            return ResponseEntity.ok(adminUserService.getUserComplaints(id));
        } catch (IllegalArgumentException e) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body(Map.of("message", e.getMessage()));
        }
    }

    public record ResetPasswordRequest(String newPassword) {}

    /**
     * PATCH /api/admin/users/{id}/password
     * Réinitialise directement le mot de passe d'un utilisateur (sans l'ancien) — réservé à l'administrateur.
     */
    @PatchMapping("/users/{id}/password")
    public ResponseEntity<?> resetUserPassword(@PathVariable("id") UUID id,
                                               @RequestBody ResetPasswordRequest request) {
        try {
            adminUserService.resetPassword(id, request.newPassword());
            return ResponseEntity.ok(Map.of("message", "Mot de passe réinitialisé avec succès."));
        } catch (IllegalArgumentException e) {
            return ResponseEntity.badRequest().body(Map.of("message", e.getMessage()));
        }
    }

    public record UpdateUserEmailRequest(String email) {}

    /**
     * PATCH /api/admin/users/{id}/email
     * Modifie l'adresse e-mail d'un utilisateur — réservé à l'administrateur.
     */
    @PatchMapping("/users/{id}/email")
    public ResponseEntity<?> updateUserEmail(@PathVariable("id") UUID id,
                                             @RequestBody UpdateUserEmailRequest request) {
        try {
            return ResponseEntity.ok(adminUserService.updateUserEmail(id, request.email()));
        } catch (IllegalArgumentException e) {
            return ResponseEntity.badRequest().body(Map.of("message", e.getMessage()));
        }
    }

    public record UpdateUserStatusRequest(boolean active) {}

    /**
     * PATCH /api/admin/users/{id}/status
     * Active ou désactive un compte. Un compte désactivé ne peut plus se connecter.
     */
    @PatchMapping("/users/{id}/status")
    public ResponseEntity<?> updateUserStatus(@PathVariable("id") UUID id,
                                              @RequestBody UpdateUserStatusRequest request) {
        try {
            return ResponseEntity.ok(adminUserService.setUserStatus(id, request.active()));
        } catch (IllegalArgumentException e) {
            return ResponseEntity.badRequest().body(Map.of("message", e.getMessage()));
        }
    }

    /**
     * DELETE /api/admin/users/{id}
     * Supprime définitivement un compte utilisateur (non admin).
     */
    @DeleteMapping("/users/{id}")
    public ResponseEntity<?> deleteUser(@PathVariable("id") UUID id) {
        try {
            adminUserService.deleteUser(id);
            return ResponseEntity.ok(Map.of("message", "Compte supprimé avec succès."));
        } catch (IllegalArgumentException e) {
            return ResponseEntity.badRequest().body(Map.of("message", e.getMessage()));
        }
    }

    /**
     * POST /api/admin/users/{id}/resend-activation
     * Renvoie l'e-mail d'activation (compte non encore activé).
     */
    @PostMapping("/users/{id}/resend-activation")
    public ResponseEntity<?> resendActivation(@PathVariable("id") UUID id) {
        try {
            return ResponseEntity.ok(adminUserService.resendActivationEmail(id));
        } catch (IllegalArgumentException e) {
            return ResponseEntity.badRequest().body(Map.of("message", e.getMessage()));
        }
    }
}
