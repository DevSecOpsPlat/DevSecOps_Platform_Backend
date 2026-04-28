package com.backend.devsecopsplatform_backend.controller.admin;

import com.backend.devsecopsplatform_backend.entity.User;
import com.backend.devsecopsplatform_backend.service.admin.AdminUserService;
import com.backend.devsecopsplatform_backend.service.admin.dto.AdminUserMetricsResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.UUID;

@RestController
@RequestMapping("/api/admin")
@RequiredArgsConstructor
@Slf4j
@CrossOrigin(origins = "http://localhost:4200")
public class AdminController {

    private final AdminUserService adminUserService;

    /**
     * GET /api/admin/pending-users
     * Liste les utilisateurs en attente de validation.
     */
    public record PendingUserResponse(UUID id, String username, String email, String accountStatus, String createdAt) {}

    @GetMapping("/pending-users")
    public ResponseEntity<List<PendingUserResponse>> getPendingUsers() {
        List<User> users = adminUserService.getPendingUsers();
        List<PendingUserResponse> dto = users.stream()
                .map(u -> new PendingUserResponse(
                        u.getId(),
                        u.getUsername(),
                        u.getEmail(),
                        u.getAccountStatus().name(),
                        u.getCreatedAt() != null ? u.getCreatedAt().toString() : null
                ))
                .toList();
        return ResponseEntity.ok(dto);
    }

    /**
     * POST /api/admin/{id}/approve
     * Approuve un utilisateur (ACCOUNT_STATUS -> APPROVED).
     */
    @PostMapping("/{id}/approve")
    public ResponseEntity<Void> approveUser(@PathVariable("id") UUID id) {
        adminUserService.approveUser(id);
        return ResponseEntity.ok().build();
    }

    /**
     * Request body simple pour le rejet (optionnellement avec raison).
     */
    public record RejectRequest(String reason) {}

    /**
     * POST /api/admin/{id}/reject
     * Rejette un utilisateur (ACCOUNT_STATUS -> REJECTED).
     */
    @PostMapping("/{id}/reject")
    public ResponseEntity<Void> rejectUser(@PathVariable("id") UUID id,
                                           @RequestBody(required = false) RejectRequest request) {
        String reason = request != null ? request.reason() : null;
        adminUserService.rejectUser(id, reason);
        return ResponseEntity.ok().build();
    }

    /**
     * GET /api/admin/users
     * Utilisateurs sans rôle admin : profil, agrégats pipelines / environnements, détail applications et historique des envs.
     */
    @GetMapping("/users")
    public ResponseEntity<java.util.List<AdminUserMetricsResponse>> getAllUsersWithMetrics() {
        return ResponseEntity.ok(adminUserService.getAllUsersWithMetrics());
    }
}

