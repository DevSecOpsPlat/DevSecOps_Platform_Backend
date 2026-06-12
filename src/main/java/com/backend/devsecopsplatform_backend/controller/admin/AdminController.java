package com.backend.devsecopsplatform_backend.controller.admin;

import com.backend.devsecopsplatform_backend.service.admin.AdminUserService;
import com.backend.devsecopsplatform_backend.service.admin.dto.AdminUserMetricsResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

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
}
