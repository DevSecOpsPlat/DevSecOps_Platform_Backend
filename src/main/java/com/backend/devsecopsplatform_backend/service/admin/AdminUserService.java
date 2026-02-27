package com.backend.devsecopsplatform_backend.service.admin;

import com.backend.devsecopsplatform_backend.entity.AccountStatus;
import com.backend.devsecopsplatform_backend.entity.User;
import com.backend.devsecopsplatform_backend.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.UUID;

@Service
@RequiredArgsConstructor
@Slf4j
public class AdminUserService {

    private final UserRepository userRepository;

    /**
     * Liste des utilisateurs en attente de validation.
     */
    public List<User> getPendingUsers() {
        return userRepository.findByAccountStatus(AccountStatus.PENDING);
    }

    /**
     * Approuve un utilisateur (ACCOUNT_STATUS -> APPROVED).
     */
    public User approveUser(UUID userId) {
        User admin = getCurrentUser();
        User user = findByIdOrThrow(userId);
        user.approve(admin);
        User saved = userRepository.save(user);
        log.info("✅ Utilisateur {} approuvé par {}", saved.getUsername(), admin.getUsername());
        return saved;
    }

    /**
     * Rejette un utilisateur (ACCOUNT_STATUS -> REJECTED).
     */
    public User rejectUser(UUID userId, String reason) {
        User admin = getCurrentUser();
        User user = findByIdOrThrow(userId);
        user.reject(admin, reason != null ? reason : "Rejeté par l'administrateur");
        User saved = userRepository.save(user);
        log.info("🚫 Utilisateur {} rejeté par {} (raison: {})", saved.getUsername(), admin.getUsername(), saved.getRejectionReason());
        return saved;
    }

    private User findByIdOrThrow(UUID id) {
        // Recherche naïve par ID (UUID) : on filtre en mémoire.
        // La volumétrie d'utilisateurs étant faible, cela reste acceptable pour l'administration.
        return userRepository.findAll().stream()
                .filter(u -> id.equals(u.getId()))
                .findFirst()
                .orElseThrow(() -> new RuntimeException("Utilisateur introuvable"));
    }

    private User getCurrentUser() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication == null || authentication.getName() == null) {
            throw new RuntimeException("Administrateur non authentifié");
        }
        return userRepository.findByUsername(authentication.getName())
                .orElseThrow(() -> new RuntimeException("Administrateur non trouvé"));
    }
}

