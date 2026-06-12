package com.backend.devsecopsplatform_backend.service.user;

import com.backend.devsecopsplatform_backend.controller.user.ChangePasswordRequest;
import com.backend.devsecopsplatform_backend.controller.user.ProfileResponse;
import com.backend.devsecopsplatform_backend.controller.user.UpdateEmailRequest;
import com.backend.devsecopsplatform_backend.entity.Role;
import com.backend.devsecopsplatform_backend.entity.User;
import com.backend.devsecopsplatform_backend.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.regex.Pattern;

@Service
@RequiredArgsConstructor
public class ProfileService {

    private static final Pattern EMAIL_PATTERN =
            Pattern.compile("^[A-Za-z0-9+_.-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}$");

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    @Transactional(readOnly = true)
    public ProfileResponse getCurrentProfile() {
        return toResponse(getCurrentUser());
    }

    @Transactional
    public ProfileResponse updateEmail(UpdateEmailRequest request) {
        if (request.email() == null || request.email().isBlank()) {
            throw new IllegalArgumentException("L'e-mail est obligatoire.");
        }
        if (request.currentPassword() == null || request.currentPassword().isBlank()) {
            throw new IllegalArgumentException("Le mot de passe actuel est obligatoire.");
        }

        User user = getCurrentUser();
        if (!passwordEncoder.matches(request.currentPassword(), user.getPassword())) {
            throw new IllegalArgumentException("Mot de passe actuel incorrect.");
        }

        String email = request.email().trim();
        if (!EMAIL_PATTERN.matcher(email).matches()) {
            throw new IllegalArgumentException("Format d'e-mail invalide.");
        }

        if (userRepository.existsByEmail(email) && !email.equalsIgnoreCase(user.getEmail())) {
            throw new IllegalArgumentException("Cet e-mail est déjà utilisé par un autre compte.");
        }

        user.setEmail(email);
        return toResponse(userRepository.save(user));
    }

    @Transactional
    public void changePassword(ChangePasswordRequest request) {
        if (request.currentPassword() == null || request.currentPassword().isBlank()) {
            throw new IllegalArgumentException("Le mot de passe actuel est obligatoire.");
        }
        if (request.newPassword() == null || request.newPassword().length() < 8) {
            throw new IllegalArgumentException("Le nouveau mot de passe doit contenir au moins 8 caractères.");
        }

        User user = getCurrentUser();
        if (!passwordEncoder.matches(request.currentPassword(), user.getPassword())) {
            throw new IllegalArgumentException("Mot de passe actuel incorrect.");
        }
        if (passwordEncoder.matches(request.newPassword(), user.getPassword())) {
            throw new IllegalArgumentException("Le nouveau mot de passe doit être différent de l'actuel.");
        }

        user.setPassword(passwordEncoder.encode(request.newPassword()));
        userRepository.save(user);
    }

    private ProfileResponse toResponse(User user) {
        List<String> roles = user.getRoles() == null
                ? List.of()
                : user.getRoles().stream().map(Role::name).toList();
        String createdAt = user.getCreatedAt() != null ? user.getCreatedAt().toString() : null;
        return new ProfileResponse(
                user.getId(),
                user.getUsername(),
                user.getEmail(),
                roles,
                user.getAccountStatus().name(),
                createdAt
        );
    }

    private User getCurrentUser() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication == null || authentication.getName() == null) {
            throw new IllegalStateException("Utilisateur non authentifié.");
        }
        return userRepository.findByUsername(authentication.getName())
                .orElseThrow(() -> new IllegalStateException("Utilisateur introuvable."));
    }
}
