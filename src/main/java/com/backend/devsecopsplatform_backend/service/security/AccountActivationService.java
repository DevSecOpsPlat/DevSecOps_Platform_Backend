package com.backend.devsecopsplatform_backend.service.security;

import com.backend.devsecopsplatform_backend.entity.AuditAction;
import com.backend.devsecopsplatform_backend.entity.User;
import com.backend.devsecopsplatform_backend.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.security.SecureRandom;
import java.time.LocalDateTime;
import java.util.Base64;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class AccountActivationService {

    private static final int TOKEN_BYTES = 32;
    private static final int TOKEN_VALIDITY_HOURS = 48;

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final EmailService emailService;
    private final SecurityEventService securityEventService;
    private final SecureRandom secureRandom = new SecureRandom();

    @Transactional
    public AccountPrepareResult prepareNewAccount(User user, String performedBy, String ipAddress) {
        String token = generateToken();
        user.setActivationToken(token);
        user.setActivationTokenExpiresAt(LocalDateTime.now().plusHours(TOKEN_VALIDITY_HOURS));
        user.setActivatedAt(null);
        user.setMustChangePassword(true);
        user.setPassword(passwordEncoder.encode(generateInternalSecret()));
        userRepository.save(user);

        EmailSendResult emailResult = emailService.sendActivationEmail(user, token);
        String auditDetail = emailResult.sent()
                ? "E-mail d'activation envoyé à " + user.getEmail()
                : "E-mail non envoyé — " + emailResult.detail();
        securityEventService.recordAudit(
                AuditAction.ACTIVATION_EMAIL_SENT,
                user,
                auditDetail,
                performedBy,
                ipAddress
        );
        return new AccountPrepareResult(token, emailResult);
    }

    /** Renvoie l'e-mail d'activation (compte non encore activé). */
    @Transactional
    public EmailSendResult resendActivationEmail(UUID userId, String performedBy) {
        User user = userRepository.findOneById(userId)
                .orElseThrow(() -> new IllegalArgumentException("Utilisateur introuvable."));
        if (user.isAdmin()) {
            throw new IllegalArgumentException("Action non applicable aux administrateurs.");
        }
        if (!user.isPendingActivation()) {
            throw new IllegalArgumentException("Ce compte est déjà activé.");
        }
        String token = generateToken();
        user.setActivationToken(token);
        user.setActivationTokenExpiresAt(LocalDateTime.now().plusHours(TOKEN_VALIDITY_HOURS));
        userRepository.save(user);

        EmailSendResult result = emailService.sendActivationEmail(user, token);
        securityEventService.recordAudit(
                AuditAction.ACTIVATION_EMAIL_SENT,
                user,
                result.sent() ? "E-mail d'activation renvoyé" : "Renvoi échoué — " + result.detail(),
                performedBy,
                null
        );
        return result;
    }

    @Transactional
    public void activateAccount(String token, String newPassword, String ipAddress) {
        if (newPassword == null || newPassword.length() < 8) {
            throw new IllegalArgumentException("Le mot de passe doit contenir au moins 8 caractères.");
        }
        User user = userRepository.findByActivationToken(token)
                .orElseThrow(() -> new IllegalArgumentException("Lien d'activation invalide ou expiré."));

        if (user.getActivationTokenExpiresAt() == null
                || user.getActivationTokenExpiresAt().isBefore(LocalDateTime.now())) {
            throw new IllegalArgumentException("Ce lien d'activation a expiré. Contactez un administrateur.");
        }

        user.setPassword(passwordEncoder.encode(newPassword));
        user.setActivationToken(null);
        user.setActivationTokenExpiresAt(null);
        user.setActivatedAt(LocalDateTime.now());
        user.setMustChangePassword(false);
        userRepository.save(user);

        securityEventService.recordAudit(
                AuditAction.ACCOUNT_ACTIVATED,
                user,
                "Compte activé — mot de passe défini",
                user.getUsername(),
                ipAddress
        );
    }

    private String generateToken() {
        byte[] bytes = new byte[TOKEN_BYTES];
        secureRandom.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    private String generateInternalSecret() {
        byte[] bytes = new byte[24];
        secureRandom.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }
}
