package com.backend.devsecopsplatform_backend.service.auth;

import com.backend.devsecopsplatform_backend.controller.user.TwoFactorSetupResponse;
import com.backend.devsecopsplatform_backend.entity.AuditAction;
import com.backend.devsecopsplatform_backend.entity.TwoFactorMethod;
import com.backend.devsecopsplatform_backend.entity.User;
import com.backend.devsecopsplatform_backend.repository.UserRepository;
import com.backend.devsecopsplatform_backend.service.security.EmailSendResult;
import com.backend.devsecopsplatform_backend.service.security.EmailService;
import com.backend.devsecopsplatform_backend.service.security.SecurityEventService;
import com.backend.devsecopsplatform_backend.util.IpAddressUtils;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

@Service
@RequiredArgsConstructor
public class TwoFactorAuthService {

    private static final int SETUP_TTL_MINUTES = 10;

    private final TotpService totpService;
    private final UserRepository userRepository;
    private final SecurityEventService securityEventService;
    private final EmailService emailService;
    private final TwoFactorEmailOtpService emailOtpService;

    /** Secret TOTP en attente de validation (activation ou changement de méthode). */
    private final Map<UUID, PendingTotpSetup> pendingTotpSetups = new ConcurrentHashMap<>();

    @Transactional(readOnly = true)
    public boolean isEnabled(User user) {
        return user != null && user.isTwoFactorEnabled();
    }

    @Transactional(readOnly = true)
    public Map<String, Object> status(User user) {
        TwoFactorMethod method = user.getTwoFactorMethod();
        return Map.of(
                "enabled", user.isTwoFactorEnabled(),
                "required", !user.isTwoFactorEnabled(),
                "mandatory", true,
                "method", method != null ? method.name() : "",
                "accountEmail", user.getEmail() != null ? user.getEmail() : "",
                "enabledAt", user.getTotpEnabledAt() != null ? user.getTotpEnabledAt().toString() : ""
        );
    }

    @Transactional
    public TwoFactorSetupResponse startTotpSetup(User user, String currentPassword, PasswordEncoder passwordEncoder) {
        requirePasswordIfSwitching(user, currentPassword, passwordEncoder);
        String secret = totpService.generatePlainSecret();
        String otpAuthUrl = totpService.buildOtpAuthUrl(user.getUsername(), secret);
        pendingTotpSetups.put(user.getId(), new PendingTotpSetup(secret, LocalDateTime.now().plusMinutes(SETUP_TTL_MINUTES)));
        return new TwoFactorSetupResponse(otpAuthUrl, secret, issuerName());
    }

    @Transactional
    public EmailSendResult sendEmailSetupCode(User user, String currentPassword, PasswordEncoder passwordEncoder) {
        requirePasswordIfSwitching(user, currentPassword, passwordEncoder);
        String code = emailOtpService.createForUser(user.getId());
        return emailService.sendTwoFactorCode(user, code, "activation de la double authentification");
    }

    @Transactional
    public void enableTotp(User user, String code, String currentPassword, String ipAddress, PasswordEncoder passwordEncoder) {
        requirePasswordIfSwitching(user, currentPassword, passwordEncoder);
        PendingTotpSetup pending = requirePendingTotpSetup(user.getId());
        if (!totpService.verifyPlainSecret(pending.plainSecret(), code)) {
            throw new IllegalArgumentException("Code incorrect. Vérifiez l'application d'authentification.");
        }

        TwoFactorMethod previous = user.getTwoFactorMethod();
        user.setTotpSecretEncrypted(totpService.encryptSecret(pending.plainSecret()));
        user.setTotpEnabled(true);
        user.setTotpEnabledAt(LocalDateTime.now());
        user.setTwoFactorMethod(TwoFactorMethod.TOTP);
        userRepository.save(user);
        pendingTotpSetups.remove(user.getId());
        emailOtpService.clearForUser(user.getId());

        recordEnabledOrSwitched(user, previous, "TOTP", ipAddress);
    }

    @Transactional
    public void enableEmail(User user, String code, String currentPassword, String ipAddress, PasswordEncoder passwordEncoder) {
        requirePasswordIfSwitching(user, currentPassword, passwordEncoder);
        if (!emailOtpService.verifyForUser(user.getId(), code)) {
            throw new IllegalArgumentException("Code e-mail incorrect ou expiré. Demandez un nouveau code.");
        }

        TwoFactorMethod previous = user.getTwoFactorMethod();
        user.setTotpEnabled(false);
        user.setTotpSecretEncrypted(null);
        user.setTwoFactorMethod(TwoFactorMethod.EMAIL);
        user.setTotpEnabledAt(LocalDateTime.now());
        userRepository.save(user);
        pendingTotpSetups.remove(user.getId());

        recordEnabledOrSwitched(user, previous, "EMAIL", ipAddress);
    }

    @Transactional
    public void disable(User user, String code, String currentPassword, String ipAddress, PasswordEncoder passwordEncoder) {
        if (!user.isTwoFactorEnabled()) {
            throw new IllegalStateException("La double authentification n'est pas activée.");
        }
        if (currentPassword == null || currentPassword.isBlank()) {
            throw new IllegalArgumentException("Le mot de passe actuel est obligatoire.");
        }
        if (!passwordEncoder.matches(currentPassword, user.getPassword())) {
            throw new IllegalArgumentException("Mot de passe actuel incorrect.");
        }
        if (user.getTwoFactorMethod() == TwoFactorMethod.TOTP
                && !totpService.verifyEncryptedSecret(user.getTotpSecretEncrypted(), code)) {
            throw new IllegalArgumentException("Code TOTP incorrect.");
        }
        if (user.getTwoFactorMethod() == TwoFactorMethod.EMAIL
                && !emailOtpService.peekForUser(user.getId(), code)) {
            throw new IllegalArgumentException("Code e-mail incorrect.");
        }
        throw new IllegalArgumentException("La double authentification est obligatoire. Vous pouvez changer de méthode, pas la supprimer.");
    }

    @Transactional(readOnly = true)
    public boolean verifyLoginCode(User user, String code, String emailOtpFromPending) {
        if (user.getTwoFactorMethod() == TwoFactorMethod.EMAIL) {
            if (emailOtpFromPending == null || code == null) {
                return false;
            }
            return emailOtpFromPending.equals(code.replaceAll("\\s", ""));
        }
        return totpService.verifyEncryptedSecret(user.getTotpSecretEncrypted(), code);
    }

    public String generateLoginEmailCode() {
        return emailOtpService.generateCode();
    }

    public EmailSendResult sendLoginEmailCode(User user, String pendingLoginId, PendingLoginService pendingLoginService) {
        String code = emailOtpService.generateCode();
        pendingLoginService.updateEmailOtp(pendingLoginId, code);
        return emailService.sendTwoFactorCode(user, code, "connexion");
    }

    private void requirePasswordIfSwitching(User user, String currentPassword, PasswordEncoder passwordEncoder) {
        if (!user.isTwoFactorEnabled()) {
            return;
        }
        if (currentPassword == null || currentPassword.isBlank()) {
            throw new IllegalArgumentException("Le mot de passe actuel est obligatoire pour changer de méthode.");
        }
        if (!passwordEncoder.matches(currentPassword, user.getPassword())) {
            throw new IllegalArgumentException("Mot de passe actuel incorrect.");
        }
    }

    private PendingTotpSetup requirePendingTotpSetup(UUID userId) {
        PendingTotpSetup pending = pendingTotpSetups.get(userId);
        if (pending == null || pending.expiresAt().isBefore(LocalDateTime.now())) {
            pendingTotpSetups.remove(userId);
            throw new IllegalStateException("Configuration TOTP expirée. Relancez la configuration.");
        }
        return pending;
    }

    private void recordEnabledOrSwitched(User user, TwoFactorMethod previous, String newMethod, String ipAddress) {
        String ip = IpAddressUtils.normalize(ipAddress);
        if (previous == null) {
            securityEventService.recordAudit(
                    AuditAction.TWO_FACTOR_ENABLED,
                    user,
                    "Double authentification activée (" + newMethod + ")",
                    user.getUsername(),
                    ip
            );
            return;
        }
        if (previous.name().equals(newMethod)) {
            return;
        }
        securityEventService.recordAudit(
                AuditAction.TWO_FACTOR_METHOD_CHANGED,
                user,
                "Méthode 2FA : " + previous.name() + " → " + newMethod,
                user.getUsername(),
                ip
        );
    }

    private String issuerName() {
        return "EnviroTest";
    }

    public Optional<PendingTotpSetup> findPendingTotpSetup(UUID userId) {
        PendingTotpSetup pending = pendingTotpSetups.get(userId);
        if (pending == null || pending.expiresAt().isBefore(LocalDateTime.now())) {
            pendingTotpSetups.remove(userId);
            return Optional.empty();
        }
        return Optional.of(pending);
    }

    public record PendingTotpSetup(String plainSecret, LocalDateTime expiresAt) {}
}
