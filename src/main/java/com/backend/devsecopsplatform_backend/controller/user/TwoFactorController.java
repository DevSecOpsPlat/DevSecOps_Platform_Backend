package com.backend.devsecopsplatform_backend.controller.user;

import com.backend.devsecopsplatform_backend.entity.TwoFactorMethod;
import com.backend.devsecopsplatform_backend.entity.User;
import com.backend.devsecopsplatform_backend.repository.UserRepository;
import com.backend.devsecopsplatform_backend.service.auth.TwoFactorAuthService;
import com.backend.devsecopsplatform_backend.service.security.EmailSendResult;
import com.backend.devsecopsplatform_backend.util.IpAddressUtils;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/api/profile/2fa")
@RequiredArgsConstructor
public class TwoFactorController {

    private final TwoFactorAuthService twoFactorAuthService;
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    @GetMapping("/status")
    public ResponseEntity<Map<String, Object>> status() {
        return ResponseEntity.ok(twoFactorAuthService.status(getCurrentUser()));
    }

    /** Démarre la configuration TOTP (QR / secret). Mot de passe requis si changement de méthode. */
    @PostMapping("/setup/totp")
    public ResponseEntity<?> setupTotp(@RequestBody(required = false) TwoFactorSetupTotpRequest request) {
        try {
            String password = request != null ? request.currentPassword() : null;
            return ResponseEntity.ok(twoFactorAuthService.startTotpSetup(getCurrentUser(), password, passwordEncoder));
        } catch (IllegalArgumentException | IllegalStateException e) {
            return ResponseEntity.badRequest().body(Map.of("message", e.getMessage()));
        }
    }

    /** Envoie un code au e-mail du compte pour activer ou passer à la 2FA e-mail. */
    @PostMapping("/setup/email")
    public ResponseEntity<?> setupEmail(@RequestBody(required = false) TwoFactorSetupEmailRequest request,
                                          HttpServletRequest httpRequest) {
        try {
            User user = getCurrentUser();
            String password = request != null ? request.currentPassword() : null;
            EmailSendResult result = twoFactorAuthService.sendEmailSetupCode(user, password, passwordEncoder);
            if (!result.sent()) {
                return ResponseEntity.badRequest().body(Map.of(
                        "message", result.detail(),
                        "emailSent", false,
                        "accountEmail", user.getEmail()
                ));
            }
            return ResponseEntity.ok(Map.of(
                    "message", "Code envoyé à " + maskEmail(user.getEmail()) + ".",
                    "emailSent", true,
                    "accountEmail", user.getEmail()
            ));
        } catch (IllegalArgumentException | IllegalStateException e) {
            return ResponseEntity.badRequest().body(Map.of("message", e.getMessage()));
        }
    }

    @PostMapping("/enable/totp")
    public ResponseEntity<?> enableTotp(@RequestBody EnableTwoFactorRequest request, HttpServletRequest httpRequest) {
        try {
            twoFactorAuthService.enableTotp(
                    getCurrentUser(),
                    request.code(),
                    request.currentPassword(),
                    IpAddressUtils.resolve(httpRequest),
                    passwordEncoder
            );
            return ResponseEntity.ok(Map.of(
                    "message", "Double authentification par application activée.",
                    "enabled", true,
                    "method", TwoFactorMethod.TOTP.name()
            ));
        } catch (IllegalArgumentException | IllegalStateException e) {
            return ResponseEntity.badRequest().body(Map.of("message", e.getMessage()));
        }
    }

    @PostMapping("/enable/email")
    public ResponseEntity<?> enableEmail(@RequestBody EnableTwoFactorRequest request, HttpServletRequest httpRequest) {
        try {
            twoFactorAuthService.enableEmail(
                    getCurrentUser(),
                    request.code(),
                    request.currentPassword(),
                    IpAddressUtils.resolve(httpRequest),
                    passwordEncoder
            );
            return ResponseEntity.ok(Map.of(
                    "message", "Double authentification par e-mail activée.",
                    "enabled", true,
                    "method", TwoFactorMethod.EMAIL.name()
            ));
        } catch (IllegalArgumentException | IllegalStateException e) {
            return ResponseEntity.badRequest().body(Map.of("message", e.getMessage()));
        }
    }

    /** Rétrocompatibilité — alias TOTP. */
    @PostMapping("/setup")
    public ResponseEntity<?> setupLegacy() {
        return setupTotp(null);
    }

    /** Rétrocompatibilité — alias TOTP. */
    @PostMapping("/enable")
    public ResponseEntity<?> enableLegacy(@RequestBody EnableTwoFactorRequest request, HttpServletRequest httpRequest) {
        return enableTotp(request, httpRequest);
    }

    @PostMapping("/disable")
    public ResponseEntity<?> disable(@RequestBody DisableTwoFactorRequest request, HttpServletRequest httpRequest) {
        try {
            twoFactorAuthService.disable(
                    getCurrentUser(),
                    request.code(),
                    request.currentPassword(),
                    IpAddressUtils.resolve(httpRequest),
                    passwordEncoder
            );
            return ResponseEntity.ok(Map.of("message", "Double authentification désactivée.", "enabled", false));
        } catch (IllegalArgumentException | IllegalStateException e) {
            return ResponseEntity.badRequest().body(Map.of("message", e.getMessage()));
        }
    }

    private User getCurrentUser() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth == null || auth.getName() == null) {
            throw new IllegalStateException("Utilisateur non authentifié.");
        }
        return userRepository.findByUsername(auth.getName())
                .orElseThrow(() -> new IllegalStateException("Utilisateur introuvable."));
    }

    private static String maskEmail(String email) {
        if (email == null || !email.contains("@")) {
            return "votre e-mail";
        }
        int at = email.indexOf('@');
        String local = email.substring(0, at);
        String domain = email.substring(at);
        if (local.length() <= 2) {
            return local.charAt(0) + "***" + domain;
        }
        return local.substring(0, 2) + "***" + domain;
    }
}
