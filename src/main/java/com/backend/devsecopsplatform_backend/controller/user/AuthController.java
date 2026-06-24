package com.backend.devsecopsplatform_backend.controller.user;

import com.backend.devsecopsplatform_backend.configuration.JwtUtils;
import com.backend.devsecopsplatform_backend.entity.AuditAction;
import com.backend.devsecopsplatform_backend.entity.TwoFactorMethod;
import com.backend.devsecopsplatform_backend.entity.User;
import com.backend.devsecopsplatform_backend.repository.UserRepository;
import com.backend.devsecopsplatform_backend.service.auth.LoginAuditService;
import com.backend.devsecopsplatform_backend.service.auth.LoginFailureResult;
import com.backend.devsecopsplatform_backend.service.auth.PendingLoginService;
import com.backend.devsecopsplatform_backend.service.auth.PendingLoginService.PendingLogin;
import com.backend.devsecopsplatform_backend.service.auth.TwoFactorAuthService;
import com.backend.devsecopsplatform_backend.service.security.AccountActivationService;
import com.backend.devsecopsplatform_backend.service.security.EmailSendResult;
import com.backend.devsecopsplatform_backend.service.security.SecurityEventService;
import com.backend.devsecopsplatform_backend.service.security.monitoring.IpBruteForceService;
import com.backend.devsecopsplatform_backend.util.IpAddressUtils;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Duration;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class AuthController {
    private final UserRepository userRepository;
    private final AuthenticationManager authenticationManager;
    private final JwtUtils jwtUtils;
    private final LoginAuditService loginAuditService;
    private final AccountActivationService accountActivationService;
    private final IpBruteForceService ipBruteForceService;
    private final PendingLoginService pendingLoginService;
    private final TwoFactorAuthService twoFactorAuthService;
    private final SecurityEventService securityEventService;
    private static final Logger log = LoggerFactory.getLogger(AuthController.class);
    private static final DateTimeFormatter LOCK_FMT = DateTimeFormatter.ofPattern("dd/MM/yyyy HH:mm");

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody User loginRequest, HttpServletRequest request) {
        User user = null;
        String ip = IpAddressUtils.resolve(request);
        try {
            ipBruteForceService.checkIpBlockedBeforeLogin(ip);

            String identifier = loginRequest.getUsername();
            user = userRepository.findByUsername(identifier)
                    .orElseGet(() -> userRepository.findByEmail(identifier).orElse(null));

            if (user == null) {
                ipBruteForceService.recordAnonymousFailure(ip, identifier);
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                        .body(Map.of("message", "Identifiants invalides."));
            }

            if (user.isPendingActivation()) {
                return ResponseEntity.status(HttpStatus.FORBIDDEN)
                        .body(Map.of("message",
                                "Compte non activé. Consultez votre e-mail pour définir votre mot de passe."));
            }

            if (user.isLocked()) {
                return lockedResponse(user);
            }

            if (!user.isAdmin() && !user.canLogin()) {
                loginAuditService.recordFailure(user, ip);
                return ResponseEntity.status(HttpStatus.FORBIDDEN)
                        .body(Map.of("message", "Votre compte est désactivé. Contactez un administrateur."));
            }

            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(
                            user.getUsername(),
                            loginRequest.getPassword()
                    )
            );

            if (authentication.isAuthenticated()) {
                if (user.isTwoFactorEnabled()) {
                    Map<String, Object> body = new HashMap<>();
                    String pendingLoginId;
                    if (user.getTwoFactorMethod() == TwoFactorMethod.EMAIL) {
                        String code = twoFactorAuthService.generateLoginEmailCode();
                        pendingLoginId = pendingLoginService.create(user.getId(), ip, code);
                        EmailSendResult sent = twoFactorAuthService.sendLoginEmailCode(user, pendingLoginId, pendingLoginService);
                        body.put("emailSent", sent.sent());
                        body.put("message", sent.sent()
                                ? "Un code a été envoyé à votre adresse e-mail de compte."
                                : "Impossible d'envoyer le code : " + sent.detail());
                    } else {
                        pendingLoginId = pendingLoginService.create(user.getId(), ip);
                        body.put("message", "Saisissez le code à 6 chiffres de votre application d'authentification.");
                    }
                    body.put("requiresTwoFactor", true);
                    body.put("pendingLoginId", pendingLoginId);
                    body.put("username", user.getUsername());
                    body.put("twoFactorMethod", user.getTwoFactorMethod().name());
                    return ResponseEntity.ok(body);
                }

                loginAuditService.recordSuccess(user, ip);
                return ResponseEntity.ok(buildAuthResponse(user));
            }

            return failedLoginResponse(user, ip);

        } catch (AuthenticationException e) {
            log.error("Login error: {}", e.getMessage());
            if (user != null) {
                return failedLoginResponse(user, ip);
            }
            ipBruteForceService.recordAnonymousFailure(ip, loginRequest.getUsername());
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(Map.of("message", "Identifiants invalides."));
        } catch (IpBruteForceService.IpBlockedException e) {
            return ResponseEntity.status(HttpStatus.TOO_MANY_REQUESTS)
                    .body(Map.of("message", e.getMessage()));
        }
    }

    @PostMapping("/verify-2fa")
    public ResponseEntity<?> verifyTwoFactor(@RequestBody VerifyTwoFactorLoginRequest body, HttpServletRequest request) {
        String ip = IpAddressUtils.resolve(request);
        try {
            ipBruteForceService.checkIpBlockedBeforeLogin(ip);
        } catch (IpBruteForceService.IpBlockedException e) {
            return ResponseEntity.status(HttpStatus.TOO_MANY_REQUESTS)
                    .body(Map.of("message", e.getMessage()));
        }

        Optional<PendingLogin> pendingOpt = pendingLoginService.findValid(body.pendingLoginId());
        if (pendingOpt.isEmpty()) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(Map.of("message", "Session expirée. Reconnectez-vous avec votre mot de passe."));
        }

        PendingLogin pending = pendingOpt.get();
        User user = userRepository.findOneById(pending.userId())
                .orElse(null);
        if (user == null || !user.isTwoFactorEnabled()) {
            pendingLoginService.remove(body.pendingLoginId());
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(Map.of("message", "Session invalide."));
        }

        if (user.isLocked()) {
            return lockedResponse(user);
        }

        Optional<PendingLogin> pendingOptForVerify = pendingLoginService.findValid(body.pendingLoginId());
        String emailOtp = pendingOptForVerify.map(PendingLogin::emailOtpCode).orElse(null);

        if (!twoFactorAuthService.verifyLoginCode(user, body.code(), emailOtp)) {
            securityEventService.recordAudit(
                    AuditAction.TWO_FACTOR_FAILED,
                    user,
                    "Code TOTP incorrect à la connexion — IP : " + ip,
                    user.getUsername(),
                    ip
            );
            LoginFailureResult result = loginAuditService.recordFailure(user, ip);
            userRepository.findOneById(user.getId()).ifPresent(u -> user.setLockedUntil(u.getLockedUntil()));
            if (result.accountLocked() || user.isLocked()) {
                pendingLoginService.remove(body.pendingLoginId());
                return lockedResponse(user);
            }
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(Map.of("message", "Code incorrect. Vérifiez l'heure de votre téléphone et réessayez."));
        }

        pendingLoginService.remove(body.pendingLoginId());
        loginAuditService.recordSuccess(user, ip);
        return ResponseEntity.ok(buildAuthResponse(user));
    }

    @PostMapping("/resend-2fa")
    public ResponseEntity<?> resendTwoFactor(@RequestBody ResendTwoFactorLoginRequest body, HttpServletRequest request) {
        String ip = IpAddressUtils.resolve(request);
        try {
            ipBruteForceService.checkIpBlockedBeforeLogin(ip);
        } catch (IpBruteForceService.IpBlockedException e) {
            return ResponseEntity.status(HttpStatus.TOO_MANY_REQUESTS)
                    .body(Map.of("message", e.getMessage()));
        }

        Optional<PendingLogin> pendingOpt = pendingLoginService.findValid(body.pendingLoginId());
        if (pendingOpt.isEmpty()) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(Map.of("message", "Session expirée. Reconnectez-vous avec votre mot de passe."));
        }

        PendingLogin pending = pendingOpt.get();
        User user = userRepository.findOneById(pending.userId()).orElse(null);
        if (user == null || !user.isTwoFactorEnabled() || user.getTwoFactorMethod() != TwoFactorMethod.EMAIL) {
            return ResponseEntity.badRequest().body(Map.of("message", "Renvoi de code non disponible."));
        }

        EmailSendResult sent = twoFactorAuthService.sendLoginEmailCode(user, body.pendingLoginId(), pendingLoginService);
        if (!sent.sent()) {
            return ResponseEntity.badRequest().body(Map.of("message", sent.detail(), "emailSent", false));
        }
        return ResponseEntity.ok(Map.of(
                "message", "Un nouveau code a été envoyé à votre adresse e-mail de compte.",
                "emailSent", true
        ));
    }

    @PostMapping("/activate")
    public ResponseEntity<?> activate(@RequestBody ActivateAccountRequest body, HttpServletRequest request) {
        try {
            accountActivationService.activateAccount(
                    body.token(),
                    body.newPassword(),
                    IpAddressUtils.resolve(request)
            );
            return ResponseEntity.ok(Map.of("message", "Compte activé. Vous pouvez vous connecter."));
        } catch (IllegalArgumentException e) {
            return ResponseEntity.badRequest().body(Map.of("message", e.getMessage()));
        }
    }

    private Map<String, Object> buildAuthResponse(User user) {
        String accessToken = jwtUtils.generateToken(user.getUsername(), user.getRoles());
        Map<String, Object> authData = new HashMap<>();
        authData.put("accessToken", accessToken);
        authData.put("tokenType", "Bearer");
        authData.put("username", user.getUsername());
        authData.put("email", user.getEmail() != null ? user.getEmail() : "");
        authData.put("id", user.getId());
        authData.put("roles", user.getRoles().stream().map(Enum::name).toList());
        authData.put("mustChangePassword", user.isMustChangePassword());
        authData.put("twoFactorEnabled", user.isTwoFactorEnabled());
        authData.put("totpEnabled", user.isTwoFactorEnabled());
        authData.put("twoFactorMethod", user.getTwoFactorMethod() != null ? user.getTwoFactorMethod().name() : "");
        authData.put("mustEnableTwoFactor", !user.isTwoFactorEnabled());
        authData.put("requiresTwoFactor", false);
        return authData;
    }

    private ResponseEntity<Map<String, Object>> failedLoginResponse(User user, String ip) {
        LoginFailureResult result = loginAuditService.recordFailure(user, ip);
        userRepository.findOneById(user.getId()).ifPresent(u -> user.setLockedUntil(u.getLockedUntil()));

        if (result.accountLocked() || user.isLocked()) {
            return lockedResponse(user);
        }

        Map<String, Object> body = new HashMap<>();
        body.put("message", "Identifiants invalides.");
        body.put("accountLocked", false);
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(body);
    }

    private ResponseEntity<Map<String, Object>> lockedResponse(User user) {
        LocalDateTime until = user.getLockedUntil();
        long minutesLeft = until != null
                ? Math.max(1, Duration.between(LocalDateTime.now(), until).toMinutes() + 1)
                : LoginAuditService.LOCKOUT_MINUTES;

        Map<String, Object> body = new HashMap<>();
        body.put("message", String.format(
                "Compte verrouillé pendant %d minutes après 3 tentatives incorrectes. Réessayez à partir du %s.",
                LoginAuditService.LOCKOUT_MINUTES,
                until != null ? until.format(LOCK_FMT) : "—"
        ));
        body.put("accountLocked", true);
        body.put("lockedUntil", until != null ? until.toString() : null);
        body.put("minutesRemaining", minutesLeft);
        body.put("remainingAttempts", 0);
        return ResponseEntity.status(HttpStatus.LOCKED).body(body);
    }
}
