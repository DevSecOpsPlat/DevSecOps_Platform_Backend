package com.backend.devsecopsplatform_backend.controller.user;

import com.backend.devsecopsplatform_backend.configuration.JwtUtils;
import com.backend.devsecopsplatform_backend.entity.User;
import com.backend.devsecopsplatform_backend.repository.UserRepository;
import com.backend.devsecopsplatform_backend.service.auth.LoginAuditService;
import com.backend.devsecopsplatform_backend.service.auth.LoginFailureResult;
import com.backend.devsecopsplatform_backend.service.security.AccountActivationService;
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

@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class AuthController {
    private final UserRepository userRepository;
    private final AuthenticationManager authenticationManager;
    private final JwtUtils jwtUtils;
    private final LoginAuditService loginAuditService;
    private final AccountActivationService accountActivationService;
    private static final Logger log = LoggerFactory.getLogger(AuthController.class);
    private static final DateTimeFormatter LOCK_FMT = DateTimeFormatter.ofPattern("dd/MM/yyyy HH:mm");

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody User loginRequest, HttpServletRequest request) {
        User user = null;
        String ip = IpAddressUtils.resolve(request);
        try {
            String identifier = loginRequest.getUsername();
            user = userRepository.findByUsername(identifier)
                    .orElseGet(() -> userRepository.findByEmail(identifier).orElse(null));

            if (user == null) {
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
                loginAuditService.recordSuccess(user, ip);

                String accessToken = jwtUtils.generateToken(user.getUsername(), user.getRoles());

                Map<String, Object> authData = new HashMap<>();
                authData.put("accessToken", accessToken);
                authData.put("tokenType", "Bearer");
                authData.put("username", user.getUsername());
                authData.put("email", user.getEmail() != null ? user.getEmail() : "");
                authData.put("id", user.getId());
                authData.put("roles", user.getRoles().stream().map(Enum::name).toList());
                authData.put("mustChangePassword", user.isMustChangePassword());

                return ResponseEntity.ok(authData);
            }

            return failedLoginResponse(user, ip);

        } catch (AuthenticationException e) {
            log.error("Login error: {}", e.getMessage());
            if (user != null) {
                return failedLoginResponse(user, ip);
            }
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(Map.of("message", "Identifiants invalides."));
        }
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
