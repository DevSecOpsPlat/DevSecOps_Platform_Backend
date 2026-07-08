package com.backend.devsecopsplatform_backend.service.admin;

import com.backend.devsecopsplatform_backend.controller.admin.CreateUserRequest;
import com.backend.devsecopsplatform_backend.controller.admin.CreateUserResponse;
import com.backend.devsecopsplatform_backend.dto.complaint.ComplaintApiDto;
import com.backend.devsecopsplatform_backend.entity.AccountStatus;
import com.backend.devsecopsplatform_backend.entity.AppService;
import com.backend.devsecopsplatform_backend.entity.EnvironmentStatus;
import com.backend.devsecopsplatform_backend.entity.EphemeralEnvironment;
import com.backend.devsecopsplatform_backend.entity.PipelineExecution;
import com.backend.devsecopsplatform_backend.entity.PipelineStatus;
import com.backend.devsecopsplatform_backend.entity.Role;
import com.backend.devsecopsplatform_backend.entity.User;
import com.backend.devsecopsplatform_backend.entity.AuditAction;
import com.backend.devsecopsplatform_backend.entity.UserActivityLog;
import com.backend.devsecopsplatform_backend.entity.UserActivityType;
import com.backend.devsecopsplatform_backend.repository.AppServiceRepository;
import com.backend.devsecopsplatform_backend.repository.ComplaintRepository;
import com.backend.devsecopsplatform_backend.repository.EphemeralEnvironmentRepository;
import com.backend.devsecopsplatform_backend.repository.LoginAttemptRepository;
import com.backend.devsecopsplatform_backend.repository.ManagedApplicationRepository;
import com.backend.devsecopsplatform_backend.repository.PipelineExecutionRepository;
import com.backend.devsecopsplatform_backend.repository.UserActivityLogRepository;
import com.backend.devsecopsplatform_backend.repository.UserRepository;
import com.backend.devsecopsplatform_backend.service.admin.dto.AdminEnvironmentStatusBreakdown;
import com.backend.devsecopsplatform_backend.service.admin.dto.AdminPipelineCounts;
import com.backend.devsecopsplatform_backend.service.admin.dto.AdminUserApplicationDetail;
import com.backend.devsecopsplatform_backend.service.admin.dto.AdminUserEnvironmentDetail;
import com.backend.devsecopsplatform_backend.service.admin.dto.AdminUserMetricsResponse;
import com.backend.devsecopsplatform_backend.service.admin.dto.AdminUsersDashboardStats;
import com.backend.devsecopsplatform_backend.service.admin.dto.UserActivityResponse;
import com.backend.devsecopsplatform_backend.service.auth.LoginAuditService;
import com.backend.devsecopsplatform_backend.service.security.AccountActivationService;
import com.backend.devsecopsplatform_backend.service.security.AccountPrepareResult;
import com.backend.devsecopsplatform_backend.service.security.EmailSendResult;
import com.backend.devsecopsplatform_backend.service.security.SecurityEventService;
import com.backend.devsecopsplatform_backend.util.PasswordPolicy;
import com.backend.devsecopsplatform_backend.util.UsernamePolicy;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.EnumMap;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
@Slf4j
public class AdminUserService {

    private final UserRepository userRepository;
    private final EphemeralEnvironmentRepository ephemeralEnvironmentRepository;
    private final PipelineExecutionRepository pipelineExecutionRepository;
    private final AppServiceRepository applicationRepository;
    private final ManagedApplicationRepository managedApplicationRepository;
    private final UserActivityLogRepository activityLogRepository;
    private final ComplaintRepository complaintRepository;
    private final LoginAttemptRepository loginAttemptRepository;
    private final LoginAuditService loginAuditService;
    private final PasswordEncoder passwordEncoder;
    private final AccountActivationService accountActivationService;
    private final SecurityEventService securityEventService;
    private final JdbcTemplate jdbcTemplate;

    /**
     * Crée un compte utilisateur — e-mail d'activation envoyé (sans mot de passe définitif).
     */
    @Transactional
    public CreateUserResponse createUser(CreateUserRequest request) {
        if (request.email() == null || request.email().isBlank()) {
            throw new IllegalArgumentException("L'e-mail est obligatoire.");
        }
        String username = request.username() != null ? request.username().trim() : "";
        UsernamePolicy.validate(username);
        String email = request.email().trim().toLowerCase();
        if (!email.matches("^[A-Za-z0-9+_.-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}$")) {
            throw new IllegalArgumentException("Format d'e-mail invalide.");
        }
        if (userRepository.existsByUsername(username)) {
            throw new IllegalArgumentException("Ce nom d'utilisateur est déjà utilisé.");
        }
        if (userRepository.existsByEmail(email)) {
            throw new IllegalArgumentException("Cet e-mail est déjà utilisé.");
        }

        Role role = request.role() != null ? request.role() : Role.ROLE_TESTER;
        if (role == Role.ROLE_ADMIN) {
            throw new IllegalArgumentException("La création de comptes administrateur via cette API n'est pas autorisée.");
        }

        User admin = getCurrentUser();
        User user = new User();
        user.setUsername(username);
        user.setEmail(email);
        user.setRoles(List.of(role));
        user.setAccountStatus(AccountStatus.ACTIVE);

        AccountPrepareResult activation = accountActivationService.prepareNewAccount(user, admin.getUsername(), null);
        User saved = user;
        EmailSendResult emailResult = activation.emailResult();

        activityLogRepository.save(UserActivityLog.of(
                saved, UserActivityType.ACCOUNT_CREATED,
                emailResult.sent()
                        ? "Compte créé — e-mail d'activation envoyé à " + saved.getEmail()
                        : "Compte créé — e-mail non envoyé (" + emailResult.detail() + ")",
                admin.getUsername()));

        String alertMsg = emailResult.sent()
                ? String.format("Compte créé : %s (%s). E-mail d'activation envoyé.", saved.getUsername(), saved.getEmail())
                : String.format("Compte créé : %s (%s). E-mail NON envoyé — %s", saved.getUsername(), saved.getEmail(), emailResult.detail());
        securityEventService.recordAudit(
                AuditAction.ACCOUNT_CREATED,
                saved,
                alertMsg,
                admin.getUsername(),
                null
        );

        log.info("Utilisateur {} créé par {} — e-mail envoyé: {}", saved.getUsername(), admin.getUsername(), emailResult.sent());

        List<String> roles = saved.getRoles().stream().map(Role::name).toList();
        String message = emailResult.sent()
                ? "Compte créé. E-mail d'activation envoyé à " + emailResult.recipientEmail() + "."
                : "Compte créé mais l'e-mail n'a pas pu être envoyé à " + emailResult.recipientEmail()
                  + " : " + emailResult.detail()
                  + " Transmettez ce lien à l'utilisateur : " + emailResult.activationLink();

        return new CreateUserResponse(
                saved.getId(),
                saved.getUsername(),
                saved.getEmail(),
                roles,
                saved.getAccountStatus().name(),
                emailResult.sent(),
                message,
                emailResult.activationLink()
        );
    }

    @Transactional
    public EmailSendResult resendActivationEmail(UUID userId) {
        User admin = getCurrentUser();
        return accountActivationService.resendActivationEmail(userId, admin.getUsername());
    }

    /**
     * Supprime définitivement un compte utilisateur et ses données associées.
     */
    @Transactional
    public void deleteUser(UUID userId) {
        User user = userRepository.findOneById(userId)
                .orElseThrow(() -> new IllegalArgumentException("Utilisateur introuvable."));
        if (user.isAdmin()) {
            throw new IllegalArgumentException("Un compte administrateur ne peut pas être supprimé via cette API.");
        }

        User admin = getCurrentUser();
        if (user.getId().equals(admin.getId())) {
            throw new IllegalArgumentException("Vous ne pouvez pas supprimer votre propre compte.");
        }

        String username = user.getUsername();
        String email = user.getEmail();
        UUID uid = user.getId();

        cleanupFindingOccurrences(uid);
        loginAttemptRepository.deleteAll(loginAttemptRepository.findByUser(user));
        activityLogRepository.deleteAll(activityLogRepository.findByUserOrderByCreatedAtDesc(user));
        complaintRepository.deleteAll(complaintRepository.findByAuthorWithMessages(user));

        // 1. Environnements d'abord (FK vers app_service)
        List<EphemeralEnvironment> envs =
                ephemeralEnvironmentRepository.findByRequestedByOrderByCreatedAtDesc(user);
        if (!envs.isEmpty()) {
            ephemeralEnvironmentRepository.deleteAll(envs);
        }

        // 2. Projets (cascade → services liés, databases, deployments)
        List<com.backend.devsecopsplatform_backend.entity.appmgmt.ManagedApplication> projects =
                managedApplicationRepository.findByCreatedByOrderByCreatedAtDesc(user);
        if (!projects.isEmpty()) {
            managedApplicationRepository.deleteAll(projects);
        }

        // 3. Services orphelins (sans projet parent)
        List<AppService> orphanServices = applicationRepository.findByCreatedByOrderByCreatedAtDesc(user);
        if (!orphanServices.isEmpty()) {
            applicationRepository.deleteAll(orphanServices);
        }

        userRepository.delete(user);

        String detail = "Compte supprimé : " + username + " (" + email + ")";
        securityEventService.recordAudit(
                AuditAction.ACCOUNT_DELETED,
                null,
                detail,
                admin.getUsername(),
                null
        );
        log.info("Compte {} supprimé par {}", username, admin.getUsername());
    }

    private void cleanupFindingOccurrences(UUID userId) {
        jdbcTemplate.update("""
                DELETE FROM finding_occurrences fo
                WHERE fo.pipeline_execution_id IN (
                    SELECT pe.id FROM pipeline_executions pe
                    INNER JOIN ephemeral_environments e ON e.id = pe.environment_id
                    WHERE e.requested_by = ?
                )
                """, userId);
    }

    /**
     * Réinitialise le mot de passe d'un utilisateur (action admin, sans ancien mot de passe).
     */
    @Transactional
    public void resetPassword(UUID userId, String newPassword) {
        PasswordPolicy.validate(newPassword);
        User user = userRepository.findOneById(userId)
                .orElseThrow(() -> new IllegalArgumentException("Utilisateur introuvable."));
        if (user.isAdmin()) {
            throw new IllegalArgumentException("Le mot de passe d'un administrateur ne peut pas être réinitialisé via cette API.");
        }
        User admin = getCurrentUser();
        user.setPassword(passwordEncoder.encode(newPassword));
        userRepository.save(user);
        activityLogRepository.save(UserActivityLog.of(
                user, UserActivityType.ADMIN_PASSWORD_RESET,
                "Mot de passe réinitialisé par l'administrateur", admin.getUsername()));
        securityEventService.recordAudit(
                AuditAction.ADMIN_PASSWORD_RESET,
                user,
                "Mot de passe réinitialisé par l'administrateur",
                admin.getUsername(),
                null
        );
        log.info("Mot de passe de {} réinitialisé par {}", user.getUsername(), admin.getUsername());
    }

    /**
     * Modifie l'adresse e-mail d'un utilisateur (action admin).
     */
    @Transactional
    public AdminUserMetricsResponse updateUserEmail(UUID userId, String newEmail) {
        if (newEmail == null || newEmail.isBlank()) {
            throw new IllegalArgumentException("L'e-mail est obligatoire.");
        }
        String email = newEmail.trim();
        if (!email.matches("^[A-Za-z0-9+_.-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}$")) {
            throw new IllegalArgumentException("Format d'e-mail invalide.");
        }
        User user = findUserOrThrow(userId);
        if (user.isAdmin()) {
            throw new IllegalArgumentException("L'e-mail d'un administrateur ne peut pas être modifié via cette API.");
        }
        if (email.equalsIgnoreCase(user.getEmail())) {
            throw new IllegalArgumentException("Le nouvel e-mail est identique à l'actuel.");
        }
        if (userRepository.existsByEmail(email)) {
            throw new IllegalArgumentException("Cet e-mail est déjà utilisé par un autre compte.");
        }

        User admin = getCurrentUser();
        String oldEmail = user.getEmail();
        user.setEmail(email);
        User saved = userRepository.save(user);
        activityLogRepository.save(UserActivityLog.of(
                saved, UserActivityType.ADMIN_EMAIL_CHANGED,
                oldEmail + " → " + email, admin.getUsername()));
        securityEventService.recordAudit(
                AuditAction.ADMIN_EMAIL_CHANGED,
                saved,
                oldEmail + " → " + email,
                admin.getUsername(),
                null
        );
        log.info("E-mail de {} modifié par {}", saved.getUsername(), admin.getUsername());
        return toMetricsResponse(saved);
    }

    /**
     * Active ou désactive un compte. Un compte désactivé ne peut plus se connecter.
     */
    @Transactional
    public AdminUserMetricsResponse setUserStatus(UUID userId, boolean active) {
        User user = findUserOrThrow(userId);
        if (user.isAdmin()) {
            throw new IllegalArgumentException("Le statut d'un administrateur ne peut pas être modifié via cette API.");
        }
        AccountStatus target = active ? AccountStatus.ACTIVE : AccountStatus.DISABLED;
        if (user.getAccountStatus() == target) {
            throw new IllegalArgumentException(active
                    ? "Ce compte est déjà actif."
                    : "Ce compte est déjà désactivé.");
        }

        User admin = getCurrentUser();
        user.setAccountStatus(target);
        User saved = userRepository.save(user);
        activityLogRepository.save(UserActivityLog.of(
                saved,
                active ? UserActivityType.ACCOUNT_ENABLED : UserActivityType.ACCOUNT_DISABLED,
                active ? "Compte réactivé par l'administrateur" : "Compte désactivé par l'administrateur",
                admin.getUsername()));
        securityEventService.recordAudit(
                active ? AuditAction.ACCOUNT_ENABLED : AuditAction.ACCOUNT_DISABLED,
                saved,
                active ? "Compte réactivé" : "Compte désactivé",
                admin.getUsername(),
                null
        );
        log.info("Compte {} {} par {}", saved.getUsername(), active ? "réactivé" : "désactivé", admin.getUsername());
        return toMetricsResponse(saved);
    }

    /**
     * Détail d'un utilisateur (métriques complètes).
     */
    @Transactional(readOnly = true)
    public AdminUserMetricsResponse getUserMetrics(UUID userId) {
        return toMetricsResponse(findUserOrThrow(userId));
    }

    /**
     * Journal d'activité d'un compte (créations, changements d'e-mail / mot de passe, statut).
     */
    @Transactional(readOnly = true)
    public List<UserActivityResponse> getUserActivity(UUID userId) {
        User user = findUserOrThrow(userId);
        return activityLogRepository.findByUserOrderByCreatedAtDesc(user).stream()
                .map(a -> new UserActivityResponse(
                        a.getId(),
                        a.getAction().name(),
                        a.getDetail(),
                        a.getPerformedBy(),
                        a.getCreatedAt()
                ))
                .toList();
    }

    /**
     * Réclamations (discussions) ouvertes par l'utilisateur, avec leurs messages.
     */
    @Transactional(readOnly = true)
    public List<ComplaintApiDto.ThreadDto> getUserComplaints(UUID userId) {
        User user = findUserOrThrow(userId);
        return complaintRepository.findByAuthorWithMessages(user).stream()
                .map(ComplaintApiDto::toThread)
                .toList();
    }

    /**
     * Statistiques tableau de bord : tentatives échouées, graphique connexions, alertes sécurité.
     */
    @Transactional(readOnly = true)
    public AdminUsersDashboardStats getDashboardStats() {
        return loginAuditService.getDashboardStats();
    }

    /**
     * Utilisateurs non-admin avec métriques enrichies (apps, envs, pipelines par statut).
     */
    @Transactional(readOnly = true)
    public List<AdminUserMetricsResponse> getAllUsersWithMetrics() {
        return userRepository.findAll().stream()
                .filter(u -> !u.isAdmin())
                .map(this::toMetricsResponse)
                .toList();
    }

    private AdminUserMetricsResponse toMetricsResponse(User u) {
        long activeEnvs = ephemeralEnvironmentRepository
                .countByRequestedByAndStatus(u, EnvironmentStatus.RUNNING);
        long pipelines = pipelineExecutionRepository.countByUser(u);
        long applications = applicationRepository.countByCreatedBy(u);

        List<String> roles = (u.getRoles() == null)
                ? List.of()
                : u.getRoles().stream().map(Role::name).toList();

        List<EphemeralEnvironment> envs =
                ephemeralEnvironmentRepository.findByRequestedByWithServiceAndPipelineOrderByCreatedAtDesc(u);

        AdminPipelineCounts globalPipelineCounts =
                buildPipelineCounts(pipelineExecutionRepository.countByUserGroupByStatus(u));

        Map<UUID, AdminPipelineCounts> pipelineByApp =
                buildApplicationPipelineCountsMap(pipelineExecutionRepository.countByUserGroupByApplicationAndStatus(u));

        Map<UUID, Long> envCountByAppId = envs.stream()
                .collect(Collectors.groupingBy(e -> e.getService().getId(), Collectors.counting()));

        List<AppService> appList = applicationRepository.findByCreatedByOrderByCreatedAtDesc(u);
        List<AdminUserApplicationDetail> appDetails = appList.stream()
                .map(app -> new AdminUserApplicationDetail(
                        app.getId(),
                        app.getName(),
                        app.getDescription(),
                        app.getGitRepositoryUrl(),
                        app.getCreatedAt(),
                        envCountByAppId.getOrDefault(app.getId(), 0L),
                        pipelineByApp.getOrDefault(app.getId(), AdminPipelineCounts.empty())
                ))
                .toList();

        List<AdminUserEnvironmentDetail> envDetails = envs.stream()
                .map(this::toEnvironmentDetail)
                .toList();

        int recentFailures = (int) loginAuditService.countRecentFailuresSinceLastSuccess(u);
        LocalDateTime lastPwdChange = findLastPasswordChange(u);

        return new AdminUserMetricsResponse(
                u.getId(),
                u.getUsername(),
                u.getEmail(),
                roles,
                u.getAccountStatus().name(),
                u.getCreatedAt(),
                u.getUpdatedAt(),
                u.getLastLoginAt(),
                lastPwdChange,
                recentFailures,
                activeEnvs,
                pipelines,
                applications,
                globalPipelineCounts,
                buildEnvironmentBreakdown(envs),
                appDetails,
                envDetails
        );
    }

    private AdminUserEnvironmentDetail toEnvironmentDetail(EphemeralEnvironment e) {
        AppService app = e.getService();
        PipelineExecution pe = e.getPipelineExecution();
        return new AdminUserEnvironmentDetail(
                e.getId(),
                app.getId(),
                app.getName(),
                e.getEnvironmentName(),
                e.getGitBranch(),
                e.getStatus().name(),
                e.getUrl(),
                e.getTtlHours(),
                e.getCreatedAt(),
                e.getExpiresAt(),
                pe != null ? pe.getGitlabPipelineId() : null,
                pe != null && pe.getStatus() != null ? pe.getStatus().name() : null,
                pe != null ? pe.getStartedAt() : null,
                pe != null ? pe.getFinishedAt() : null
        );
    }

    private AdminEnvironmentStatusBreakdown buildEnvironmentBreakdown(List<EphemeralEnvironment> envs) {
        if (envs.isEmpty()) {
            return AdminEnvironmentStatusBreakdown.empty();
        }
        long p = 0, b = 0, r = 0, f = 0, d = 0, ex = 0;
        for (EphemeralEnvironment e : envs) {
            switch (e.getStatus()) {
                case PENDING -> p++;
                case BUILDING -> b++;
                case RUNNING -> r++;
                case FAILED -> f++;
                case DESTROYED -> d++;
                case EXPIRED -> ex++;
            }
        }
        return new AdminEnvironmentStatusBreakdown(p, b, r, f, d, ex);
    }

    private AdminPipelineCounts buildPipelineCounts(List<Object[]> rows) {
        if (rows == null || rows.isEmpty()) {
            return AdminPipelineCounts.empty();
        }
        EnumMap<PipelineStatus, Long> map = new EnumMap<>(PipelineStatus.class);
        for (Object[] row : rows) {
            PipelineStatus st = (PipelineStatus) row[0];
            long n = ((Number) row[1]).longValue();
            map.merge(st, n, Long::sum);
        }
        return fromStatusMap(map);
    }

    private Map<UUID, AdminPipelineCounts> buildApplicationPipelineCountsMap(List<Object[]> rows) {
        Map<UUID, EnumMap<PipelineStatus, Long>> acc = new HashMap<>();
        if (rows != null) {
            for (Object[] row : rows) {
                UUID appId = (UUID) row[0];
                PipelineStatus st = (PipelineStatus) row[1];
                long n = ((Number) row[2]).longValue();
                acc.computeIfAbsent(appId, k -> new EnumMap<>(PipelineStatus.class))
                        .merge(st, n, Long::sum);
            }
        }
        Map<UUID, AdminPipelineCounts> out = new HashMap<>();
        for (Map.Entry<UUID, EnumMap<PipelineStatus, Long>> e : acc.entrySet()) {
            out.put(e.getKey(), fromStatusMap(e.getValue()));
        }
        return out;
    }

    private AdminPipelineCounts fromStatusMap(Map<PipelineStatus, Long> map) {
        return new AdminPipelineCounts(
                map.getOrDefault(PipelineStatus.SUCCESS, 0L),
                map.getOrDefault(PipelineStatus.FAILED, 0L),
                map.getOrDefault(PipelineStatus.RUNNING, 0L),
                map.getOrDefault(PipelineStatus.PENDING, 0L),
                map.getOrDefault(PipelineStatus.CANCELED, 0L),
                map.getOrDefault(PipelineStatus.SKIPPED, 0L)
        );
    }

    private User findUserOrThrow(UUID id) {
        return userRepository.findOneById(id)
                .orElseThrow(() -> new IllegalArgumentException("Utilisateur introuvable."));
    }

    private LocalDateTime findLastPasswordChange(User user) {
        return activityLogRepository.findByUserOrderByCreatedAtDesc(user).stream()
                .filter(a -> a.getAction() == UserActivityType.PASSWORD_CHANGED
                        || a.getAction() == UserActivityType.ADMIN_PASSWORD_RESET)
                .map(UserActivityLog::getCreatedAt)
                .findFirst()
                .orElse(null);
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
