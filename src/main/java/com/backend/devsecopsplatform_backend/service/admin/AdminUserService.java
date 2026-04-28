package com.backend.devsecopsplatform_backend.service.admin;

import com.backend.devsecopsplatform_backend.entity.AccountStatus;
import com.backend.devsecopsplatform_backend.entity.Application;
import com.backend.devsecopsplatform_backend.entity.EnvironmentStatus;
import com.backend.devsecopsplatform_backend.entity.EphemeralEnvironment;
import com.backend.devsecopsplatform_backend.entity.PipelineExecution;
import com.backend.devsecopsplatform_backend.entity.PipelineStatus;
import com.backend.devsecopsplatform_backend.entity.Role;
import com.backend.devsecopsplatform_backend.entity.User;
import com.backend.devsecopsplatform_backend.repository.ApplicationRepository;
import com.backend.devsecopsplatform_backend.repository.EphemeralEnvironmentRepository;
import com.backend.devsecopsplatform_backend.repository.PipelineExecutionRepository;
import com.backend.devsecopsplatform_backend.repository.UserRepository;
import com.backend.devsecopsplatform_backend.service.admin.dto.AdminEnvironmentStatusBreakdown;
import com.backend.devsecopsplatform_backend.service.admin.dto.AdminPipelineCounts;
import com.backend.devsecopsplatform_backend.service.admin.dto.AdminUserApplicationDetail;
import com.backend.devsecopsplatform_backend.service.admin.dto.AdminUserEnvironmentDetail;
import com.backend.devsecopsplatform_backend.service.admin.dto.AdminUserMetricsResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

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
    private final ApplicationRepository applicationRepository;

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

        String validatedByUsername = (u.getValidatedBy() == null) ? null : u.getValidatedBy().getUsername();

        List<EphemeralEnvironment> envs =
                ephemeralEnvironmentRepository.findByRequestedByWithApplicationAndPipelineOrderByCreatedAtDesc(u);

        AdminPipelineCounts globalPipelineCounts =
                buildPipelineCounts(pipelineExecutionRepository.countByUserGroupByStatus(u));

        Map<UUID, AdminPipelineCounts> pipelineByApp =
                buildApplicationPipelineCountsMap(pipelineExecutionRepository.countByUserGroupByApplicationAndStatus(u));

        Map<UUID, Long> envCountByAppId = envs.stream()
                .collect(Collectors.groupingBy(e -> e.getApplication().getId(), Collectors.counting()));

        List<Application> appList = applicationRepository.findByCreatedByOrderByCreatedAtDesc(u);
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

        return new AdminUserMetricsResponse(
                u.getId(),
                u.getUsername(),
                u.getEmail(),
                roles,
                u.getAccountStatus().name(),
                u.getCreatedAt(),
                u.getUpdatedAt(),
                u.getValidatedAt(),
                validatedByUsername,
                u.getRejectionReason(),
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
        Application app = e.getApplication();
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

    private User findByIdOrThrow(UUID id) {
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
