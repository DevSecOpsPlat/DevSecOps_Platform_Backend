package com.backend.devsecopsplatform_backend.service.security.monitoring;

import com.backend.devsecopsplatform_backend.configuration.SecurityMonitoringProperties;
import com.backend.devsecopsplatform_backend.entity.BlockSource;
import com.backend.devsecopsplatform_backend.entity.BlockedIp;
import com.backend.devsecopsplatform_backend.repository.BlockedIpRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.event.EventListener;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.fasterxml.jackson.annotation.JsonFormat;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

@Service
@Slf4j
@RequiredArgsConstructor
public class IpBlocklistService {

    private static final DateTimeFormatter FMT = DateTimeFormatter.ofPattern("dd/MM/yyyy HH:mm");

    private final SecurityMonitoringProperties properties;
    private final BlockedIpRepository blockedIpRepository;

    /** Cache chaud — synchronisé avec {@code blocked_ips} en base. */
    private final Map<String, BlockEntry> cache = new ConcurrentHashMap<>();

    @EventListener(ApplicationReadyEvent.class)
    @Transactional
    public void restoreActiveBlocksOnStartup() {
        if (!properties.getBlocklist().isEnabled()) {
            return;
        }
        LocalDateTime now = LocalDateTime.now();
        blockedIpRepository.deactivateExpired(now);
        List<BlockedIp> active = blockedIpRepository.findByActiveTrueAndBlockedUntilAfterOrderByBlockedUntilAsc(now);
        cache.clear();
        for (BlockedIp row : active) {
            cache.put(normalizeKey(row.getIpAddress()), new BlockEntry(row.getBlockedUntil(), row.getReason()));
        }
        log.info("{} blocage(s) IP actif(s) restauré(s) depuis la base de données.", active.size());
    }

    @Scheduled(fixedRateString = "${app.security.blocklist.cleanup-interval-ms:300000}")
    @Transactional
    public void purgeExpiredBlocks() {
        LocalDateTime now = LocalDateTime.now();
        int deactivated = blockedIpRepository.deactivateExpired(now);
        if (deactivated > 0) {
            cache.entrySet().removeIf(e -> e.getValue().blockedUntil().isBefore(now));
            log.info("{} blocage(s) IP expiré(s) désactivé(s) en base.", deactivated);
        }
    }

    @Transactional(readOnly = true)
    public boolean isBlocked(String ip) {
        if (!properties.getBlocklist().isEnabled()) {
            return false;
        }
        String key = normalizeKey(ip);
        BlockEntry cached = cache.get(key);
        LocalDateTime now = LocalDateTime.now();
        if (cached != null) {
            if (cached.blockedUntil().isAfter(now)) {
                return true;
            }
            cache.remove(key);
        }
        return blockedIpRepository
                .findFirstByIpAddressAndActiveTrueAndBlockedUntilAfter(key, now)
                .map(row -> {
                    cache.put(key, new BlockEntry(row.getBlockedUntil(), row.getReason()));
                    return true;
                })
                .orElse(false);
    }

    @Transactional
    public void block(String ip, int minutes, String reason) {
        block(ip, minutes, reason, BlockSource.AUTO);
    }

    @Transactional
    public void blockManual(String ip, int minutes, String reason) {
        block(ip, minutes, reason, BlockSource.MANUAL);
    }

    @Transactional
    public void block(String ip, int minutes, String reason, BlockSource source) {
        if (!properties.getBlocklist().isEnabled()) {
            return;
        }
        String key = normalizeKey(ip);
        LocalDateTime until = LocalDateTime.now().plusMinutes(Math.max(1, minutes));

        blockedIpRepository.deactivateByIpAddress(key);

        BlockedIp row = new BlockedIp();
        row.setIpAddress(key);
        row.setReason(truncate(reason, 500));
        row.setBlockedUntil(until);
        row.setSource(source);
        row.setActive(true);
        blockedIpRepository.save(row);

        cache.put(key, new BlockEntry(until, row.getReason()));
        log.warn("IP bloquée {} jusqu'à {} — {} ({}, persisté en BD)", key, until.format(FMT), reason, source);
    }

    @Transactional
    public void unblock(String ip) {
        String key = normalizeKey(ip);
        blockedIpRepository.deactivateByIpAddress(key);
        cache.remove(key);
        log.info("IP débloquée manuellement : {}", key);
    }

    @Transactional(readOnly = true)
    public List<BlockedIpView> listBlocked() {
        return listBlockedDetailed();
    }

    @Transactional(readOnly = true)
    public long countCurrentlyBlocked() {
        return blockedIpRepository.countByActiveTrueAndBlockedUntilAfter(LocalDateTime.now());
    }

    /** 50 derniers blocages en base (actifs ou expirés) — visibilité admin complète. */
    @Transactional(readOnly = true)
    public List<BlockedIpView> listBlockedDetailed() {
        LocalDateTime now = LocalDateTime.now();
        return blockedIpRepository.findTop50ByOrderByCreatedAtDesc().stream()
                .map(row -> toView(row, now))
                .toList();
    }

    private BlockedIpView toView(BlockedIp row, LocalDateTime now) {
        boolean active = row.isActive() && row.getBlockedUntil().isAfter(now);
        return new BlockedIpView(
                row.getIpAddress(),
                row.getReason(),
                row.getBlockedUntil(),
                row.getCreatedAt(),
                row.getSource().name(),
                active
        );
    }

    public BlockEntry getEntry(String ip) {
        return cache.get(normalizeKey(ip));
    }

    private String normalizeKey(String ip) {
        if (ip == null || ip.isBlank()) {
            return "unknown";
        }
        return ip.replace(" (localhost)", "").trim();
    }

    private String truncate(String value, int max) {
        if (value == null) {
            return "";
        }
        return value.length() <= max ? value : value.substring(0, max);
    }

    public record BlockEntry(LocalDateTime blockedUntil, String reason) {}

    public record BlockedIpView(
            String ip,
            String reason,
            @JsonFormat(shape = JsonFormat.Shape.STRING, pattern = "yyyy-MM-dd'T'HH:mm:ss")
            LocalDateTime blockedUntil,
            @JsonFormat(shape = JsonFormat.Shape.STRING, pattern = "yyyy-MM-dd'T'HH:mm:ss")
            LocalDateTime createdAt,
            String source,
            boolean currentlyActive
    ) {}
}
