package com.backend.devsecopsplatform_backend.controller.admin;

import com.backend.devsecopsplatform_backend.service.security.DataProtectionService;
import com.backend.devsecopsplatform_backend.service.security.monitoring.IpBlocklistService;
import com.backend.devsecopsplatform_backend.service.security.monitoring.IpBlocklistService.BlockedIpView;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import jakarta.validation.Valid;

import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/admin/security")
@RequiredArgsConstructor
public class AdminSecurityController {

    private final IpBlocklistService blocklistService;
    private final DataProtectionService dataProtectionService;

    @GetMapping("/data-protection")
    public ResponseEntity<Map<String, Object>> dataProtection() {
        return ResponseEntity.ok(dataProtectionService.getProtectionSummary());
    }

    @GetMapping("/blocked-ips")
    public ResponseEntity<List<BlockedIpView>> listBlockedIps() {
        return ResponseEntity.ok(blocklistService.listBlocked());
    }

    @PostMapping("/blocked-ips")
    public ResponseEntity<Map<String, String>> blockIp(@Valid @RequestBody BlockIpRequest request) {
        int minutes = request.minutes() != null && request.minutes() > 0 ? request.minutes() : 60;
        String reason = request.reason() != null && !request.reason().isBlank()
                ? request.reason()
                : "Blocage manuel par administrateur";
        blocklistService.blockManual(request.ip(), minutes, reason);
        return ResponseEntity.ok(Map.of("message", "IP bloquée : " + request.ip()));
    }

    @DeleteMapping("/blocked-ips/{ip}")
    public ResponseEntity<Map<String, String>> unblockIp(@PathVariable String ip) {
        blocklistService.unblock(ip);
        return ResponseEntity.ok(Map.of("message", "IP débloquée : " + ip));
    }
}
