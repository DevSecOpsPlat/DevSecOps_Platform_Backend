package com.backend.devsecopsplatform_backend.controller.user;

import com.backend.devsecopsplatform_backend.service.user.ProfileService;
import com.backend.devsecopsplatform_backend.util.IpAddressUtils;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/api/profile")
@RequiredArgsConstructor
@CrossOrigin(origins = {"http://localhost:4200", "http://envirotest.local", "http://envirotest.local:4200"})
public class ProfileController {

    private final ProfileService profileService;

    @GetMapping("/me")
    public ResponseEntity<ProfileResponse> getMyProfile() {
        return ResponseEntity.ok(profileService.getCurrentProfile());
    }

    @PatchMapping("/email")
    public ResponseEntity<?> updateEmail(@RequestBody UpdateEmailRequest request, HttpServletRequest httpRequest) {
        try {
            ProfileResponse updated = profileService.updateEmail(request, IpAddressUtils.resolve(httpRequest));
            return ResponseEntity.ok(updated);
        } catch (IllegalArgumentException | IllegalStateException e) {
            return ResponseEntity.badRequest().body(Map.of("message", e.getMessage()));
        }
    }

    @PatchMapping("/password")
    public ResponseEntity<?> changePassword(@RequestBody ChangePasswordRequest request, HttpServletRequest httpRequest) {
        try {
            profileService.changePassword(request, IpAddressUtils.resolve(httpRequest));
            return ResponseEntity.ok(Map.of("message", "Mot de passe mis à jour avec succès."));
        } catch (IllegalArgumentException | IllegalStateException e) {
            return ResponseEntity.badRequest().body(Map.of("message", e.getMessage()));
        }
    }
}
