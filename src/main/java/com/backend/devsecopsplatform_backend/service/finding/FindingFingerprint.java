package com.backend.devsecopsplatform_backend.service.finding;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;

final class FindingFingerprint {
    private FindingFingerprint() {
    }

    static String sha256Hex(String input) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] digest = md.digest(input.getBytes(StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder(digest.length * 2);
            for (byte b : digest) {
                sb.append(String.format("%02x", b));
            }
            return sb.toString();
        } catch (Exception e) {
            // fallback non cryptographique, mais stable
            return Integer.toHexString(input.hashCode());
        }
    }
}

