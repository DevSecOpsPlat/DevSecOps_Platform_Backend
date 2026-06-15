package com.backend.devsecopsplatform_backend.service.auth;

import java.time.LocalDateTime;

public record LoginFailureResult(
        long consecutiveFailures,
        boolean accountLocked,
        LocalDateTime lockedUntil,
        int remainingAttemptsBeforeLockout
) {
    public static LoginFailureResult notApplicable() {
        return new LoginFailureResult(0, false, null, 0);
    }
}
