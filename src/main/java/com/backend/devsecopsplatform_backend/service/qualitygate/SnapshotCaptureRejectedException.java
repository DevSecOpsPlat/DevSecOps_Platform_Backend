package com.backend.devsecopsplatform_backend.service.qualitygate;

/** Capture snapshot refusée (pipeline / security-validation pas prêt). */
public class SnapshotCaptureRejectedException extends RuntimeException {
    public SnapshotCaptureRejectedException(String message) {
        super(message);
    }
}
