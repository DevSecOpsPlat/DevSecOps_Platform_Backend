package com.backend.devsecopsplatform_backend.service.report;

/**
 * PDF généré en mémoire uniquement (aucune persistance disque / S3 / DB).
 */
public record GeneratedPdf(byte[] content, String fileName) {}
