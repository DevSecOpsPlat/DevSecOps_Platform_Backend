package com.backend.devsecopsplatform_backend.service.security;

/** Résultat de la préparation d'un compte (token + envoi e-mail). */
public record AccountPrepareResult(
        String token,
        EmailSendResult emailResult
) {}
