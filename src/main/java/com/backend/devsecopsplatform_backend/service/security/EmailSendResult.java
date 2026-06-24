package com.backend.devsecopsplatform_backend.service.security;

/** Résultat d'une tentative d'envoi d'e-mail d'activation. */
public record EmailSendResult(
        boolean sent,
        String activationLink,
        String detail,
        String recipientEmail
) {
    public static EmailSendResult sent(String link, String recipientEmail) {
        return new EmailSendResult(true, link, "E-mail envoyé à " + recipientEmail + ".", recipientEmail);
    }

    public static EmailSendResult notSent(String link, String recipientEmail, String reason) {
        return new EmailSendResult(false, link, reason, recipientEmail);
    }
}
