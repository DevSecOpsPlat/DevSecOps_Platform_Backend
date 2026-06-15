package com.backend.devsecopsplatform_backend.service.security;

import com.backend.devsecopsplatform_backend.entity.User;
import jakarta.mail.internet.InternetAddress;
import jakarta.mail.internet.MimeMessage;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

import java.util.regex.Pattern;

@Service
@Slf4j
public class EmailService {

    private static final Pattern EMAIL = Pattern.compile("^[A-Za-z0-9+_.-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}$");

    @Value("${app.frontend-url:http://localhost:4200}")
    private String frontendUrl;

    @Value("${app.mail.enabled:false}")
    private boolean mailEnabled;

    @Value("${app.mail.from:noreply@envirotest.local}")
    private String mailFrom;

    @Value("${spring.mail.password:}")
    private String mailPassword;

    private final JavaMailSender mailSender;

    public EmailService(@Autowired(required = false) JavaMailSender mailSender) {
        this.mailSender = mailSender;
    }

    public EmailSendResult sendActivationEmail(User user, String token) {
        String recipient = normalizeEmail(user.getEmail());
        String link = frontendUrl + "/activate?token=" + token;
        String subject = "Activation de votre compte EnviroTest";
        String body = """
                Bonjour %s,

                Votre compte EnviroTest a été créé par un administrateur.

                E-mail de connexion : %s

                Veuillez définir votre mot de passe en cliquant sur le lien ci-dessous :
                %s

                Ce lien expire dans 48 heures.

                Si vous n'êtes pas à l'origine de cette demande, contactez votre administrateur.
                """.formatted(user.getUsername(), recipient, link);

        if (!EMAIL.matcher(recipient).matches()) {
            String reason = "Adresse destinataire invalide : " + recipient;
            log.error(reason);
            return EmailSendResult.notSent(link, recipient, reason);
        }

        if (!mailEnabled) {
            String reason = "SMTP désactivé (app.mail.enabled=false). Transmettez le lien manuellement.";
            log.warn("{} — destinataire prévu : {}", reason, recipient);
            return EmailSendResult.notSent(link, recipient, reason);
        }
        if (!StringUtils.hasText(mailPassword)) {
            String reason = "Variable PASSSMTP vide (mot de passe d'application Gmail requis).";
            log.error("{} — destinataire prévu : {} — lien : {}", reason, recipient, link);
            return EmailSendResult.notSent(link, recipient, reason);
        }
        if (mailSender == null) {
            String reason = "Serveur SMTP non configuré (spring.mail.host / mot de passe).";
            log.error("{} — destinataire prévu : {}", reason, recipient);
            return EmailSendResult.notSent(link, recipient, reason);
        }

        try {
            MimeMessage mime = mailSender.createMimeMessage();
            MimeMessageHelper helper = new MimeMessageHelper(mime, false, "UTF-8");
            helper.setFrom(new InternetAddress(mailFrom.trim(), "EnviroTest", "UTF-8"));
            helper.setTo(new InternetAddress(recipient));
            helper.setReplyTo(mailFrom.trim());
            helper.setSubject(subject);
            helper.setText(body, false);

            mailSender.send(mime);
            log.info("E-mail d'activation envoyé — destinataire: {} | expéditeur: {}", recipient, mailFrom);
            return EmailSendResult.sent(link, recipient);
        } catch (Exception e) {
            String reason = friendlySmtpError(e);
            log.error("Échec envoi e-mail — destinataire prévu: {} — {}", recipient, reason, e);
            return EmailSendResult.notSent(link, recipient, reason);
        }
    }

    private String normalizeEmail(String email) {
        return email == null ? "" : email.trim().toLowerCase();
    }

    private String friendlySmtpError(Throwable e) {
        String raw = rootMessage(e);
        if (raw == null) {
            return "Erreur SMTP inconnue.";
        }
        if (raw.contains("534-5.7.9") || raw.contains("Application-specific password")) {
            return "Gmail exige un mot de passe d'application (PASSSMTP), pas le mot de passe du compte. "
                    + "https://myaccount.google.com/apppasswords";
        }
        if (raw.contains("Authentication failed") || raw.contains("535")) {
            return "Authentification SMTP refusée — vérifiez spring.mail.username et PASSSMTP.";
        }
        return "Échec SMTP : " + raw;
    }

    private String rootMessage(Throwable e) {
        Throwable t = e;
        while (t.getCause() != null) {
            t = t.getCause();
        }
        return t.getMessage();
    }
}
