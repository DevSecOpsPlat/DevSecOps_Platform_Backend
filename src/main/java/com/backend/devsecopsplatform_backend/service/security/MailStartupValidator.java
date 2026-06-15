package com.backend.devsecopsplatform_backend.service.security;

import com.backend.devsecopsplatform_backend.entity.User;
import jakarta.annotation.PostConstruct;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Component;

@Component
@Slf4j
public class MailStartupValidator {

    @Value("${app.mail.enabled:false}")
    private boolean mailEnabled;

    @Value("${spring.mail.host:}")
    private String mailHost;

    @Value("${spring.mail.username:}")
    private String mailUsername;

    @Value("${spring.mail.password:}")
    private String mailPassword;

    @Value("${app.mail.from:}")
    private String mailFrom;

    @Autowired(required = false)
    private JavaMailSender mailSender;

    @PostConstruct
    public void logMailStatus() {
        if (!mailEnabled) {
            log.warn("""
                    ═══ E-mail SMTP DÉSACTIVÉ (app.mail.enabled=false) ═══
                    Les liens d'activation seront affichés dans les logs et la réponse admin.
                    Pour activer Gmail : app.mail.enabled=true + variable PASSSMTP (mot de passe d'application).
                    """);
            return;
        }
        if (mailPassword == null || mailPassword.isBlank()) {
            log.error("""
                    ═══ E-mail activé mais PASSSMTP vide ═══
                    Définissez la variable d'environnement PASSSMTP (mot de passe d'application Google).
                    https://myaccount.google.com/apppasswords
                    """);
            return;
        }
        if (mailSender == null) {
            log.error("E-mail activé mais JavaMailSender non configuré (vérifiez spring.mail.host).");
            return;
        }
        log.info("E-mail SMTP prêt : {} → expéditeur {} (from: {})",
                mailHost, mailUsername, mailFrom);
    }
}
