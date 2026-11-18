package com.backend.devsecopsplatform_backend.configuration;

import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;

/**
 * Fuseaux horaires. Les {@link LocalDateTime} de la plateforme sont produits par {@code LocalDateTime.now()}
 * dans le fuseau de la JVM (UTC dans le cluster, comme PostgreSQL) et stockés sans fuseau. Envoyés tels quels,
 * le navigateur les lisait comme des heures locales : tout s'affichait avec une heure de retard en Tunisie.
 * <ul>
 *   <li>{@link #iso(LocalDateTime)} : instant ISO avec décalage (« …Z ») pour le JSON — le navigateur convertit ;</li>
 *   <li>{@link #format(LocalDateTime, DateTimeFormatter)} : texte rédigé côté serveur (messages, alertes),
 *       dans le fuseau des utilisateurs ({@code APP_DISPLAY_TIMEZONE}, Africa/Tunis par défaut).</li>
 * </ul>
 */
public final class DisplayTime {

    /** Fuseau dans lequel les {@link LocalDateTime} sont produits (celui de la JVM). */
    public static final ZoneId STORAGE_ZONE = ZoneId.systemDefault();

    /** Fuseau des utilisateurs pour les textes formatés côté serveur. */
    public static final ZoneId DISPLAY_ZONE = resolveDisplayZone();

    private DisplayTime() {
    }

    private static ZoneId resolveDisplayZone() {
        String configured = System.getenv("APP_DISPLAY_TIMEZONE");
        try {
            return ZoneId.of(configured != null && !configured.isBlank() ? configured.trim() : "Africa/Tunis");
        } catch (Exception e) {
            return ZoneId.of("Africa/Tunis");
        }
    }

    /** « 2026-11-18T09:50:36.166Z » : instant non ambigu pour le navigateur. */
    public static String iso(LocalDateTime value) {
        return value == null ? null : value.atZone(STORAGE_ZONE).toOffsetDateTime().toString();
    }

    /** Date-heure telle que la voit l'utilisateur. */
    public static LocalDateTime toDisplay(LocalDateTime value) {
        return value == null ? null : value.atZone(STORAGE_ZONE).withZoneSameInstant(DISPLAY_ZONE).toLocalDateTime();
    }

    /** Texte rédigé côté serveur, dans le fuseau des utilisateurs. */
    public static String format(LocalDateTime value, DateTimeFormatter formatter) {
        return value == null ? "—" : toDisplay(value).format(formatter);
    }

    /** Jour courant pour l'utilisateur (regroupements par jour). */
    public static LocalDate today() {
        return LocalDate.now(DISPLAY_ZONE);
    }
}
