package com.backend.devsecopsplatform_backend.util;

public final class UsernamePolicy {

    public static final int MIN_LENGTH = 2;
    public static final int MAX_LENGTH = 30;

    private UsernamePolicy() {}

    public static void validate(String username) {
        if (username == null || username.isBlank()) {
            throw new IllegalArgumentException("Le nom d'utilisateur est obligatoire.");
        }

        String value = username.trim();
        if (value.length() < MIN_LENGTH || value.length() > MAX_LENGTH) {
            throw new IllegalArgumentException(
                    "Le nom d'utilisateur doit contenir entre " + MIN_LENGTH + " et " + MAX_LENGTH + " caractères.");
        }
        if (!Character.isLetterOrDigit(value.charAt(0))) {
            throw new IllegalArgumentException("Le nom d'utilisateur doit commencer par une lettre ou un chiffre.");
        }
        if (value.length() == 2) {
            if (!value.matches("^[a-zA-Z0-9]{2}$")) {
                throw new IllegalArgumentException(
                        "Caractères autorisés : lettres, chiffres, point (.), tiret (-) et underscore (_).");
            }
        } else if (!value.matches("^[a-zA-Z0-9][a-zA-Z0-9._-]*[a-zA-Z0-9]$")) {
            throw new IllegalArgumentException(
                    "Le nom d'utilisateur doit commencer et se terminer par une lettre ou un chiffre.");
        }
        if (value.contains("..")) {
            throw new IllegalArgumentException("Le point (.) ne peut pas être répété.");
        }
        if (!value.matches(".*[a-zA-Z].*")) {
            throw new IllegalArgumentException("Le nom d'utilisateur doit contenir au moins une lettre.");
        }
        if (value.chars().distinct().count() == 1) {
            throw new IllegalArgumentException("Nom d'utilisateur non valide (caractères répétés).");
        }
        if (value.matches(".*(.)\\1{4,}.*")) {
            throw new IllegalArgumentException("Trop de caractères identiques consécutifs.");
        }
    }
}
