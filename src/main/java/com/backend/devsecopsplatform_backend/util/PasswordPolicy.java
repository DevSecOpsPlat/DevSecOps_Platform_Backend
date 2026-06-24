package com.backend.devsecopsplatform_backend.util;

public final class PasswordPolicy {

    private PasswordPolicy() {}

    public static void validate(String password) {
        if (password == null || password.length() < 8) {
            throw new IllegalArgumentException(
                    "Le mot de passe doit contenir au moins 8 caractères, une majuscule, une minuscule et un chiffre.");
        }
        if (!password.matches(".*[a-z].*")) {
            throw new IllegalArgumentException("Le mot de passe doit contenir au moins une lettre minuscule.");
        }
        if (!password.matches(".*[A-Z].*")) {
            throw new IllegalArgumentException("Le mot de passe doit contenir au moins une lettre majuscule.");
        }
        if (!password.matches(".*\\d.*")) {
            throw new IllegalArgumentException("Le mot de passe doit contenir au moins un chiffre.");
        }
    }
}
