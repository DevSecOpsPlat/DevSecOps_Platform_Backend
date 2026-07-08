package com.backend.devsecopsplatform_backend.service.appmgmt;

import com.backend.devsecopsplatform_backend.entity.appmgmt.AppDatabase;
import org.springframework.stereotype.Service;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;

/**
 * Génération de l'URL de connexion d'une base managée (architecture.md §3.1).
 *
 * <p>Le service K8s d'une base s'appelle {@code db-<name>} → DNS interne
 * {@code db-<name>.<namespace>.svc.cluster.local}. L'URL est construite selon le moteur
 * puis stockée dans {@code app_database.generated_connection_url} et injectée aux
 * services dépendants via un Secret K8s. L'utilisateur ne la saisit jamais.</p>
 */
@Service
public class AppConnectionUrlService {

    public static final String MASK = "\u2022\u2022\u2022\u2022\u2022\u2022";

    /** Nom du Service Kubernetes exposant la base. */
    public String serviceName(AppDatabase db) {
        return "db-" + AppNaming.k8sName(db.getName());
    }

    /** DNS interne stable de la base dans le cluster. */
    public String internalHost(AppDatabase db, String namespace) {
        return serviceName(db) + "." + namespace + ".svc.cluster.local";
    }

    /**
     * Percent-encoding pour userinfo (Mongo / Redis). Remplace {@code +} par {@code %20}
     * car « + » n'est pas un espace dans un userinfo d'URI.
     */
    static String enc(String s) {
        if (s == null) {
            return "";
        }
        return URLEncoder.encode(s, StandardCharsets.UTF_8).replace("+", "%20");
    }

    /**
     * URL de connexion en clair (destinée au Secret K8s injecté dans les services).
     */
    public String buildConnectionUrl(AppDatabase db, String namespace) {
        String host = internalHost(db, namespace);
        int port = db.getExposedPort() != null ? db.getExposedPort() : db.getEngine().defaultPort();
        // Valeur stockée = vérité (normalisée à l'écriture seulement). Ne pas re-normaliser ici.
        String dbName = db.getDbName();
        String user = AppDatabaseRules.effectiveRootUser(db);
        String password = db.getRootPassword() != null ? db.getRootPassword() : "";

        // JDBC SQL / Cassandra : user/password hors URL → injectés via DATABASE_USER / DATABASE_PASSWORD.
        // Mongo/Redis : userinfo dans l'URI → percent-encoding obligatoire.
        return switch (db.getEngine()) {
            case MARIADB -> "jdbc:mariadb://" + host + ":" + port + "/" + dbName;
            case MYSQL -> "jdbc:mysql://" + host + ":" + port + "/" + dbName;
            case POSTGRES -> "jdbc:postgresql://" + host + ":" + port + "/" + dbName;
            case MONGODB -> "mongodb://" + enc(user) + ":" + enc(password)
                    + "@" + host + ":" + port + "/" + dbName;
            case REDIS -> password.isBlank()
                    ? "redis://" + host + ":" + port + "/" + (dbName != null ? dbName : "0")
                    : "redis://:" + enc(password) + "@" + host + ":" + port
                    + "/" + (dbName != null ? dbName : "0");
            case CASSANDRA -> "cassandra://" + host + ":" + port + "/" + dbName;
        };
    }

    /**
     * Version masquée de l'URL (mot de passe remplacé par ••••••), pour l'API et l'UI.
     * Masque sur la forme claire ET encodée pour éviter une fuite si l'encodage diffère.
     */
    public String maskConnectionUrl(AppDatabase db, String url) {
        if (url == null) {
            return null;
        }
        String password = db.getRootPassword();
        if (password == null || password.isEmpty()) {
            return url;
        }
        String masked = url;
        if (masked.contains(":" + password + "@")) {
            masked = masked.replace(":" + password + "@", ":" + MASK + "@");
        }
        String encoded = enc(password);
        if (masked.contains(":" + encoded + "@")) {
            masked = masked.replace(":" + encoded + "@", ":" + MASK + "@");
        }
        return masked;
    }
}
