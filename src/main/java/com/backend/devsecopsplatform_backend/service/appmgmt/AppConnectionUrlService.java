package com.backend.devsecopsplatform_backend.service.appmgmt;

import com.backend.devsecopsplatform_backend.entity.appmgmt.AppDatabase;
import org.springframework.stereotype.Service;

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
     * URL de connexion en clair (destinée au Secret K8s injecté dans les services).
     */
    public String buildConnectionUrl(AppDatabase db, String namespace) {
        String host = internalHost(db, namespace);
        int port = db.getExposedPort() != null ? db.getExposedPort() : db.getEngine().defaultPort();
        String dbName = db.getDbName();
        String user = db.getRootUser();
        String password = db.getRootPassword();

        return switch (db.getEngine()) {
            case MARIADB -> "jdbc:mariadb://" + host + ":" + port + "/" + dbName;
            case MYSQL -> "jdbc:mysql://" + host + ":" + port + "/" + dbName;
            case POSTGRES -> "jdbc:postgresql://" + host + ":" + port + "/" + dbName;
            case MONGODB -> "mongodb://" + user + ":" + password + "@" + host + ":" + port + "/" + dbName;
            case REDIS -> "redis://" + host + ":" + port;
            case CASSANDRA -> "cassandra://" + host + ":" + port + "/" + dbName;
        };
    }

    /**
     * Version masquée de l'URL (mot de passe remplacé par ••••••), pour l'API et l'UI.
     */
    public String maskConnectionUrl(AppDatabase db, String url) {
        if (url == null) {
            return null;
        }
        String password = db.getRootPassword();
        if (password != null && !password.isEmpty() && url.contains(":" + password + "@")) {
            return url.replace(":" + password + "@", ":" + MASK + "@");
        }
        return url;
    }
}
