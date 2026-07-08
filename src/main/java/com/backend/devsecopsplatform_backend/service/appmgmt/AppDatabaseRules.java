package com.backend.devsecopsplatform_backend.service.appmgmt;

import com.backend.devsecopsplatform_backend.entity.appmgmt.AppDatabase;
import com.backend.devsecopsplatform_backend.entity.appmgmt.DbEngine;

import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * Règles métier partagées pour les bases managées (validation + normalisations).
 * Source unique pour le frontend/backend — le contrat reste le service.
 */
public final class AppDatabaseRules {

    public static final long MAX_STORAGE_MIB = 50L * 1024; // 50 Gi

    public static final Pattern RESOURCE_NAME =
            Pattern.compile("^[a-z]([a-z0-9-]{0,48}[a-z0-9])?$");
    public static final Pattern LOGICAL_DB_NAME =
            Pattern.compile("^[a-zA-Z][a-zA-Z0-9_]{0,62}$");
    public static final Pattern CASSANDRA_KEYSPACE =
            Pattern.compile("^[a-z][a-z0-9_]{0,47}$");
    public static final Pattern REDIS_DB_INDEX =
            Pattern.compile("^(1[0-5]|[0-9])$");
    public static final Pattern ROOT_USER =
            Pattern.compile("^[a-zA-Z_][a-zA-Z0-9_]{1,31}$");
    public static final Pattern ENGINE_VERSION =
            Pattern.compile("^[0-9]+(\\.[0-9]+)*([._-][a-zA-Z0-9]+)?$");
    public static final Pattern STORAGE_SIZE =
            Pattern.compile("^[1-9][0-9]*[KMGT]i$");
    public static final Pattern PASSWORD_SAFE =
            Pattern.compile("^[\\x21-\\x7E]{8,128}$"); // printable ASCII, no control/space

    private static final Map<DbEngine, Set<String>> RESERVED_DB_NAMES = Map.of(
            DbEngine.POSTGRES, Set.of("postgres", "template0", "template1"),
            DbEngine.MYSQL, Set.of("mysql", "sys", "information_schema", "performance_schema"),
            DbEngine.MARIADB, Set.of("mysql", "sys", "information_schema", "performance_schema"),
            DbEngine.MONGODB, Set.of("admin", "local", "config")
    );

    private AppDatabaseRules() {
    }

    /** Images officielles : MYSQL_USER / MARIADB_USER ne doivent jamais être {@code root}. */
    public static boolean isForbiddenRootUser(DbEngine engine, String rootUser) {
        if (rootUser == null) {
            return false;
        }
        return (engine == DbEngine.MYSQL || engine == DbEngine.MARIADB)
                && "root".equalsIgnoreCase(rootUser.trim());
    }

    /**
     * MySQL/MariaDB : le formulaire « utilisateur root » n'est pas mappé
     * (seul MYSQL_ROOT_PASSWORD / MARIADB_ROOT_PASSWORD l'est) → ne pas l'exiger.
     * Redis / Cassandra : pas d'utilisateur nommé via env.
     */
    public static boolean usesRootUser(DbEngine engine) {
        return switch (engine) {
            case POSTGRES, MONGODB -> true;
            case MYSQL, MARIADB, REDIS, CASSANDRA -> false;
        };
    }

    public static boolean usesRootPassword(DbEngine engine) {
        return switch (engine) {
            case POSTGRES, MYSQL, MARIADB, MONGODB, REDIS -> true;
            case CASSANDRA -> false;
        };
    }

    /** True si l'image crée la base logique au boot (POSTGRES_DB / MYSQL_DATABASE…). */
    public static boolean createsLogicalDbAtStartup(DbEngine engine) {
        return switch (engine) {
            case POSTGRES, MYSQL, MARIADB, MONGODB, REDIS -> true;
            case CASSANDRA -> false; // pas d'équivalent ; keyspace à créer via CQL Job
        };
    }

    /**
     * Utilisateur réel créé / attendu par l'image officielle.
     * Diffère du champ stocké pour MySQL/MariaDB (seul {@code root} existe).
     */
    public static String effectiveRootUser(AppDatabase db) {
        if (db == null || db.getEngine() == null) {
            return "";
        }
        return switch (db.getEngine()) {
            case MYSQL, MARIADB -> "root";
            case CASSANDRA -> "cassandra";
            case REDIS -> "";
            case POSTGRES, MONGODB -> db.getRootUser() != null ? db.getRootUser() : "";
        };
    }

    /**
     * True si l'URL de connexion ne porte pas le userinfo (JDBC SQL, Cassandra) :
     * le service dépendant doit recevoir DATABASE_USER / DATABASE_PASSWORD en plus de DATABASE_URL.
     */
    public static boolean credentialsOutsideUrl(DbEngine engine) {
        return switch (engine) {
            case POSTGRES, MYSQL, MARIADB, CASSANDRA -> true;
            case MONGODB, REDIS -> false;
        };
    }

    /**
     * Normalisation à l'écriture uniquement ({@code applyDatabaseScalars}).
     * PostgreSQL : conserver la casse (l'entrypoint fait {@code CREATE DATABASE :\"db\"} quoté).
     * Cassandra : minuscules (futur Job CQL non quoté → repliage natif).
     */
    public static String normalizeLogicalDbName(DbEngine engine, String dbName) {
        if (dbName == null) {
            return "";
        }
        String t = dbName.trim();
        return switch (engine) {
            case CASSANDRA -> t.toLowerCase(Locale.ROOT);
            default -> t;
        };
    }

    public static boolean isReservedDbName(DbEngine engine, String dbName) {
        if (dbName == null) {
            return false;
        }
        Set<String> reserved = RESERVED_DB_NAMES.get(engine);
        return reserved != null && reserved.contains(dbName.trim().toLowerCase(Locale.ROOT));
    }

    public static boolean isValidLogicalDbName(DbEngine engine, String raw) {
        if (raw == null || raw.isBlank()) {
            return false;
        }
        if (engine == DbEngine.REDIS) {
            return REDIS_DB_INDEX.matcher(raw.trim()).matches();
        }
        // Cassandra : valider sur la forme normalisée (minuscules, ≤ 48).
        if (engine == DbEngine.CASSANDRA) {
            String dbName = normalizeLogicalDbName(engine, raw);
            return CASSANDRA_KEYSPACE.matcher(dbName).matches();
        }
        // PostgreSQL / MySQL / … : casse préservée, comparaison littérale dans l'URL JDBC.
        String dbName = raw.trim();
        return LOGICAL_DB_NAME.matcher(dbName).matches() && !isReservedDbName(engine, dbName);
    }

    public static long storageToMib(String storageSize) {
        if (storageSize == null || storageSize.isBlank()) {
            return 1024;
        }
        String s = storageSize.trim();
        long n = Long.parseLong(s.substring(0, s.length() - 2));
        String unit = s.substring(s.length() - 2);
        return switch (unit) {
            case "Ki" -> Math.max(1, n / 1024);
            case "Mi" -> n;
            case "Gi" -> n * 1024;
            case "Ti" -> n * 1024 * 1024;
            default -> n;
        };
    }

    public static String imageRef(DbEngine engine, String version) {
        String tag = (version != null && !version.isBlank()) ? version.trim() : "latest";
        return switch (engine) {
            case MARIADB -> "mariadb:" + tag;
            case MYSQL -> "mysql:" + tag;
            case POSTGRES -> "postgres:" + tag;
            case MONGODB -> "mongo:" + tag;
            case REDIS -> "redis:" + tag;
            case CASSANDRA -> "cassandra:" + tag;
        };
    }

    public static String dockerHubRepo(DbEngine engine) {
        return switch (engine) {
            case MARIADB -> "library/mariadb";
            case MYSQL -> "library/mysql";
            case POSTGRES -> "library/postgres";
            case MONGODB -> "library/mongo";
            case REDIS -> "library/redis";
            case CASSANDRA -> "library/cassandra";
        };
    }

    public static int majorOf(String version) {
        if (version == null || version.isBlank()) {
            return -1;
        }
        String head = version.trim().split("[.\\-_]")[0];
        try {
            return Integer.parseInt(head);
        } catch (NumberFormatException e) {
            return -1;
        }
    }
}
