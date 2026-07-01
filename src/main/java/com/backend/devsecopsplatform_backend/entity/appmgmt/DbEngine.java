package com.backend.devsecopsplatform_backend.entity.appmgmt;

/**
 * Moteur de base de données. Les valeurs SQL et NoSQL sont regroupées ici ;
 * la cohérence avec {@link DbFamily} est validée côté service.
 */
public enum DbEngine {
    // SQL
    MARIADB,
    POSTGRES,
    MYSQL,
    // NoSQL
    MONGODB,
    REDIS,
    CASSANDRA;

    /** Port par défaut du moteur (pré-remplissage du champ exposed_port). */
    public int defaultPort() {
        return switch (this) {
            case MARIADB, MYSQL -> 3306;
            case POSTGRES -> 5432;
            case MONGODB -> 27017;
            case REDIS -> 6379;
            case CASSANDRA -> 9042;
        };
    }

    public DbFamily family() {
        return switch (this) {
            case MARIADB, POSTGRES, MYSQL -> DbFamily.SQL;
            case MONGODB, REDIS, CASSANDRA -> DbFamily.NOSQL;
        };
    }
}
