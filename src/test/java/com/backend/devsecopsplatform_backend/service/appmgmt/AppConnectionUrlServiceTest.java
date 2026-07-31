package com.backend.devsecopsplatform_backend.service.appmgmt;

import com.backend.devsecopsplatform_backend.entity.appmgmt.AppDatabase;
import com.backend.devsecopsplatform_backend.entity.appmgmt.DbEngine;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class AppConnectionUrlServiceTest {

    private final AppConnectionUrlService service = new AppConnectionUrlService();

    @Test
    void createsSqlAlchemyCompatiblePostgresUri() {
        AppDatabase database = postgresDatabase();

        String url = service.buildApplicationConnectionUrl(database, "env-demo");

        assertThat(url).isEqualTo(
                "postgresql://postgres:p%40ss%20word@db-mydb.env-demo.svc.cluster.local:5432/dockerapp");
    }

    @Test
    void keepsJdbcUrlAvailableForSpringServices() {
        AppDatabase database = postgresDatabase();

        String url = service.buildConnectionUrl(database, "env-demo");

        assertThat(url).isEqualTo(
                "jdbc:postgresql://db-mydb.env-demo.svc.cluster.local:5432/dockerapp");
    }

    private static AppDatabase postgresDatabase() {
        AppDatabase database = new AppDatabase();
        database.setName("mydb");
        database.setEngine(DbEngine.POSTGRES);
        database.setDbName("dockerapp");
        database.setRootUser("postgres");
        database.setRootPassword("p@ss word");
        database.setExposedPort(5432);
        return database;
    }
}
