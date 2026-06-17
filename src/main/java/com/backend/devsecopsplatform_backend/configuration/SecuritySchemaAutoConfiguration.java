package com.backend.devsecopsplatform_backend.configuration;

import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.ApplicationRunner;
import org.springframework.boot.autoconfigure.AutoConfigureBefore;
import org.springframework.boot.autoconfigure.orm.jpa.HibernateJpaAutoConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.jdbc.core.JdbcTemplate;

import javax.sql.DataSource;

/**
 * Applique les colonnes sécurité avant l'initialisation Hibernate (ddl-auto ne les ajoute pas toujours).
 */
@Configuration
@AutoConfigureBefore(HibernateJpaAutoConfiguration.class)
@Slf4j
public class SecuritySchemaAutoConfiguration {

    @Bean
    SecuritySchemaMigration securitySchemaMigration(DataSource dataSource) {
        SecuritySchemaMigration migration = new SecuritySchemaMigration(new JdbcTemplate(dataSource));
        migration.migrate();
        return migration;
    }

    /** Ré-aligne les CHECK après Hibernate ddl-auto=update (sinon EMAIL reste interdit). */
    @Bean
    ApplicationRunner securitySchemaPostAlign(SecuritySchemaMigration migration) {
        return args -> migration.alignTwoFactorMethodCheck();
    }
}
