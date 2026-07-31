package com.backend.devsecopsplatform_backend.service.appmgmt;

import com.backend.devsecopsplatform_backend.entity.AppService;
import com.backend.devsecopsplatform_backend.entity.appmgmt.AppServiceRole;
import com.backend.devsecopsplatform_backend.entity.appmgmt.ManagedApplication;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class ServiceTopologyTest {

    @Test
    void deploysBackendsBeforeIndependentFrontends() {
        AppService backend = service("api", AppServiceRole.BACKEND);
        AppService frontend = service("web", AppServiceRole.FRONTEND);

        Map<Integer, List<AppService>> waves = ServiceTopology.computeWaves(app(backend, frontend));

        assertThat(waves.get(1)).containsExactly(backend);
        assertThat(waves.get(2)).containsExactly(frontend);
    }

    @Test
    void dependencyAlwaysMovesServiceToLaterWave() {
        AppService databaseApi = service("database-api", AppServiceRole.BACKEND);
        AppService publicApi = service("public-api", AppServiceRole.BACKEND);
        publicApi.setDependsOnServiceId(databaseApi.getId());
        AppService frontend = service("web", AppServiceRole.FRONTEND);
        frontend.setDependsOnServiceId(publicApi.getId());

        Map<Integer, List<AppService>> waves =
                ServiceTopology.computeWaves(app(databaseApi, publicApi, frontend));

        assertThat(waves.get(1)).containsExactly(databaseApi);
        assertThat(waves.get(2)).containsExactly(publicApi);
        assertThat(waves.get(3)).containsExactly(frontend);
    }

    @Test
    void rejectsBackendDependingOnFrontend() {
        AppService frontend = service("web", AppServiceRole.FRONTEND);
        AppService backend = service("api", AppServiceRole.BACKEND);
        backend.setDependsOnServiceId(frontend.getId());

        assertThatThrownBy(() -> ServiceTopology.computeWaves(app(frontend, backend)))
                .isInstanceOf(AppValidationException.class)
                .hasMessageContaining("ne peut pas dépendre d'un frontend");
    }

    @Test
    void rejectsDependencyCycle() {
        AppService first = service("first", AppServiceRole.BACKEND);
        AppService second = service("second", AppServiceRole.BACKEND);
        first.setDependsOnServiceId(second.getId());
        second.setDependsOnServiceId(first.getId());

        assertThatThrownBy(() -> ServiceTopology.computeWaves(app(first, second)))
                .isInstanceOf(AppValidationException.class)
                .hasMessageContaining("Cycle de dépendances");
    }

    private static AppService service(String name, AppServiceRole role) {
        AppService service = new AppService();
        service.setId(UUID.randomUUID());
        service.setName(name);
        service.setRole(role);
        return service;
    }

    private static ManagedApplication app(AppService... services) {
        ManagedApplication app = new ManagedApplication();
        app.setServices(List.of(services));
        return app;
    }
}
