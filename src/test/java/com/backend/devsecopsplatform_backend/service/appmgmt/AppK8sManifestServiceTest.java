package com.backend.devsecopsplatform_backend.service.appmgmt;

import com.backend.devsecopsplatform_backend.entity.AppService;
import com.backend.devsecopsplatform_backend.entity.appmgmt.AppServiceRole;
import com.backend.devsecopsplatform_backend.entity.appmgmt.ManagedApplication;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class AppK8sManifestServiceTest {

    private final AppK8sManifestService manifestService = new AppK8sManifestService(null);

    @Test
    void assignsEachServiceItsResolvedImage() {
        AppService api = service("api-fast", AppServiceRole.BACKEND, 8000);
        AppService web = service("vite", AppServiceRole.FRONTEND, 5173);
        ManagedApplication app = app(api, web);
        AppK8sManifestService.ManifestOptions options =
                AppK8sManifestService.ManifestOptions.builder()
                        .pullSecretName("gitlab-registry")
                        .resolvedServiceImages(Map.of(
                                "api-fast", "registry.gitlab.com/demo/app/api-fast:abc123",
                                "vite", "registry.gitlab.com/demo/app/vite:abc123"))
                        .build();

        String yaml = manifestService.generateServiceWaveBundle(
                app, "env-demo", options, app.getServices(), false);

        assertThat(yaml)
                .contains("registry.gitlab.com/demo/app/api-fast:abc123")
                .contains("registry.gitlab.com/demo/app/vite:abc123")
                .doesNotContain("CI_REGISTRY_IMAGE");
    }

    @Test
    void rejectsMissingResolvedImage() {
        AppService api = service("api-fast", AppServiceRole.BACKEND, 8000);
        ManagedApplication app = app(api);
        AppK8sManifestService.ManifestOptions options =
                AppK8sManifestService.ManifestOptions.builder()
                        .pullSecretName("gitlab-registry")
                        .resolvedServiceImages(Map.of())
                        .build();

        assertThatThrownBy(() -> manifestService.generateServiceWaveBundle(
                app, "env-demo", options, app.getServices(), false))
                .isInstanceOf(AppValidationException.class)
                .hasMessageContaining("api-fast");
    }

    private static AppService service(String name, AppServiceRole role, int port) {
        AppService service = new AppService();
        service.setName(name);
        service.setRole(role);
        service.setExposedPort(port);
        service.setReplicas(1);
        return service;
    }

    private static ManagedApplication app(AppService... services) {
        ManagedApplication app = new ManagedApplication();
        app.setName("Demo");
        app.setSlug("demo");
        app.setServices(List.of(services));
        return app;
    }
}
