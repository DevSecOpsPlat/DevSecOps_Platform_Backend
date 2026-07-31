package com.backend.devsecopsplatform_backend.service.appmgmt;

import com.backend.devsecopsplatform_backend.entity.AppService;
import com.backend.devsecopsplatform_backend.entity.appmgmt.AppServiceRole;
import com.backend.devsecopsplatform_backend.entity.appmgmt.ManagedApplication;
import com.backend.devsecopsplatform_backend.entity.appmgmt.ServiceEnvVar;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;
import java.util.UUID;

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

    @Test
    void configuresStableFrontendAndBackendRoutes() {
        AppService api = service("api-fast", AppServiceRole.BACKEND, 8000);
        AppService web = service("vite", AppServiceRole.FRONTEND, 5173);
        web.setDependsOnServiceId(api.getId());
        ManagedApplication app = app(api, web);
        AppK8sManifestService.ManifestOptions options =
                AppK8sManifestService.ManifestOptions.builder()
                        .pullSecretName("gitlab-registry")
                        .ingressEnabled(true)
                        .pathBasedRouting(true)
                        .ingressController("traefik")
                        .ingressClassName("traefik")
                        .ingressDomain("192.168.92.10.nip.io")
                        .resolvedServiceImages(Map.of(
                                "api-fast", "registry.gitlab.com/demo/app/api-fast:abc123",
                                "vite", "registry.gitlab.com/demo/app/vite:abc123"))
                        .build();

        String yaml = manifestService.generateServiceWaveBundle(
                app, "env-demo", options, app.getServices(), true);

        assertThat(yaml)
                .contains("kind: Middleware")
                .contains("path: /api")
                .contains("prefixes:")
                .contains("- /api")
                .contains("name: VITE_API_URL")
                .contains("value: /api")
                .contains("env-demo-app-strip-prefix@kubernetescrd");
    }

    @Test
    void rewritesPublicApiPrefixToBackendContextPath() {
        AppService api = service("api-fast", AppServiceRole.BACKEND, 8080);
        api.setContextPath("/projet");
        api.setHealthCheckPath("/actuator/health");
        AppService web = service("vite", AppServiceRole.FRONTEND, 5173);
        web.setDependsOnServiceId(api.getId());
        ManagedApplication app = app(api, web);
        AppK8sManifestService.ManifestOptions options =
                AppK8sManifestService.ManifestOptions.builder()
                        .pullSecretName("gitlab-registry")
                        .ingressEnabled(true)
                        .pathBasedRouting(true)
                        .ingressController("traefik")
                        .ingressClassName("traefik")
                        .ingressDomain("192.168.92.10.nip.io")
                        .resolvedServiceImages(Map.of(
                                "api-fast", "registry.gitlab.com/demo/app/api-fast:abc123",
                                "vite", "registry.gitlab.com/demo/app/vite:abc123"))
                        .build();

        String yaml = manifestService.generateServiceWaveBundle(
                app, "env-demo", options, app.getServices(), true);

        assertThat(yaml)
                .contains("kind: Middleware")
                .contains("replacePathRegex:")
                .contains("regex: ^/api(.*)$")
                .contains("replacement: /projet$1")
                .contains("path: /projet/actuator/health")
                .contains("value: /api")
                .contains("env-demo-app-api-rewrite@kubernetescrd")
                .doesNotContain("app-strip-prefix@kubernetescrd");
    }

    @Test
    void injectsInternalDnsForBackendDependenciesAndCustomVariables() {
        AppService core = service("core-api", AppServiceRole.BACKEND, 8080);
        AppService worker = service("orders", AppServiceRole.BACKEND, 8090);
        worker.setDependsOnServiceId(core.getId());
        ServiceEnvVar customUrl = new ServiceEnvVar();
        customUrl.setVarKey("ORDERS_CORE_ENDPOINT");
        customUrl.setVarValue("${DEPENDENCY_URL}/v1");
        worker.setEnvVars(List.of(customUrl));
        ManagedApplication app = app(core, worker);
        AppK8sManifestService.ManifestOptions options =
                AppK8sManifestService.ManifestOptions.builder()
                        .pullSecretName("gitlab-registry")
                        .resolvedServiceImages(Map.of(
                                "core-api", "registry.gitlab.com/demo/app/core-api:abc123",
                                "orders", "registry.gitlab.com/demo/app/orders:abc123"))
                        .build();

        String yaml = manifestService.generateServiceWaveBundle(
                app, "env-demo", options, app.getServices(), false);

        String internalUrl = "http://core-api.env-demo.svc.cluster.local:8080";
        assertThat(yaml)
                .contains("name: DEPENDENCY_URL")
                .contains("name: UPSTREAM_URL")
                .contains("name: ORDERS_CORE_ENDPOINT")
                .contains(internalUrl)
                .contains(internalUrl + "/v1");
    }

    private static AppService service(String name, AppServiceRole role, int port) {
        AppService service = new AppService();
        service.setId(UUID.randomUUID());
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
