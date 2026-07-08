package com.backend.devsecopsplatform_backend.service.appmgmt;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;

/**
 * Applique des manifestes Kubernetes via {@code kubectl apply} (API URL + token).
 */
@Service
@Slf4j
public class K8sManifestApplyService {

    @Value("${deployment.k8s.api-url:}")
    private String apiUrl;

    @Value("${deployment.k8s.token:}")
    private String token;

    @Value("${deployment.k8s.insecure-skip-tls-verify:true}")
    private boolean insecureSkipTlsVerify;

    public void applyManifests(String multiDocYaml) throws IOException, InterruptedException {
        if (apiUrl == null || apiUrl.isBlank()) {
            throw new IllegalStateException("K8S_API_URL non configuré sur le backend");
        }
        if (token == null || token.isBlank()) {
            throw new IllegalStateException("K8S_TOKEN non configuré sur le backend");
        }
        if (multiDocYaml == null || multiDocYaml.isBlank()) {
            throw new IllegalArgumentException("Manifestes Kubernetes vides");
        }

        List<String> command = new ArrayList<>();
        command.add("kubectl");
        command.add("apply");
        command.add("-f");
        command.add("-");
        command.add("--server");
        command.add(apiUrl.trim());
        command.add("--token");
        command.add(token.trim());
        if (insecureSkipTlsVerify) {
            command.add("--insecure-skip-tls-verify=true");
        }

        ProcessBuilder pb = new ProcessBuilder(command);
        pb.redirectErrorStream(true);
        Process process = pb.start();
        try (OutputStream stdin = process.getOutputStream()) {
            stdin.write(multiDocYaml.getBytes(StandardCharsets.UTF_8));
        }
        String output = new String(process.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
        boolean finished = process.waitFor(3, TimeUnit.MINUTES);
        if (!finished) {
            process.destroyForcibly();
            throw new IOException("kubectl apply timeout");
        }
        if (process.exitValue() != 0) {
            log.error("kubectl apply échec (exit {}): {}", process.exitValue(), output);
            throw new IOException("kubectl apply échoué: " + output);
        }
        log.info("kubectl apply OK: {}", output.trim());
    }

    public boolean isDeploymentReady(String namespace, String deploymentName) {
        if (namespace == null || namespace.isBlank() || deploymentName == null || deploymentName.isBlank()) {
            return false;
        }
        if (apiUrl == null || apiUrl.isBlank() || token == null || token.isBlank()) {
            return false;
        }
        try {
            List<String> command = new ArrayList<>();
            command.add("kubectl");
            command.add("rollout");
            command.add("status");
            command.add("deployment/" + deploymentName);
            command.add("-n");
            command.add(namespace);
            command.add("--timeout=5s");
            command.add("--server");
            command.add(apiUrl.trim());
            command.add("--token");
            command.add(token.trim());
            if (insecureSkipTlsVerify) {
                command.add("--insecure-skip-tls-verify=true");
            }
            Process process = new ProcessBuilder(command).redirectErrorStream(true).start();
            boolean finished = process.waitFor(15, TimeUnit.SECONDS);
            return finished && process.exitValue() == 0;
        } catch (Exception e) {
            log.debug("rollout status {} / {}: {}", namespace, deploymentName, e.getMessage());
            return false;
        }
    }

    public boolean areAllDeploymentsReady(String namespace) {
        if (namespace == null || namespace.isBlank()) {
            return false;
        }
        if (apiUrl == null || apiUrl.isBlank() || token == null || token.isBlank()) {
            return false;
        }
        try {
            List<String> command = new ArrayList<>();
            command.add("kubectl");
            command.add("get");
            command.add("deployments");
            command.add("-n");
            command.add(namespace);
            command.add("-o");
            command.add("jsonpath={range .items[*]}{.spec.replicas}{\":\"}{.status.readyReplicas}{\" \"}{end}");
            command.add("--server");
            command.add(apiUrl.trim());
            command.add("--token");
            command.add(token.trim());
            if (insecureSkipTlsVerify) {
                command.add("--insecure-skip-tls-verify=true");
            }
            Process process = new ProcessBuilder(command).redirectErrorStream(true).start();
            boolean finished = process.waitFor(15, TimeUnit.SECONDS);
            if (!finished || process.exitValue() != 0) {
                return false;
            }
            String output = new String(process.getInputStream().readAllBytes(), StandardCharsets.UTF_8).trim();
            if (output.isBlank()) {
                return false;
            }
            for (String pair : output.split("\\s+")) {
                String[] parts = pair.split(":");
                if (parts.length != 2) {
                    return false;
                }
                String want = parts[0];
                String have = "null".equals(parts[1]) ? "0" : parts[1];
                if (!want.equals(have)) {
                    return false;
                }
            }
            return true;
        } catch (Exception e) {
            log.debug("deployments ready check {}: {}", namespace, e.getMessage());
            return false;
        }
    }

    public void deleteNamespace(String namespace) throws IOException, InterruptedException {
        if (namespace == null || namespace.isBlank()) {
            return;
        }
        if (apiUrl == null || apiUrl.isBlank()) {
            throw new IllegalStateException("K8S_API_URL non configuré sur le backend");
        }
        if (token == null || token.isBlank()) {
            throw new IllegalStateException("K8S_TOKEN non configuré sur le backend");
        }

        List<String> command = new ArrayList<>();
        command.add("kubectl");
        command.add("delete");
        command.add("namespace");
        command.add(namespace);
        command.add("--ignore-not-found=true");
        command.add("--wait=false");
        command.add("--server");
        command.add(apiUrl.trim());
        command.add("--token");
        command.add(token.trim());
        if (insecureSkipTlsVerify) {
            command.add("--insecure-skip-tls-verify=true");
        }

        Process process = new ProcessBuilder(command).redirectErrorStream(true).start();
        String output = new String(process.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
        boolean finished = process.waitFor(2, TimeUnit.MINUTES);
        if (!finished) {
            process.destroyForcibly();
            throw new IOException("kubectl delete namespace timeout");
        }
        if (process.exitValue() != 0) {
            log.error("kubectl delete namespace échec (exit {}): {}", process.exitValue(), output);
            throw new IOException("kubectl delete namespace échoué: " + output);
        }
        log.info("kubectl delete namespace {} OK", namespace);
    }
}
