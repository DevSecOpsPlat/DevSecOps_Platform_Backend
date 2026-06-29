stages:
  - setup
  - code-analysis
  - sca
  - sast
  - secrets-iac
  - build
  - container-scan
  - push-image
  - deploy-k8s
  - zap-scan
  - reporting
  - security-validation
  - schedule-delete

# ── Global variables ──────────────────────────────────────────────
variables:
  GIT_REPO_URL:       ""
  GIT_BRANCH:         "main"
  GITHUB_TOKEN:       ""
  ENVIRONMENT_ID:     ""
  DOCKERFILE_PATH:    "./Dockerfile"
  DEFECTDOJO_URL:     ""
  DEFECTDOJO_TOKEN:   ""
  SONAR_HOST_URL:     ""   # URL de ton SonarQube self-hosted (ex: https://xxxx.trycloudflare.com)
  SONAR_TOKEN:        ""   # Token généré dans SonarQube Admin
  DOCKER_USERNAME:    ""
  DOCKER_ACCESS_TOKEN: ""
  ENVIRONMENT_URL:    ""
  BACKEND_URL:        ""
  PIPELINE_SECRET:    ""   # Secret partagé avec le backend (pipeline.secret) — auth CI sans JWT
  K8S_API_URL:        ""
  K8S_TOKEN:          ""
  K8S_NAMESPACE:      "envirotest-${ENVIRONMENT_ID}"
  K8S_MASTER_IP:      ""
  K8S_SSH_USER:       "ubuntu"
  SSH_PRIVATE_KEY:    ""
  TTL_HOURS:          "4"
  SCA_CRITICAL_THRESHOLD:       "5"
  SCA_HIGH_THRESHOLD:           "20"
  CONTAINER_CRITICAL_THRESHOLD: "0"
  CONTAINER_HIGH_THRESHOLD:     "10"
  SEMGREP_HIGH_THRESHOLD:       "10"
  SEMGREP_MEDIUM_THRESHOLD:     "50"
  IAC_FAILED_THRESHOLD:         "10"
  USE_KANIKO: "false"

# ══════════════════════════════════════════════════════════════════
# STAGE 1 · SETUP — Clone + détection langages
# ══════════════════════════════════════════════════════════════════
hello-world:
  stage: setup
  image: alpine:latest
  retry: 2
  script:
    - echo "EnviroTest Security Pipeline"
    - echo "Environment = $ENVIRONMENT_ID"
    - echo "Repository  = $GIT_REPO_URL"
    - echo "Branch      = $GIT_BRANCH"

clone-repository:
  stage: setup
  image: alpine:latest
  retry: 2
  needs: ["hello-world"]
  before_script:
    - apk add --no-cache git bash
  script:
    - echo "Cloning repository..."
    - test -n "$GIT_REPO_URL" || (echo "GIT_REPO_URL is required" && exit 1)
    - |
      if [ -n "$GITHUB_TOKEN" ]; then
        AUTH_URL=$(echo "$GIT_REPO_URL" | sed "s|https://|https://oauth2:${GITHUB_TOKEN}@|")
      else
        AUTH_URL="$GIT_REPO_URL"
      fi
      git clone --depth 1 --branch "$GIT_BRANCH" "$AUTH_URL" user-repo
    - chmod -R 777 user-repo
    - touch build.env

    - if [ -f "user-repo/package.json" ];                                                   then echo "LANG_NODE=true"   >> build.env; else echo "LANG_NODE=false"   >> build.env; fi
    - if [ -f "user-repo/requirements.txt" ] || [ -f "user-repo/Pipfile" ] || [ -f "user-repo/setup.py" ]; then echo "LANG_PYTHON=true" >> build.env; else echo "LANG_PYTHON=false" >> build.env; fi
    - if [ -f "user-repo/pom.xml" ] || [ -f "user-repo/build.gradle" ];                    then echo "LANG_JAVA=true"   >> build.env; else echo "LANG_JAVA=false"   >> build.env; fi
    - if [ -f "user-repo/go.mod" ];                                                         then echo "LANG_GO=true"     >> build.env; else echo "LANG_GO=false"     >> build.env; fi
    - if [ -f "user-repo/Gemfile" ];                                                        then echo "LANG_RUBY=true"   >> build.env; else echo "LANG_RUBY=false"   >> build.env; fi
    - if [ -f "user-repo/composer.json" ];                                                  then echo "LANG_PHP=true"    >> build.env; else echo "LANG_PHP=false"    >> build.env; fi
    - if [ -f "user-repo/Cargo.toml" ];                                                     then echo "LANG_RUST=true"   >> build.env; else echo "LANG_RUST=false"   >> build.env; fi
    - if find user-repo -maxdepth 2 -name "*.csproj" -o -name "*.fsproj" | grep -q .;      then echo "LANG_DOTNET=true" >> build.env; else echo "LANG_DOTNET=false" >> build.env; fi
    - if find user-repo -name "*.c" -o -name "*.cpp" -o -name "*.h" | grep -q .;           then echo "LANG_CPP=true"    >> build.env; else echo "LANG_CPP=false"    >> build.env; fi

    - |
      if [ -f "user-repo/angular.json" ]; then
        echo "FRAMEWORK=angular" >> build.env
      elif grep -q '"react"' user-repo/package.json 2>/dev/null; then
        echo "FRAMEWORK=react" >> build.env
      elif grep -q '"next"' user-repo/package.json 2>/dev/null; then
        echo "FRAMEWORK=next" >> build.env
      elif [ -f "user-repo/vue.config.js" ]; then
        echo "FRAMEWORK=vue" >> build.env
      elif grep -q '"spring-boot"' user-repo/pom.xml 2>/dev/null; then
        echo "FRAMEWORK=spring-boot" >> build.env
      else
        echo "FRAMEWORK=unknown" >> build.env
      fi

    - if [ -f "user-repo/Dockerfile" ];                                   then echo "HAS_DOCKERFILE=true"  >> build.env; else echo "HAS_DOCKERFILE=false"  >> build.env; fi
    - if find user-repo -name "*.tf" | grep -q .;                         then echo "HAS_TERRAFORM=true"   >> build.env; else echo "HAS_TERRAFORM=false"   >> build.env; fi
    - if find user-repo -name "*.tf" -o -name "*.yaml" -o -name "*.yml" | grep -q .; then echo "HAS_IAC=true" >> build.env; else echo "HAS_IAC=false" >> build.env; fi

    - cat build.env
  artifacts:
    paths:
      - user-repo/
      - build.env
    reports:
      dotenv: build.env
    expire_in: 1 day

# ══════════════════════════════════════════════════════════════════
# STAGE 2 · CODE-ANALYSIS — SonarQube self-hosted + community branch plugin
#
# Stratégie Option C : UN seul projet par repo, toutes les branches
# dans ce projet grace au community branch plugin.
# PROJECT_KEY = slug du repo (sans branche)
# sonar.branch.name = nom de la branche scannée
#
# Résultat dans SonarQube :
#   Projet : Angular
#   ├── Branche : main
#   ├── Branche : test
#   └── Branche : feature/auth
# ══════════════════════════════════════════════════════════════════
sonarqube-setup:
  stage: code-analysis
  image: alpine:latest
  needs: ["clone-repository"]
  before_script:
    - apk add --no-cache curl jq
  script:
    - |
      if [ -z "$SONAR_HOST_URL" ] || [ -z "$SONAR_TOKEN" ]; then
        echo "SONAR_HOST_URL or SONAR_TOKEN not set — skip"
        echo "PROJECT_KEY=" >> project.env
        exit 0
      fi

      # Build project key
      REPO_NAME=$(echo "${GIT_REPO_URL}" | sed -E 's|.*/||; s|\.git$||')
      PROJECT_KEY=$(echo "${GIT_REPO_URL}" \
        | sed -E 's|https?://||; s|\.git$||; s|/|_|g; s|[^a-zA-Z0-9_]|_|g')

      echo "Repo name   = ${REPO_NAME}"
      echo "Project key = ${PROJECT_KEY}"
      echo "Branch      = ${GIT_BRANCH}"
      echo "SonarQube   = ${SONAR_HOST_URL}"

      # Check if project exists — with error handling
      RESPONSE=$(curl -s -w "\n%{http_code}" -u "${SONAR_TOKEN}:" \
        "${SONAR_HOST_URL}/api/projects/search?projects=${PROJECT_KEY}" 2>&1) || true
      HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
      BODY=$(echo "$RESPONSE" | head -n-1)

      # Debug: print response (mask token)
      echo "HTTP status: $HTTP_CODE"
      echo "Response body (first 200 chars): ${BODY:0:200}"

      if [ "$HTTP_CODE" != "200" ]; then
        echo "ERROR: SonarQube API returned HTTP $HTTP_CODE"
        echo "PROJECT_KEY=" >> project.env
        exit 0
      fi

      # Validate JSON
      if ! echo "$BODY" | jq -e . >/dev/null 2>&1; then
        echo "ERROR: Response is not valid JSON"
        echo "PROJECT_KEY=" >> project.env
        exit 0
      fi

      EXISTS=$(echo "$BODY" | jq -r '.components | length // 0')
      echo "Existing projects: $EXISTS"

      if [ "$EXISTS" -eq 0 ]; then
        echo "Creating SonarQube project ${PROJECT_KEY}..."
        CREATE_RESP=$(curl -s -w "\n%{http_code}" -X POST -u "${SONAR_TOKEN}:" \
          "${SONAR_HOST_URL}/api/projects/create" \
          -d "project=${PROJECT_KEY}&name=${REPO_NAME}&visibility=private")
        CREATE_HTTP=$(echo "$CREATE_RESP" | tail -n1)
        CREATE_BODY=$(echo "$CREATE_RESP" | head -n-1)
        if [ "$CREATE_HTTP" != "200" ]; then
          echo "Project creation failed: HTTP $CREATE_HTTP"
          echo "Response: $CREATE_BODY"
        else
          echo "Project created successfully"
        fi
      else
        echo "Project already exists: ${PROJECT_KEY}"
      fi

      # Set quality gate (ignore errors)
      curl -s -X POST -u "${SONAR_TOKEN}:" \
        "${SONAR_HOST_URL}/api/qualitygates/select" \
        -d "projectKey=${PROJECT_KEY}&gateName=Sonar way" \
        | jq -r 'if .errors then .errors else "Quality gate attached" end' 2>/dev/null || echo "Quality gate set failed"

      echo "PROJECT_KEY=${PROJECT_KEY}" >> project.env
      echo "SONAR_DASHBOARD_URL=${SONAR_HOST_URL}/dashboard?id=${PROJECT_KEY}&branch=${GIT_BRANCH}" >> project.env
      echo "Dashboard: ${SONAR_HOST_URL}/dashboard?id=${PROJECT_KEY}&branch=${GIT_BRANCH}"
  artifacts:
    reports:
      dotenv: project.env
    expire_in: 1 hour
  allow_failure: true

sonarqube-scan:
  stage: code-analysis
  image: sonarsource/sonar-scanner-cli:latest
  needs:
    - job: clone-repository
    - job: sonarqube-setup
  script:
    - |
      if [ -z "$SONAR_HOST_URL" ] || [ -z "$SONAR_TOKEN" ] || [ -z "$PROJECT_KEY" ]; then
        echo "SonarQube non configure — skip"
        exit 0
      fi
    - echo "SonarQube Scan — project=${PROJECT_KEY} branch=${GIT_BRANCH}"
    - cd user-repo
    - |
      sonar-scanner \
        -Dsonar.projectKey="${PROJECT_KEY}" \
        -Dsonar.sources=. \
        -Dsonar.host.url="${SONAR_HOST_URL}" \
        -Dsonar.token="${SONAR_TOKEN}" \
        -Dsonar.branch.name="${GIT_BRANCH}" \
        -Dsonar.exclusions="**/node_modules/**,**/dist/**,**/target/**,**/build/**" \
        -Dsonar.scm.provider=git
      echo "Dashboard: ${SONAR_HOST_URL}/dashboard?id=${PROJECT_KEY}&branch=${GIT_BRANCH}"
  allow_failure: true

# ══════════════════════════════════════════════════════════════════
# STAGE 3 · SCA — Trivy FS
# ══════════════════════════════════════════════════════════════════
trivy-fs-scan:
  stage: sca
  image: alpine:latest
  needs: ["clone-repository"]
  before_script:
    - apk add --no-cache curl
    - curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin
  script:
    - echo "Trivy FS — Universal SCA"
    - mkdir -p reports/trivy
    - |
      trivy fs \
        --scanners vuln \
        --format json \
        --output reports/trivy/trivy-fs.json \
        user-repo/ || true
    - |
      apk add --no-cache jq 2>/dev/null || true
      CRIT=$(jq '[.Results[]?.Vulnerabilities[]? | select(.Severity=="CRITICAL")] | length' reports/trivy/trivy-fs.json 2>/dev/null || echo 0)
      HIGH=$(jq '[.Results[]?.Vulnerabilities[]? | select(.Severity=="HIGH")] | length' reports/trivy/trivy-fs.json 2>/dev/null || echo 0)
      echo "Trivy FS: CRITICAL=$CRIT HIGH=$HIGH"
  artifacts:
    paths:
      - reports/trivy/trivy-fs.json
    expire_in: 1 day
  allow_failure: true

syft-license-scan:
  stage: sca
  image: alpine:latest
  needs: ["clone-repository"]
  before_script:
    - apk add --no-cache curl
    - curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin
  script:
    - echo "Syft — License compliance"
    - mkdir -p reports/license
    - syft dir:user-repo --output spdx-json=reports/license/sbom-spdx.json || true
  artifacts:
    paths:
      - reports/license/sbom-spdx.json
    expire_in: 1 day
  allow_failure: true

# ══════════════════════════════════════════════════════════════════
# STAGE 4 · SAST — Semgrep + Hadolint
# ══════════════════════════════════════════════════════════════════
semgrep-sast:
  stage: sast
  image: returntocorp/semgrep:latest
  needs: ["clone-repository"]
  script:
    - echo "Semgrep — Universal SAST"
    - mkdir -p reports/sast
    - |
      semgrep scan \
        --config auto \
        --json \
        -o reports/sast/semgrep.json \
        user-repo/ || echo '{"results":[],"errors":[]}' > reports/sast/semgrep.json
    - |
      apk add --no-cache jq 2>/dev/null || true
      HIGH=$(jq '[.results[]? | select(.extra.severity=="ERROR")] | length' reports/sast/semgrep.json 2>/dev/null || echo 0)
      MED=$(jq '[.results[]? | select(.extra.severity=="WARNING")] | length' reports/sast/semgrep.json 2>/dev/null || echo 0)
      echo "Semgrep: HIGH=$HIGH MEDIUM=$MED"
  artifacts:
    paths:
      - reports/sast/semgrep.json
    expire_in: 1 day
  allow_failure: true

hadolint-dockerfile:
  stage: sast
  image: hadolint/hadolint:latest-debian
  needs: ["clone-repository"]
  script:
    - echo "Hadolint — Dockerfile security lint"
    - mkdir -p reports/sast
    - |
      if [ "$HAS_DOCKERFILE" != "true" ]; then
        echo "Skipping — No Dockerfile"
        echo "[]" > reports/sast/hadolint.json
        exit 0
      fi
    - hadolint --format json user-repo/Dockerfile > reports/sast/hadolint.json || echo '[]' > reports/sast/hadolint.json
  artifacts:
    paths:
      - reports/sast/hadolint.json
    expire_in: 1 day
  allow_failure: true

# ══════════════════════════════════════════════════════════════════
# STAGE 5 · SECRETS-IAC — Gitleaks + Checkov
# ══════════════════════════════════════════════════════════════════
gitleaks-secrets:
  stage: secrets-iac
  image: alpine:latest
  needs: ["clone-repository"]
  before_script:
    - apk add --no-cache curl jq
    - curl -sSfL https://github.com/zricethezav/gitleaks/releases/download/v8.18.2/gitleaks_8.18.2_linux_x64.tar.gz | tar xz
    - mv gitleaks /usr/local/bin/
  script:
    - echo "Gitleaks — Secrets detection"
    - mkdir -p reports/secrets
    - |
      gitleaks detect \
        --source user-repo \
        --no-git \
        --report-path reports/secrets/gitleaks.json \
        --report-format json \
        --exit-code 0 || true
      if [ ! -f reports/secrets/gitleaks.json ]; then
        echo "[]" > reports/secrets/gitleaks.json
      fi
      COUNT=$(jq '. | if type=="array" then length else 0 end' reports/secrets/gitleaks.json 2>/dev/null || echo 0)
      echo "Secrets found: $COUNT"
  artifacts:
    paths:
      - reports/secrets/gitleaks.json
    expire_in: 1 day
  allow_failure: true

checkov-iac:
  stage: secrets-iac
  image: python:3.11-alpine
  needs:
    - job: clone-repository
      artifacts: true
  before_script:
    - pip install checkov --quiet
  script:
    - echo "Checkov — IaC scan"
    - mkdir -p reports/iac
    - |
      if [ "$HAS_IAC" != "true" ]; then
        echo "Skipping — No IaC files detected"
        echo '{"results":{"passed_checks":[],"failed_checks":[]}}' > reports/iac/results_json.json
        exit 0
      fi
    - |
      checkov --directory user-repo \
        --output json \
        --output-file-path reports/iac/ \
        --soft-fail || true

      # Checkov génère parfois results_json.json, parfois checkov_results.json
      # Normaliser en un seul fichier attendu par aggregate-report
      if [ ! -f reports/iac/results_json.json ]; then
        if [ -f reports/iac/checkov_results.json ]; then
          cp reports/iac/checkov_results.json reports/iac/results_json.json
          echo "Renamed checkov_results.json -> results_json.json"
        elif ls reports/iac/*.json 2>/dev/null | head -1 | grep -q .; then
          FIRST=$(ls reports/iac/*.json | head -1)
          cp "$FIRST" reports/iac/results_json.json
          echo "Copied $FIRST -> results_json.json"
        else
          echo "Aucun fichier JSON Checkov trouvé — fichier vide créé"
          echo '{"results":{"passed_checks":[],"failed_checks":[]}}' > reports/iac/results_json.json
        fi
      fi

      # Debug : afficher le nb de checks échoués
      IS_ARRAY=$(jq 'if type=="array" then "yes" else "no" end' reports/iac/results_json.json 2>/dev/null || echo "no")
      if [ "$IS_ARRAY" = "yes" ]; then
        FAILED=$(jq '[.[].results.failed_checks // [] | length] | add // 0' reports/iac/results_json.json 2>/dev/null || echo 0)
      else
        FAILED=$(jq '.results.failed_checks | length' reports/iac/results_json.json 2>/dev/null || echo 0)
      fi
      echo "Checkov failed checks: $FAILED (format: $IS_ARRAY)"
      ls -lh reports/iac/
  artifacts:
    paths:
      - reports/iac/
    expire_in: 1 day
  allow_failure: true

# ══════════════════════════════════════════════════════════════════
# STAGE 6 · BUILD — Docker image
# ══════════════════════════════════════════════════════════════════
build-docker-image:
  stage: build
  image: docker:latest
  retry: 2
  needs:
    - job: clone-repository
      artifacts: true
  variables:
    DOCKER_HOST: unix:///var/run/docker.sock
    DOCKER_TLS_CERTDIR: ""
  script:
    - echo "Building Docker image"
    - |
      if [ "$USE_KANIKO" = "true" ]; then
        echo "USE_KANIKO=true — skipping socket build"
        exit 0
      fi
    - until docker info 2>/dev/null; do echo "Waiting for Docker daemon..."; sleep 3; done
    - cd user-repo
    - IMAGE_NAME="${DOCKER_USERNAME}/envirotest-app:${ENVIRONMENT_ID}"
    - docker build -f ${DOCKERFILE_PATH} -t ${IMAGE_NAME} .
    - docker save -o ../image.tar ${IMAGE_NAME}
    - cd ..
    - echo "IMAGE_NAME=${IMAGE_NAME}" > image_name.env
    - echo "Image built $IMAGE_NAME"
  artifacts:
    paths:
      - image.tar
      - image_name.env
    expire_in: 2 hours
  allow_failure: false

build-docker-image-kaniko:
  stage: build
  image:
    name: gcr.io/kaniko-project/executor:debug
    entrypoint: [""]
  needs:
    - job: clone-repository
      artifacts: true
  rules:
    - if: '$USE_KANIKO == "true"'
  script:
    - echo "Kaniko build"
    - |
      IMAGE_NAME="${DOCKER_USERNAME}/envirotest-app:${ENVIRONMENT_ID}"
      echo "${DOCKER_ACCESS_TOKEN}" | /kaniko/executor \
        --context=dir://user-repo \
        --dockerfile=user-repo/${DOCKERFILE_PATH} \
        --destination="${IMAGE_NAME}" \
        --no-push \
        --tarPath=/workspace/image.tar
      echo "IMAGE_NAME=${IMAGE_NAME}" > image_name.env
      cp /workspace/image.tar image.tar
  artifacts:
    paths:
      - image.tar
      - image_name.env
    expire_in: 2 hours
  allow_failure: false

# ══════════════════════════════════════════════════════════════════
# STAGE 7 · CONTAINER-SCAN — Anchore Grype
# ══════════════════════════════════════════════════════════════════
grype-image-scan:
  stage: container-scan
  image: alpine:latest
  retry: 2
  needs:
    - job: build-docker-image
      artifacts: true
      optional: true
    - job: build-docker-image-kaniko
      artifacts: true
      optional: true
  before_script:
    - apk add --no-cache curl jq
    - curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin
  script:
    - echo "Grype — Container vulnerability scan"
    - mkdir -p reports/container-scan
    - |
      if [ ! -f image.tar ]; then
        echo "No image.tar — skipping container scan"
        echo '{"matches":[]}' > reports/container-scan/grype-image.json
        exit 0
      fi
    - grype docker-archive:$(pwd)/image.tar -o json > reports/container-scan/grype-image.json || true
    - |
      CRIT=$(jq '[.matches[]?.vulnerability?.severity? | select(.=="Critical")] | length' reports/container-scan/grype-image.json 2>/dev/null || echo 0)
      HIGH=$(jq '[.matches[]?.vulnerability?.severity? | select(.=="High")] | length' reports/container-scan/grype-image.json 2>/dev/null || echo 0)
      echo "Grype: CRITICAL=$CRIT HIGH=$HIGH"
  artifacts:
    paths:
      - reports/container-scan/grype-image.json
    expire_in: 1 day
  allow_failure: true

# ══════════════════════════════════════════════════════════════════
# STAGE 8 · PUSH-IMAGE — Docker Hub
# ══════════════════════════════════════════════════════════════════
push-docker-image:
  stage: push-image
  image: docker:latest
  retry: 2
  needs:
    - job: build-docker-image
      artifacts: true
      optional: true
    - job: build-docker-image-kaniko
      artifacts: true
      optional: true
  variables:
    DOCKER_HOST: unix:///var/run/docker.sock
    DOCKER_TLS_CERTDIR: ""
  script:
    - |
      if [ ! -f image.tar ]; then
        echo "No image.tar — skipping push"
        exit 0
      fi
    - until docker info 2>/dev/null; do echo "Waiting for Docker..."; sleep 3; done
    - docker load -i image.tar
    - . image_name.env
    - echo "$DOCKER_ACCESS_TOKEN" | docker login -u "$DOCKER_USERNAME" --password-stdin
    - docker push ${IMAGE_NAME}
    - echo "Pushed ${IMAGE_NAME}"
  allow_failure: true

# ══════════════════════════════════════════════════════════════════
# STAGE 9 · DEPLOY-K8S — Environnement éphémère Kubernetes
# ══════════════════════════════════════════════════════════════════
deploy-to-kubernetes:
  stage: deploy-k8s
  image: alpine:3.18
  tags:
    - k8s-deployer
  needs:
    - job: push-docker-image
    - job: clone-repository
      artifacts: true
      optional: true
  before_script:
    - apk add --no-cache curl jq gettext openssh-client
    - curl -LO "https://dl.k8s.io/release/v1.28.0/bin/linux/amd64/kubectl"
    - chmod +x kubectl && mv kubectl /usr/local/bin/
    - |
      cat > kubeconfig.yaml << EOF
      apiVersion: v1
      kind: Config
      clusters:
      - name: local-cluster
        cluster:
          server: ${K8S_API_URL}
          insecure-skip-tls-verify: true
      users:
      - name: gitlab-deployer
        user:
          token: ${K8S_TOKEN}
      contexts:
      - name: default
        context:
          cluster: local-cluster
          user: gitlab-deployer
      current-context: default
      EOF
    - export KUBECONFIG=$(pwd)/kubeconfig.yaml
  script:
    - echo "Deploying to namespace ${K8S_NAMESPACE}"
    - kubectl create namespace ${K8S_NAMESPACE} --dry-run=client -o yaml | kubectl apply -f -
    - |
      cat > deployment.yaml << EOF
      apiVersion: apps/v1
      kind: Deployment
      metadata:
        name: app-${ENVIRONMENT_ID}
        namespace: ${K8S_NAMESPACE}
        labels:
          app: envirotest
          env-id: ${ENVIRONMENT_ID}
      spec:
        replicas: 1
        selector:
          matchLabels:
            app: envirotest
            env-id: ${ENVIRONMENT_ID}
        template:
          metadata:
            labels:
              app: envirotest
              env-id: ${ENVIRONMENT_ID}
          spec:
            containers:
            - name: app
              image: ${DOCKER_USERNAME}/envirotest-app:${ENVIRONMENT_ID}
              imagePullPolicy: Always
              ports:
              - containerPort: 80
      EOF
    - |
      cat > service.yaml << EOF
      apiVersion: v1
      kind: Service
      metadata:
        name: app-${ENVIRONMENT_ID}-svc
        namespace: ${K8S_NAMESPACE}
      spec:
        selector:
          app: envirotest
          env-id: ${ENVIRONMENT_ID}
        ports:
        - port: 80
          targetPort: 80
      EOF
    - |
      cat > ingress.yaml << EOF
      apiVersion: networking.k8s.io/v1
      kind: Ingress
      metadata:
        name: app-${ENVIRONMENT_ID}-ingress
        namespace: ${K8S_NAMESPACE}
        annotations:
          kubernetes.io/ingress.class: nginx
      spec:
        rules:
        - host: app-${ENVIRONMENT_ID}.${K8S_MASTER_IP}.nip.io
          http:
            paths:
            - path: /
              pathType: Prefix
              backend:
                service:
                  name: app-${ENVIRONMENT_ID}-svc
                  port:
                    number: 80
      EOF
    - kubectl apply -f deployment.yaml
    - kubectl apply -f service.yaml
    - kubectl apply -f ingress.yaml
    - kubectl rollout status deployment/app-${ENVIRONMENT_ID} -n ${K8S_NAMESPACE} --timeout=5m
    - |
      INGRESS_PORT=$(kubectl get svc -n ingress-nginx ingress-nginx-controller \
        -o jsonpath='{.spec.ports[?(@.name=="http")].nodePort}' 2>/dev/null || echo "80")
      APP_URL="http://app-${ENVIRONMENT_ID}.${K8S_MASTER_IP}.nip.io:${INGRESS_PORT}"
      echo "APP_URL=${APP_URL}" > app_url.env
      echo "Deployed: ${APP_URL}"
  artifacts:
    reports:
      dotenv: app_url.env
    paths:
      - app_url.env
    expire_in: 1 day
  allow_failure: true

# ══════════════════════════════════════════════════════════════════
# STAGE 10 · DAST — OWASP ZAP
# ══════════════════════════════════════════════════════════════════
owasp-zap-dast:
  stage: zap-scan
  image: ghcr.io/zaproxy/zaproxy:stable
  needs:
    - job: deploy-to-kubernetes
      artifacts: true
      optional: true
  before_script:
    - apk add --no-cache jq 2>/dev/null || apt-get install -y -qq jq 2>/dev/null || true
  script:
    - echo "OWASP ZAP Baseline DAST — Target ${APP_URL}"
    - mkdir -p reports/dast
    - |
      if [ -z "$APP_URL" ]; then
        echo "APP_URL not set — skipping DAST"
        echo '{"site":[]}' > reports/dast/zap-report.json
        exit 0
      fi
    - |
      MAX=10; N=0
      until curl -sf --max-time 5 "${APP_URL}" >/dev/null 2>&1 || [ $N -ge $MAX ]; do
        echo "Waiting for app... ($N/$MAX)"; sleep 10; N=$((N+1))
      done
    - |
      zap-baseline.py \
        -t "${APP_URL}" \
        -x reports/dast/zap-report.xml \
        -I \
        --auto || true
    - |
      ALERTS=$(jq '[.site[]?.alerts[]?] | length' reports/dast/zap-report.json 2>/dev/null || echo 0)
      HIGH_DAST=$(jq '[.site[]?.alerts[]? | select(.riskcode=="3")] | length' reports/dast/zap-report.json 2>/dev/null || echo 0)
      echo "DAST: Total=$ALERTS High=$HIGH_DAST"
  artifacts:
    paths:
      - reports/dast/zap-report.xml
    expire_in: 7 days
  allow_failure: true

# ══════════════════════════════════════════════════════════════════
# STAGE 11 · REPORTING — Agrégation + DefectDojo
# ══════════════════════════════════════════════════════════════════
aggregate-report:
  stage: reporting
  image: alpine:latest
  needs:
    - clone-repository
    - trivy-fs-scan
    - syft-license-scan
    - semgrep-sast
    - hadolint-dockerfile
    - gitleaks-secrets
    - checkov-iac
    - grype-image-scan
    - owasp-zap-dast
  before_script:
    - apk add --no-cache jq
  script:
    - echo "Aggregating all scan results..."
    - mkdir -p final-report
    - source build.env 2>/dev/null || true

    - |
      echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
      echo "ARTIFACT VALIDATION"
      echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
      MISSING=0; EMPTY=0; TOTAL=0

      check_file() {
        local file="$1" name="$2"
        TOTAL=$((TOTAL + 1))
        if [ ! -f "$file" ]; then
          echo "MISSING: $name"
          MISSING=$((MISSING + 1))
        elif [ ! -s "$file" ]; then
          echo "EMPTY: $name"
          EMPTY=$((EMPTY + 1))
        else
          echo "OK: $name ($(wc -c < "$file") bytes)"
        fi
      }

      check_file "reports/trivy/trivy-fs.json"             "Trivy FS (SCA)"
      check_file "reports/license/sbom-spdx.json"          "Syft SBOM (Licenses)"
      check_file "reports/sast/semgrep.json"               "Semgrep (SAST)"
      check_file "reports/sast/hadolint.json"              "Hadolint (Dockerfile)"
      check_file "reports/secrets/gitleaks.json"           "Gitleaks (Secrets)"
      check_file "reports/iac/results_json.json"           "Checkov (IaC)"
      check_file "reports/container-scan/grype-image.json" "Grype Image (Container)"
      check_file "reports/dast/zap-report.json"            "OWASP ZAP (DAST)"
      echo "Total: $TOTAL | OK: $((TOTAL-MISSING-EMPTY)) | Missing: $MISSING | Empty: $EMPTY"
      echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

    - |
      SCA_CRITICAL=$(jq '[.Results[]?.Vulnerabilities[]? | select(.Severity=="CRITICAL")] | length' reports/trivy/trivy-fs.json 2>/dev/null || echo 0); SCA_CRITICAL=${SCA_CRITICAL:-0}
      SCA_HIGH=$(jq '[.Results[]?.Vulnerabilities[]? | select(.Severity=="HIGH")] | length' reports/trivy/trivy-fs.json 2>/dev/null || echo 0); SCA_HIGH=${SCA_HIGH:-0}
      SCA_MEDIUM=$(jq '[.Results[]?.Vulnerabilities[]? | select(.Severity=="MEDIUM")] | length' reports/trivy/trivy-fs.json 2>/dev/null || echo 0); SCA_MEDIUM=${SCA_MEDIUM:-0}
      SCA_LOW=$(jq '[.Results[]?.Vulnerabilities[]? | select(.Severity=="LOW")] | length' reports/trivy/trivy-fs.json 2>/dev/null || echo 0); SCA_LOW=${SCA_LOW:-0}
      CONTAINER_CRITICAL=$(jq '[.matches[]?.vulnerability?.severity? | select(.=="Critical")] | length' reports/container-scan/grype-image.json 2>/dev/null || echo 0); CONTAINER_CRITICAL=${CONTAINER_CRITICAL:-0}
      CONTAINER_HIGH=$(jq '[.matches[]?.vulnerability?.severity? | select(.=="High")] | length' reports/container-scan/grype-image.json 2>/dev/null || echo 0); CONTAINER_HIGH=${CONTAINER_HIGH:-0}
      SECRETS=$(jq '. | if type=="array" then length else 0 end' reports/secrets/gitleaks.json 2>/dev/null || echo 0); SECRETS=${SECRETS:-0}
      SEMGREP_HIGH=$(jq '[.results[]? | select(.extra.severity=="ERROR")] | length' reports/sast/semgrep.json 2>/dev/null || echo 0); SEMGREP_HIGH=${SEMGREP_HIGH:-0}
      SEMGREP_MEDIUM=$(jq '[.results[]? | select(.extra.severity=="WARNING")] | length' reports/sast/semgrep.json 2>/dev/null || echo 0); SEMGREP_MEDIUM=${SEMGREP_MEDIUM:-0}
      SEMGREP_INFO=$(jq '[.results[]? | select(.extra.severity=="INFO")] | length' reports/sast/semgrep.json 2>/dev/null || echo 0); SEMGREP_INFO=${SEMGREP_INFO:-0}
      HADOLINT_ERRORS=$(jq 'length' reports/sast/hadolint.json 2>/dev/null || echo 0); HADOLINT_ERRORS=${HADOLINT_ERRORS:-0}
      # Checkov peut générer un objet {results:{failed_checks:[]}} ou un tableau [{results:{failed_checks:[]}}]
      IS_ARRAY=$(jq 'if type=="array" then "yes" else "no" end' reports/iac/results_json.json 2>/dev/null || echo "no")
      if [ "$IS_ARRAY" = "yes" ]; then
        CHECKOV_FAILED=$(jq '[.[].results.failed_checks // [] | length] | add // 0' reports/iac/results_json.json 2>/dev/null || echo 0)
      else
        CHECKOV_FAILED=$(jq '.results.failed_checks | length' reports/iac/results_json.json 2>/dev/null || echo 0)
      fi
      CHECKOV_FAILED=${CHECKOV_FAILED:-0}
      DAST_HIGH=$(jq '[.site[]?.alerts[]? | select(.riskcode=="3")] | length' reports/dast/zap-report.json 2>/dev/null || echo 0); DAST_HIGH=${DAST_HIGH:-0}
      DAST_MEDIUM=$(jq '[.site[]?.alerts[]? | select(.riskcode=="2")] | length' reports/dast/zap-report.json 2>/dev/null || echo 0); DAST_MEDIUM=${DAST_MEDIUM:-0}
      DAST_LOW=$(jq '[.site[]?.alerts[]? | select(.riskcode=="1")] | length' reports/dast/zap-report.json 2>/dev/null || echo 0); DAST_LOW=${DAST_LOW:-0}

    - |
      cat > final-report/summary.json << EOF
      {
        "environment_id": "$ENVIRONMENT_ID",
        "git_repository": "$GIT_REPO_URL",
        "git_branch": "$GIT_BRANCH",
        "pipeline_id": "$CI_PIPELINE_ID",
        "scan_date": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
        "app_url": "${APP_URL:-}",
        "languages_detected": {
          "node":   ${LANG_NODE:-false},
          "python": ${LANG_PYTHON:-false},
          "java":   ${LANG_JAVA:-false},
          "go":     ${LANG_GO:-false},
          "ruby":   ${LANG_RUBY:-false},
          "php":    ${LANG_PHP:-false},
          "rust":   ${LANG_RUST:-false},
          "dotnet": ${LANG_DOTNET:-false},
          "cpp":    ${LANG_CPP:-false}
        },
        "framework": "${FRAMEWORK:-unknown}",
        "has_dockerfile": ${HAS_DOCKERFILE:-false},
        "has_iac": ${HAS_IAC:-false},
        "sca":       { "critical": ${SCA_CRITICAL},       "high": ${SCA_HIGH}, "medium": ${SCA_MEDIUM}, "low": ${SCA_LOW} },
        "container": { "critical": ${CONTAINER_CRITICAL}, "high": ${CONTAINER_HIGH} },
        "secrets": ${SECRETS},
        "sast": {
          "semgrep_high": ${SEMGREP_HIGH}, "semgrep_medium": ${SEMGREP_MEDIUM},
          "semgrep_info": ${SEMGREP_INFO}, "hadolint_errors": ${HADOLINT_ERRORS}
        },
        "dast": { "high": ${DAST_HIGH}, "medium": ${DAST_MEDIUM}, "low": ${DAST_LOW} },
        "iac":  { "checkov_failed": ${CHECKOV_FAILED} },
        "status": "completed",
        "reports_url": "$CI_JOB_URL/artifacts"
      }
      EOF
    - cat final-report/summary.json
  artifacts:
    paths:
      - reports/
      - final-report/summary.json
    expire_in: 7 days

import-defectdojo:
  stage: reporting
  image: alpine:latest
  needs:
    - aggregate-report
  before_script:
    - apk add --no-cache curl jq python3
  script:
    - |
      echo "DefectDojo import"
      if [ -z "$DEFECTDOJO_URL" ] || [ -z "$DEFECTDOJO_TOKEN" ]; then
        echo "DefectDojo not configured — skipping"
        exit 0
      fi

      REPO_NAME=$(echo "${GIT_REPO_URL}" | sed -E 's|.*/||; s|\.git$||')
      PRODUCT_NAME="${REPO_NAME}"
      ENGAGEMENT_NAME="${REPO_NAME}_${GIT_BRANCH}"

      PROD_TYPE_ID=$(curl -s -H "Authorization: ${DEFECTDOJO_TOKEN}" \
        "${DEFECTDOJO_URL}/api/v2/product_types/" | jq -r '.results[0].id // empty')
      if [ -z "$PROD_TYPE_ID" ] || [ "$PROD_TYPE_ID" = "null" ]; then
        PROD_TYPE_ID=$(curl -s -X POST "${DEFECTDOJO_URL}/api/v2/product_types/" \
          -H "Authorization: ${DEFECTDOJO_TOKEN}" -H "Content-Type: application/json" \
          -d '{"name":"Default CI/CD","description":"Created automatically"}' | jq -r '.id // empty')
      fi

      PRODUCT_ID=$(curl -s -H "Authorization: ${DEFECTDOJO_TOKEN}" \
        "${DEFECTDOJO_URL}/api/v2/products/?name=${PRODUCT_NAME}" | jq -r '.results[0].id // empty')
      if [ -z "$PRODUCT_ID" ] || [ "$PRODUCT_ID" = "null" ]; then
        PRODUCT_ID=$(curl -s -X POST "${DEFECTDOJO_URL}/api/v2/products/" \
          -H "Authorization: ${DEFECTDOJO_TOKEN}" -H "Content-Type: application/json" \
          -d "{\"name\":\"$PRODUCT_NAME\",\"description\":\"${GIT_REPO_URL}\",\"prod_type\":$PROD_TYPE_ID}" \
          | jq -r '.id')
        echo "Product created: $PRODUCT_ID"
      fi
      [ -z "$PRODUCT_ID" ] || [ "$PRODUCT_ID" = "null" ] && echo "Failed to get product ID" && exit 1

      TODAY=$(date +%Y-%m-%d)
      END_DATE=$(date -d "+30 days" +%Y-%m-%d 2>/dev/null || date -v+30d +%Y-%m-%d 2>/dev/null || echo "$TODAY")

      ENGAGEMENT_ID=$(curl -s -H "Authorization: ${DEFECTDOJO_TOKEN}" \
        "${DEFECTDOJO_URL}/api/v2/engagements/?product=${PRODUCT_ID}&name=${ENGAGEMENT_NAME}" \
        | jq -r '.results[0].id // empty')
      if [ -z "$ENGAGEMENT_ID" ] || [ "$ENGAGEMENT_ID" = "null" ]; then
        ENGAGEMENT_ID=$(curl -s -X POST "${DEFECTDOJO_URL}/api/v2/engagements/" \
          -H "Authorization: ${DEFECTDOJO_TOKEN}" -H "Content-Type: application/json" \
          -d "{\"name\":\"$ENGAGEMENT_NAME\",\"product\":$PRODUCT_ID,\"target_start\":\"$TODAY\",\"target_end\":\"$END_DATE\",\"status\":\"In Progress\",\"engagement_type\":\"CI/CD\",\"branch_tag\":\"$GIT_BRANCH\"}" \
          | jq -r '.id')
        echo "Engagement created: $ENGAGEMENT_ID"
      fi
      [ -z "$ENGAGEMENT_ID" ] || [ "$ENGAGEMENT_ID" = "null" ] && echo "Failed to get engagement" && exit 1

      smart_import() {
        local FILE="$1" SCAN_TYPE="$2" LABEL="$3"
        if [ ! -f "$FILE" ] || [ ! -s "$FILE" ]; then
          echo "[$LABEL] missing or empty"; return
        fi
        ENCODED_TYPE=$(python3 -c "import urllib.parse,sys; print(urllib.parse.quote(sys.argv[1]))" "$SCAN_TYPE" 2>/dev/null || echo "$SCAN_TYPE" | sed 's/ /%20/g')
        ALL_TESTS=$(curl -s -H "Authorization: ${DEFECTDOJO_TOKEN}" \
          "${DEFECTDOJO_URL}/api/v2/tests/?engagement=${ENGAGEMENT_ID}&scan_type=${ENCODED_TYPE}&limit=100" \
          | jq -r '.results[].id' | sort -n)
        COUNT=$(echo "$ALL_TESTS" | grep -c . 2>/dev/null || echo 0)
        if [ "$COUNT" -gt 1 ]; then
          LATEST=$(echo "$ALL_TESTS" | tail -1)
          for ID in $ALL_TESTS; do
            [ "$ID" != "$LATEST" ] && curl -s -X DELETE -H "Authorization: ${DEFECTDOJO_TOKEN}" "${DEFECTDOJO_URL}/api/v2/tests/${ID}/" >/dev/null
          done
        fi
        TEST_ID=$(curl -s -H "Authorization: ${DEFECTDOJO_TOKEN}" \
          "${DEFECTDOJO_URL}/api/v2/tests/?engagement=${ENGAGEMENT_ID}&scan_type=${ENCODED_TYPE}" \
          | jq -r '.results[0].id // empty')
        if [ -z "$TEST_ID" ] || [ "$TEST_ID" = "null" ]; then
          HTTP_CODE=$(curl -s -o /tmp/dojo_resp.json -w "%{http_code}" -X POST \
            "${DEFECTDOJO_URL}/api/v2/import-scan/" -H "Authorization: ${DEFECTDOJO_TOKEN}" \
            -F "product_name=$PRODUCT_NAME" -F "engagement_name=$ENGAGEMENT_NAME" \
            -F "scan_type=$SCAN_TYPE" -F "file=@$FILE" -F "tags=env-${ENVIRONMENT_ID}" \
            -F "auto_create_context=true" -F "close_old_findings=false" -F "deduplication_on_engagement=true")
        else
          HTTP_CODE=$(curl -s -o /tmp/dojo_resp.json -w "%{http_code}" -X POST \
            "${DEFECTDOJO_URL}/api/v2/reimport-scan/" -H "Authorization: ${DEFECTDOJO_TOKEN}" \
            -F "test=$TEST_ID" -F "scan_type=$SCAN_TYPE" -F "file=@$FILE" \
            -F "tags=env-${ENVIRONMENT_ID}" -F "close_old_findings=true" -F "deduplication_on_engagement=true")
        fi
        if [ "$HTTP_CODE" -ge 400 ]; then
          echo "[$LABEL] HTTP $HTTP_CODE FAILED — $(cat /tmp/dojo_resp.json)"
        else
          echo "[$LABEL] HTTP $HTTP_CODE OK"
        fi
      }

      echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
      smart_import "reports/trivy/trivy-fs.json"             "Trivy Scan"                "Trivy FS"
      smart_import "reports/sast/semgrep.json"               "Semgrep JSON Report"       "Semgrep"
      smart_import "reports/sast/hadolint.json"              "Hadolint Dockerfile check" "Hadolint"
      smart_import "reports/secrets/gitleaks.json"           "Gitleaks Scan"             "Gitleaks"
      smart_import "reports/iac/results_json.json"           "Checkov Scan"              "Checkov"
      smart_import "reports/container-scan/grype-image.json" "Anchore Grype"             "Grype Image"
      smart_import "reports/dast/zap-report.xml"             "ZAP Scan"                  "OWASP ZAP"
      echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
      echo "DefectDojo import complete"
  allow_failure: true

# ══════════════════════════════════════════════════════════════════
# STAGE 12 · SECURITY-VALIDATION — Quality gate complet
#   Agrège : CI scans + SonarQube self-hosted
# ══════════════════════════════════════════════════════════════════
security-validation:
  stage: security-validation
  image: alpine:latest
  needs:
    - job: aggregate-report
      artifacts: true
    - job: import-defectdojo
    - job: sonarqube-setup
      artifacts: true
  before_script:
    - apk add --no-cache jq curl
  script:
    # ── 1. Lecture du summary CI ──────────────────────────────────
    - |
      [ ! -f final-report/summary.json ] && echo "summary.json not found" && exit 1

      SCA_CRITICAL=$(jq '.sca.critical'             final-report/summary.json)
      SCA_HIGH=$(jq '.sca.high'                     final-report/summary.json)
      SCA_MEDIUM=$(jq '.sca.medium'                 final-report/summary.json)
      SCA_LOW=$(jq '.sca.low'                       final-report/summary.json)
      CONTAINER_CRITICAL=$(jq '.container.critical' final-report/summary.json)
      CONTAINER_HIGH=$(jq '.container.high'         final-report/summary.json)
      SECRETS=$(jq '.secrets'                       final-report/summary.json)
      SEMGREP_HIGH=$(jq '.sast.semgrep_high'        final-report/summary.json)
      SEMGREP_MEDIUM=$(jq '.sast.semgrep_medium'    final-report/summary.json)
      SEMGREP_INFO=$(jq '.sast.semgrep_info'        final-report/summary.json)
      HADOLINT=$(jq '.sast.hadolint_errors'         final-report/summary.json)
      CHECKOV_FAILED=$(jq '.iac.checkov_failed'     final-report/summary.json)
      DAST_HIGH=$(jq '.dast.high'                   final-report/summary.json)
      DAST_MEDIUM=$(jq '.dast.medium'               final-report/summary.json)
      DAST_LOW=$(jq '.dast.low'                     final-report/summary.json)

    # ── 2. Métriques SonarQube self-hosted ───────────────────────
    - |
      SONAR_BUGS=0; SONAR_VULNERABILITIES=0; SONAR_CODE_SMELLS=0
      SONAR_COVERAGE="N/A"; SONAR_DUPLICATIONS="N/A"
      SONAR_SECURITY_HOTSPOTS=0
      SONAR_QUALITY_GATE="N/A"; SONAR_QUALITY_GATE_LABEL="N/A"
      SONAR_RELIABILITY_RATING="N/A"; SONAR_SECURITY_RATING="N/A"
      SONAR_MAINTAINABILITY_RATING="N/A"; SONAR_NCLOC="N/A"
      SONAR_BLOCKERS=0; SONAR_CRITICALS=0; SONAR_MAJORS=0; SONAR_MINORS=0
      SONAR_AVAILABLE=false

      if [ -n "$SONAR_HOST_URL" ] && [ -n "$SONAR_TOKEN" ] && [ -n "$PROJECT_KEY" ]; then
        echo "Fetching SonarQube metrics — project=${PROJECT_KEY} branch=${GIT_BRANCH}"

        # Quality Gate — on interroge sur la branche
        QG_RESP=$(curl -s -u "${SONAR_TOKEN}:" \
          "${SONAR_HOST_URL}/api/qualitygates/project_status?projectKey=${PROJECT_KEY}&branch=${GIT_BRANCH}" \
          2>/dev/null || echo '{}')
        SONAR_QUALITY_GATE=$(echo "$QG_RESP" | jq -r '.projectStatus.status // "N/A"')

        case "$SONAR_QUALITY_GATE" in
          OK)    SONAR_QUALITY_GATE_LABEL="PASSED" ;;
          ERROR) SONAR_QUALITY_GATE_LABEL="FAILED" ;;
          WARN)  SONAR_QUALITY_GATE_LABEL="WARNING" ;;
          NONE)  SONAR_QUALITY_GATE_LABEL="NOT SET" ;;
          *)     SONAR_QUALITY_GATE_LABEL="$SONAR_QUALITY_GATE" ;;
        esac

        # Métriques détaillées — sur la branche
        # Appel 1 : métriques classiques (compatibles toutes versions SonarQube)
        METRICS_CLASSIC="bugs,vulnerabilities,code_smells,coverage,duplicated_lines_density,security_hotspots,reliability_rating,security_rating,sqale_rating,blocker_violations,critical_violations,major_violations,minor_violations,ncloc"

        METRICS_RESP=$(curl -s -u "${SONAR_TOKEN}:" \
          "${SONAR_HOST_URL}/api/measures/component?component=${PROJECT_KEY}&branch=${GIT_BRANCH}&metricKeys=${METRICS_CLASSIC}" \
          2>/dev/null || echo '{}')

        MEASURE_COUNT=$(echo "$METRICS_RESP" | jq '.component.measures | length' 2>/dev/null || echo 0)
        echo "Measures reçues (avec branch): $MEASURE_COUNT"

        if [ "$MEASURE_COUNT" = "0" ] || [ "$MEASURE_COUNT" = "null" ] || echo "$METRICS_RESP" | jq -e '.errors' >/dev/null 2>&1; then
          echo "Retry sans branch..."
          METRICS_RESP=$(curl -s -u "${SONAR_TOKEN}:" \
            "${SONAR_HOST_URL}/api/measures/component?component=${PROJECT_KEY}&metricKeys=${METRICS_CLASSIC}" \
            2>/dev/null || echo '{}')
          MEASURE_COUNT=$(echo "$METRICS_RESP" | jq '.component.measures | length' 2>/dev/null || echo 0)
          echo "Measures reçues (sans branch): $MEASURE_COUNT"
        fi

        get_metric() {
          echo "$METRICS_RESP" | jq -r \
            --arg key "$1" \
            '.component.measures[] | select(.metric==$key) | .value // "N/A"' \
            2>/dev/null || echo "N/A"
        }

        # Appel 2 : Software Quality (SonarQube 10.4+) — optionnel, échec silencieux
        SONAR_SQ_SECURITY_ISSUES="N/A"; SONAR_SQ_RELIABILITY_ISSUES="N/A"; SONAR_SQ_MAINTAINABILITY_ISSUES="N/A"
        SONAR_SQ_SECURITY_RATING="N/A"; SONAR_SQ_RELIABILITY_RATING="N/A"; SONAR_SQ_MAINTAINABILITY_RATING="N/A"
        SONAR_SQ_HIGH="N/A"; SONAR_SQ_MEDIUM="N/A"; SONAR_SQ_LOW="N/A"

        METRICS_SQ="software_quality_security_issues,software_quality_reliability_issues,software_quality_maintainability_issues,software_quality_security_rating,software_quality_reliability_rating,software_quality_maintainability_rating"

        SQ_RESP=$(curl -s -u "${SONAR_TOKEN}:" \
          "${SONAR_HOST_URL}/api/measures/component?component=${PROJECT_KEY}&branch=${GIT_BRANCH}&metricKeys=${METRICS_SQ}" \
          2>/dev/null || echo '{}')

        if ! echo "$SQ_RESP" | jq -e '.errors' >/dev/null 2>&1; then
          get_sq() {
            echo "$SQ_RESP" | jq -r --arg key "$1" \
              '.component.measures[] | select(.metric==$key) | .value // "N/A"' 2>/dev/null || echo "N/A"
          }
          SONAR_SQ_SECURITY_ISSUES=$(get_sq "software_quality_security_issues")
          SONAR_SQ_RELIABILITY_ISSUES=$(get_sq "software_quality_reliability_issues")
          SONAR_SQ_MAINTAINABILITY_ISSUES=$(get_sq "software_quality_maintainability_issues")
          sq_rating_label() {
            case "$1" in
              1|1.0) echo "A" ;; 2|2.0) echo "B" ;; 3|3.0) echo "C" ;;
              4|4.0) echo "D" ;; 5|5.0) echo "E" ;; *) echo "N/A" ;;
            esac
          }
          SONAR_SQ_SECURITY_RATING=$(sq_rating_label "$(get_sq 'software_quality_security_rating')")
          SONAR_SQ_RELIABILITY_RATING=$(sq_rating_label "$(get_sq 'software_quality_reliability_rating')")
          SONAR_SQ_MAINTAINABILITY_RATING=$(sq_rating_label "$(get_sq 'software_quality_maintainability_rating')")

          METRICS_SEV="software_quality_high_severity_issues,software_quality_medium_severity_issues,software_quality_low_severity_issues"
          SEV_RESP=$(curl -s -u "${SONAR_TOKEN}:" \
            "${SONAR_HOST_URL}/api/measures/component?component=${PROJECT_KEY}&branch=${GIT_BRANCH}&metricKeys=${METRICS_SEV}" \
            2>/dev/null || echo '{}')
          if ! echo "$SEV_RESP" | jq -e '.errors' >/dev/null 2>&1; then
            SONAR_SQ_HIGH=$(echo "$SEV_RESP" | jq -r --arg k "software_quality_high_severity_issues" '.component.measures[] | select(.metric==$k) | .value // "N/A"' 2>/dev/null || echo "N/A")
            SONAR_SQ_MEDIUM=$(echo "$SEV_RESP" | jq -r --arg k "software_quality_medium_severity_issues" '.component.measures[] | select(.metric==$k) | .value // "N/A"' 2>/dev/null || echo "N/A")
            SONAR_SQ_LOW=$(echo "$SEV_RESP" | jq -r --arg k "software_quality_low_severity_issues" '.component.measures[] | select(.metric==$k) | .value // "N/A"' 2>/dev/null || echo "N/A")
          fi
          echo "Software Quality chargé"
        else
          echo "Software Quality non disponible (SonarQube < 10.4)"
        fi
        SONAR_BUGS=$(get_metric "bugs")
        SONAR_VULNERABILITIES=$(get_metric "vulnerabilities")
        SONAR_CODE_SMELLS=$(get_metric "code_smells")
        SONAR_COVERAGE=$(get_metric "coverage")
        SONAR_DUPLICATIONS=$(get_metric "duplicated_lines_density")
        SONAR_SECURITY_HOTSPOTS=$(get_metric "security_hotspots")
        SONAR_NCLOC=$(get_metric "ncloc")
        SONAR_BLOCKERS=$(get_metric "blocker_violations")
        SONAR_CRITICALS=$(get_metric "critical_violations")
        SONAR_MAJORS=$(get_metric "major_violations")
        SONAR_MINORS=$(get_metric "minor_violations")

        # Software Quality metrics (SonarQube 10+)
        SONAR_SQ_SECURITY=$(get_metric "software_quality_security_issues")
        SONAR_SQ_RELIABILITY=$(get_metric "software_quality_reliability_issues")
        SONAR_SQ_MAINTAINABILITY=$(get_metric "software_quality_maintainability_issues")
        SONAR_SQ_SECURITY_HIGH=$(get_metric "software_quality_high_severity_issues")
        SONAR_SQ_SECURITY_MEDIUM=$(get_metric "software_quality_medium_severity_issues")
        SONAR_SQ_SECURITY_LOW=$(get_metric "software_quality_low_severity_issues")

        rating_label() {
          case "$1" in
            1|1.0) echo "A" ;; 2|2.0) echo "B" ;; 3|3.0) echo "C" ;;
            4|4.0) echo "D" ;; 5|5.0) echo "E" ;; *) echo "N/A" ;;
          esac
        }
        SONAR_RELIABILITY_RATING=$(rating_label "$(get_metric 'reliability_rating')")
        SONAR_SECURITY_RATING=$(rating_label "$(get_metric 'security_rating')")
        SONAR_MAINTAINABILITY_RATING=$(rating_label "$(get_metric 'sqale_rating')")

        # Software Quality ratings (SonarQube 10+)
        SONAR_SQ_SECURITY_RATING=$(rating_label "$(get_metric 'software_quality_security_rating')")
        SONAR_SQ_RELIABILITY_RATING=$(rating_label "$(get_metric 'software_quality_reliability_rating')")
        SONAR_SQ_MAINTAINABILITY_RATING=$(rating_label "$(get_metric 'software_quality_maintainability_rating')")

        [ "$SONAR_COVERAGE" != "N/A" ]    && SONAR_COVERAGE="${SONAR_COVERAGE}%"
        [ "$SONAR_DUPLICATIONS" != "N/A" ] && SONAR_DUPLICATIONS="${SONAR_DUPLICATIONS}%"

        SONAR_AVAILABLE=true
        echo "SonarQube metrics OK — Quality Gate: ${SONAR_QUALITY_GATE_LABEL}"
      else
        echo "SonarQube non configure — metriques ignorees"
      fi

    # ── 3. Rapport complet ────────────────────────────────────────
    - |
      echo ""
      echo "╔══════════════════════════════════════════════════════════════╗"
      echo "║         ENVIROTEST — SECURITY VALIDATION REPORT             ║"
      echo "╠══════════════════════════════════════════════════════════════╣"
      printf "║  %-20s : %-37s ║\n" "Environment"  "$ENVIRONMENT_ID"
      printf "║  %-20s : %-37s ║\n" "Branch"       "$GIT_BRANCH"
      printf "║  %-20s : %-37s ║\n" "Pipeline"     "$CI_PIPELINE_ID"
      printf "║  %-20s : %-37s ║\n" "Date"         "$(date -u '+%Y-%m-%d %H:%M UTC')"
      echo "╚══════════════════════════════════════════════════════════════╝"

      echo ""
      echo "┌──────────────────────────────────────────────────────────────┐"
      echo "│  SCA — Dependances & packages  (Trivy FS)                   │"
      echo "├──────────────────────────────────────────────────────────────┤"
      printf "│   %-30s %10s                │\n" "Critical"  "$SCA_CRITICAL"
      printf "│   %-30s %10s                │\n" "High"      "$SCA_HIGH"
      printf "│   %-30s %10s                │\n" "Medium"    "$SCA_MEDIUM"
      printf "│   %-30s %10s                │\n" "Low"       "$SCA_LOW"
      echo "└──────────────────────────────────────────────────────────────┘"

      echo "┌──────────────────────────────────────────────────────────────┐"
      echo "│  Container — Image Docker  (Anchore Grype)                  │"
      echo "├──────────────────────────────────────────────────────────────┤"
      printf "│   %-30s %10s                │\n" "Critical"  "$CONTAINER_CRITICAL"
      printf "│   %-30s %10s                │\n" "High"      "$CONTAINER_HIGH"
      echo "└──────────────────────────────────────────────────────────────┘"

      echo "┌──────────────────────────────────────────────────────────────┐"
      echo "│  Secrets — Credentials exposes  (Gitleaks)                  │"
      echo "├──────────────────────────────────────────────────────────────┤"
      printf "│   %-30s %10s                │\n" "Secrets detectes" "$SECRETS"
      echo "└──────────────────────────────────────────────────────────────┘"

      echo "┌──────────────────────────────────────────────────────────────┐"
      echo "│  SAST — Code source  (Semgrep + Hadolint)                   │"
      echo "├──────────────────────────────────────────────────────────────┤"
      printf "│   %-30s %10s                │\n" "Semgrep High (ERROR)"    "$SEMGREP_HIGH"
      printf "│   %-30s %10s                │\n" "Semgrep Medium (WARNING)" "$SEMGREP_MEDIUM"
      printf "│   %-30s %10s                │\n" "Semgrep Info"            "$SEMGREP_INFO"
      printf "│   %-30s %10s                │\n" "Hadolint errors"         "$HADOLINT"
      echo "└──────────────────────────────────────────────────────────────┘"

      echo "┌──────────────────────────────────────────────────────────────┐"
      echo "│  IaC — Infrastructure as Code  (Checkov)                    │"
      echo "├──────────────────────────────────────────────────────────────┤"
      printf "│   %-30s %10s                │\n" "Checks echoues" "$CHECKOV_FAILED"
      echo "└──────────────────────────────────────────────────────────────┘"

      echo "┌──────────────────────────────────────────────────────────────┐"
      echo "│  DAST — Application live  (OWASP ZAP)                       │"
      echo "├──────────────────────────────────────────────────────────────┤"
      printf "│   %-30s %10s                │\n" "High"    "$DAST_HIGH"
      printf "│   %-30s %10s                │\n" "Medium"  "$DAST_MEDIUM"
      printf "│   %-30s %10s                │\n" "Low"     "$DAST_LOW"
      echo "└──────────────────────────────────────────────────────────────┘"

      echo "┌──────────────────────────────────────────────────────────────┐"
      echo "│  SonarQube — Qualite & securite du code                     │"
      echo "├──────────────────────────────────────────────────────────────┤"
      if [ "$SONAR_AVAILABLE" = "true" ]; then
        printf "│   %-30s %10s                │\n" "Quality Gate"           "${SONAR_QUALITY_GATE_LABEL}"
        echo "│   ─────────────────────────────────────────────────────── │"
        printf "│   %-30s %10s                │\n" "Bugs"                   "$SONAR_BUGS"
        printf "│   %-30s %10s                │\n" "Vulnerabilities"        "$SONAR_VULNERABILITIES"
        printf "│   %-30s %10s                │\n" "Security Hotspots"      "$SONAR_SECURITY_HOTSPOTS"
        printf "│   %-30s %10s                │\n" "Code Smells"            "$SONAR_CODE_SMELLS"
        echo "│   ─────────────────────────────────────────────────────── │"
        printf "│   %-30s %10s                │\n" "Blocker violations"     "$SONAR_BLOCKERS"
        printf "│   %-30s %10s                │\n" "Critical violations"    "$SONAR_CRITICALS"
        printf "│   %-30s %10s                │\n" "Major violations"       "$SONAR_MAJORS"
        printf "│   %-30s %10s                │\n" "Minor violations"       "$SONAR_MINORS"
        echo "│   ─────────────────────────────────────────────────────── │"
        printf "│   %-30s %10s                │\n" "Coverage"               "$SONAR_COVERAGE"
        printf "│   %-30s %10s                │\n" "Duplications"           "$SONAR_DUPLICATIONS"
        printf "│   %-30s %10s                │\n" "Lines of code"          "$SONAR_NCLOC"
        echo "│   ─────────────────────────────────────────────────────── │"
        printf "│   %-30s %10s                │\n" "Reliability rating"     "$SONAR_RELIABILITY_RATING"
        printf "│   %-30s %10s                │\n" "Security rating"        "$SONAR_SECURITY_RATING"
        printf "│   %-30s %10s                │\n" "Maintainability rating" "$SONAR_MAINTAINABILITY_RATING"
        echo "│   ─────────────────────────────────────────────────────── │"
        echo "│   SOFTWARE QUALITY (nouveau modele SonarQube 10+)        │"
        echo "│   ─────────────────────────────────────────────────────── │"
        printf "│   %-30s %10s                │\n" "Security issues"        "$SONAR_SQ_SECURITY_ISSUES"
        printf "│   %-30s %10s                │\n" "  dont High"            "$SONAR_SQ_HIGH"
        printf "│   %-30s %10s                │\n" "  dont Medium"          "$SONAR_SQ_MEDIUM"
        printf "│   %-30s %10s                │\n" "  dont Low"             "$SONAR_SQ_LOW"
        printf "│   %-30s %10s                │\n" "Reliability issues"     "$SONAR_SQ_RELIABILITY_ISSUES"
        printf "│   %-30s %10s                │\n" "Maintainability issues" "$SONAR_SQ_MAINTAINABILITY_ISSUES"
        echo "│   ─────────────────────────────────────────────────────── │"
        printf "│   %-30s %10s                │\n" "SQ Security rating"     "$SONAR_SQ_SECURITY_RATING"
        printf "│   %-30s %10s                │\n" "SQ Reliability rating"  "$SONAR_SQ_RELIABILITY_RATING"
        printf "│   %-30s %10s                │\n" "SQ Maintain. rating"    "$SONAR_SQ_MAINTAINABILITY_RATING"
        printf "│   %-30s                           │\n" "Dashboard: ${SONAR_HOST_URL}/dashboard?id=${PROJECT_KEY}&branch=${GIT_BRANCH}"
      else
        printf "│   %-55s │\n" "Non disponible (SONAR_HOST_URL ou SONAR_TOKEN manquant)"
      fi
      echo "└──────────────────────────────────────────────────────────────┘"

    # ── 4. Evaluation du quality gate ────────────────────────────
    - |
      GATE_PASSED=true
      WARNINGS=""
      BLOCKING_REASONS=""

      fail() {
        echo "BLOCKING : $1"
        GATE_PASSED=false
        BLOCKING_REASONS="${BLOCKING_REASONS}  - $1\n"
      }
      pass() { echo "OK       : $1"; }
      warn() {
        echo "WARNING  : $1"
        WARNINGS="${WARNINGS}  - $1\n"
      }

      echo ""
      echo "┌──────────────────────────────────────────────────────────────┐"
      echo "│  GATE CHECKS                                                 │"
      echo "├──────────────────────────────────────────────────────────────┤"

      [ "$SECRETS" -gt 0 ] \
        && fail "Secrets exposes detectes ($SECRETS)" \
        || pass "Aucun secret expose"

      [ "$SCA_CRITICAL" -gt "${SCA_CRITICAL_THRESHOLD}" ] \
        && fail "SCA Critical: $SCA_CRITICAL > seuil ${SCA_CRITICAL_THRESHOLD}" \
        || pass "SCA Critical ($SCA_CRITICAL <= ${SCA_CRITICAL_THRESHOLD})"

      [ "$SCA_HIGH" -gt "${SCA_HIGH_THRESHOLD}" ] \
        && fail "SCA High: $SCA_HIGH > seuil ${SCA_HIGH_THRESHOLD}" \
        || pass "SCA High ($SCA_HIGH <= ${SCA_HIGH_THRESHOLD})"

      [ "$SCA_MEDIUM" -gt 50 ] \
        && warn "SCA Medium eleve: $SCA_MEDIUM (> 50)"

      [ "$CONTAINER_CRITICAL" -gt "${CONTAINER_CRITICAL_THRESHOLD}" ] \
        && fail "Container Critical: $CONTAINER_CRITICAL > seuil ${CONTAINER_CRITICAL_THRESHOLD}" \
        || pass "Container Critical ($CONTAINER_CRITICAL <= ${CONTAINER_CRITICAL_THRESHOLD})"

      [ "$CONTAINER_HIGH" -gt "${CONTAINER_HIGH_THRESHOLD}" ] \
        && fail "Container High: $CONTAINER_HIGH > seuil ${CONTAINER_HIGH_THRESHOLD}" \
        || pass "Container High ($CONTAINER_HIGH <= ${CONTAINER_HIGH_THRESHOLD})"

      [ "$SEMGREP_HIGH" -gt "${SEMGREP_HIGH_THRESHOLD}" ] \
        && fail "Semgrep High: $SEMGREP_HIGH > seuil ${SEMGREP_HIGH_THRESHOLD}" \
        || pass "Semgrep High ($SEMGREP_HIGH <= ${SEMGREP_HIGH_THRESHOLD})"

      [ "$SEMGREP_MEDIUM" -gt "${SEMGREP_MEDIUM_THRESHOLD}" ] \
        && warn "Semgrep Medium: $SEMGREP_MEDIUM (> ${SEMGREP_MEDIUM_THRESHOLD})"

      [ "$CHECKOV_FAILED" -gt "${IAC_FAILED_THRESHOLD}" ] \
        && fail "Checkov: $CHECKOV_FAILED checks echoues > seuil ${IAC_FAILED_THRESHOLD}" \
        || pass "IaC Checkov ($CHECKOV_FAILED <= ${IAC_FAILED_THRESHOLD})"

      [ "$DAST_HIGH" -gt 5 ] \
        && fail "DAST High: $DAST_HIGH > 5" \
        || pass "DAST High ($DAST_HIGH <= 5)"

      [ "$DAST_MEDIUM" -gt 10 ] \
        && warn "DAST Medium: $DAST_MEDIUM (> 10)"

      if [ "$SONAR_AVAILABLE" = "true" ]; then
        if [ "$SONAR_QUALITY_GATE" = "ERROR" ]; then
          fail "SonarQube Quality Gate FAILED (bugs=$SONAR_BUGS, vulns=$SONAR_VULNERABILITIES, security=$SONAR_SECURITY_RATING)"
        elif [ "$SONAR_QUALITY_GATE" = "WARN" ]; then
          warn "SonarQube Quality Gate WARNING"
        elif [ "$SONAR_QUALITY_GATE" = "OK" ]; then
          pass "SonarQube Quality Gate PASSED (reliability=$SONAR_RELIABILITY_RATING, security=$SONAR_SECURITY_RATING)"
        else
          warn "SonarQube Quality Gate indisponible ($SONAR_QUALITY_GATE)"
        fi

        if [ "$SONAR_SECURITY_HOTSPOTS" != "N/A" ] && [ "$SONAR_SECURITY_HOTSPOTS" -gt 0 ] 2>/dev/null; then
          warn "SonarQube: $SONAR_SECURITY_HOTSPOTS security hotspot(s) a reviser"
        fi

        COVERAGE_NUM=$(echo "$SONAR_COVERAGE" | tr -d '%')
        if [ "$COVERAGE_NUM" != "N/A" ] && [ -n "$COVERAGE_NUM" ]; then
          COV_INT=$(echo "$COVERAGE_NUM" | cut -d'.' -f1)
          [ "$COV_INT" -lt 50 ] 2>/dev/null && warn "SonarQube: couverture de tests faible (${SONAR_COVERAGE})"
        fi
      else
        warn "SonarQube non evalue (non configure)"
      fi

      echo "└──────────────────────────────────────────────────────────────┘"

    # ── 5. Verdict final ─────────────────────────────────────────
    - |
      echo ""
      echo "╔══════════════════════════════════════════════════════════════╗"
      echo "║                    VERDICT FINAL                            ║"
      echo "╠══════════════════════════════════════════════════════════════╣"

      if [ "$GATE_PASSED" = "true" ]; then
        if [ -n "$WARNINGS" ]; then
          RECOMMENDATION="DEPLOY_WITH_WARNINGS"
          echo "║  DEPLOIEMENT AVEC RESERVES                                  ║"
          echo "╠══════════════════════════════════════════════════════════════╣"
          printf "%b" "$WARNINGS" | while IFS= read -r line; do
            printf "║  %-60s ║\n" "$line"
          done
        else
          RECOMMENDATION="RECOMMANDE"
          echo "║  DEPLOIEMENT RECOMMANDE — Tous les checks sont passes        ║"
        fi
      else
        RECOMMENDATION="NON_RECOMMANDE"
        echo "║  DEPLOIEMENT BLOQUE — Checks critiques en echec              ║"
        echo "╠══════════════════════════════════════════════════════════════╣"
        printf "%b" "$BLOCKING_REASONS" | while IFS= read -r line; do
          printf "║  %-60s ║\n" "$line"
        done
      fi

      echo "╠══════════════════════════════════════════════════════════════╣"
      printf "║  %-20s : %-37s ║\n" "Recommandation" "$RECOMMENDATION"
      printf "║  %-20s : %-37s ║\n" "Environment"    "$ENVIRONMENT_ID"
      printf "║  %-20s : %-37s ║\n" "Branch"         "$GIT_BRANCH"
      echo "╚══════════════════════════════════════════════════════════════╝"

      echo "$RECOMMENDATION" > final-report/recommendation.txt

    # ── 6. Notification backend ───────────────────────────────────
    - |
      if [ -n "$BACKEND_URL" ] && [ -n "$PIPELINE_SECRET" ]; then
        RECOMMENDATION=$(cat final-report/recommendation.txt)
        curl -s -X POST "${BACKEND_URL}/projet/api/security-gate" \
          -H "Content-Type: application/json" \
          -H "X-Pipeline-Secret: ${PIPELINE_SECRET}" \
          -d "{
            \"environment_id\":        \"$ENVIRONMENT_ID\",
            \"recommendation\":        \"$RECOMMENDATION\",
            \"git_branch\":            \"$GIT_BRANCH\",
            \"critical\":              $SCA_CRITICAL,
            \"high\":                  $SCA_HIGH,
            \"secrets\":               $SECRETS,
            \"container_critical\":    $CONTAINER_CRITICAL,
            \"dast_high\":             $DAST_HIGH,
            \"sonar_quality_gate\":    \"$SONAR_QUALITY_GATE\",
            \"sonar_bugs\":            \"$SONAR_BUGS\",
            \"sonar_vulnerabilities\": \"$SONAR_VULNERABILITIES\",
            \"sonar_hotspots\":        \"$SONAR_SECURITY_HOTSPOTS\",
            \"sonar_coverage\":        \"$SONAR_COVERAGE\",
            \"sonar_security_rating\": \"$SONAR_SECURITY_RATING\",
            \"sonar_blockers\":        \"${SONAR_BLOCKERS:-0}\",
            \"sonar_criticals\":       \"${SONAR_CRITICALS:-0}\",
            \"sonar_ncloc\":           \"${SONAR_NCLOC:-0}\"
          }" || echo "Backend notification failed (non-blocking)"
      elif [ -n "$BACKEND_URL" ]; then
        echo "BACKEND_URL défini mais PIPELINE_SECRET manquant — ingestion security-gate ignorée"
      fi
    # ── Enrichir summary.json avec métriques Sonar (snapshot / fallback backend) ──
    - |
      if [ -f final-report/summary.json ] && [ "$SONAR_AVAILABLE" = "true" ]; then
        tmp=$(mktemp)
        jq --arg qg "${SONAR_QUALITY_GATE:-N/A}" \
           --argjson blockers "${SONAR_BLOCKERS:-0}" \
           --argjson criticals "${SONAR_CRITICALS:-0}" \
           --argjson majors "${SONAR_MAJORS:-0}" \
           --argjson minors "${SONAR_MINORS:-0}" \
           --argjson bugs "${SONAR_BUGS:-0}" \
           --argjson vulns "${SONAR_VULNERABILITIES:-0}" \
           --argjson hotspots "${SONAR_SECURITY_HOTSPOTS:-0}" \
           --argjson ncloc "${SONAR_NCLOC:-0}" \
           '. + {sonar: ((.sonar // {}) + {
             quality_gate: $qg,
             blocker_violations: $blockers,
             critical_violations: $criticals,
             major_violations: $majors,
             minor_violations: $minors,
             bugs: $bugs,
             vulnerabilities: $vulns,
             hotspots: $hotspots,
             ncloc: $ncloc
           })}' final-report/summary.json > "$tmp" \
          && mv "$tmp" final-report/summary.json
        echo "summary.json enrichi — sonar (QG=$SONAR_QUALITY_GATE, blockers=$SONAR_BLOCKERS, ncloc=$SONAR_NCLOC)"
      fi
    # ── 7. Capture automatique snapshot Quality Gate ─────────────
    - |
      if [ -n "$BACKEND_URL" ] && [ -n "$ENVIRONMENT_ID" ] && [ -n "$PIPELINE_SECRET" ]; then
        echo "Capture snapshot pour env ${ENVIRONMENT_ID}..."
        SNAP_CODE=$(curl -s -o /tmp/snap_resp.json -w "%{http_code}" -X POST \
          "${BACKEND_URL}/projet/api/quality-gate/internal/snapshot?environmentId=${ENVIRONMENT_ID}" \
          -H "X-Pipeline-Secret: ${PIPELINE_SECRET}")
        if [ "$SNAP_CODE" -ge 400 ]; then
          echo "Snapshot échoué — HTTP $SNAP_CODE : $(cat /tmp/snap_resp.json)"
        else
          VERDICT=$(cat /tmp/snap_resp.json | grep -o '"verdict":"[^"]*"' | cut -d'"' -f4)
          echo "Snapshot enregistré — verdict: $VERDICT"
        fi
      fi
  artifacts:
    paths:
      - final-report/recommendation.txt
      - final-report/summary.json
    expire_in: 7 days

# ══════════════════════════════════════════════════════════════════
# STAGE 13 · SCHEDULE-DELETE — Suppression TTL image Docker
# ══════════════════════════════════════════════════════════════════
delete-docker-image:
  stage: schedule-delete
  image: alpine:latest
  tags:
    - k8s-deployer
  when: always
  needs:
    - job: deploy-to-kubernetes
  before_script:
    - apk add --no-cache openssh-client
    - eval $(ssh-agent -s)
    - echo "$SSH_PRIVATE_KEY" | tr -d '\r' | ssh-add -
    - ssh-keyscan -H "$K8S_MASTER_IP" >> ~/.ssh/known_hosts
  script:
    - |
      ssh ${K8S_SSH_USER}@${K8S_MASTER_IP} "
        cat > ~/delete-image-${ENVIRONMENT_ID}.sh << 'EOFSCRIPT'
        #!/bin/bash
        TOKEN=\$(curl -s -X POST -H 'Content-Type: application/json' \
          -d \"{\\\"username\\\":\\\"${DOCKER_USERNAME}\\\",\\\"password\\\":\\\"${DOCKER_ACCESS_TOKEN}\\\"}\" \
          https://hub.docker.com/v2/users/login/ | jq -r .token)
        curl -s -X DELETE -H \"Authorization: JWT \${TOKEN}\" \
          \"https://hub.docker.com/v2/repositories/${DOCKER_USERNAME}/envirotest-app/tags/${ENVIRONMENT_ID}/\"
        rm -- \"\$0\"
        EOFSCRIPT
        chmod +x ~/delete-image-${ENVIRONMENT_ID}.sh
        echo \"~/delete-image-${ENVIRONMENT_ID}.sh\" | at now + ${TTL_HOURS} hours
      "
      echo "Image deletion scheduled in ${TTL_HOURS}h"
  allow_failure: true