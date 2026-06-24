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
  SONAR_TOKEN:        ""
  SONAR_ADMIN_TOKEN:  ""
  DOCKER_USERNAME:    ""
  DOCKER_ACCESS_TOKEN: ""
  ENVIRONMENT_URL:    ""
  BACKEND_URL:        ""
  API_TOKEN:          ""
  K8S_API_URL:        ""
  K8S_TOKEN:          ""
  K8S_NAMESPACE:      "envirotest-${ENVIRONMENT_ID}"
  K8S_MASTER_IP:      ""
  K8S_SSH_USER:       "ubuntu"
  SSH_PRIVATE_KEY:    ""
  TTL_HOURS:          "4"
  # Quality gate thresholds (overridable per-pipeline)
  SCA_CRITICAL_THRESHOLD:       "5"
  SCA_HIGH_THRESHOLD:           "20"
  CONTAINER_CRITICAL_THRESHOLD: "0"
  CONTAINER_HIGH_THRESHOLD:     "10"
  SEMGREP_HIGH_THRESHOLD:       "10"
  SEMGREP_MEDIUM_THRESHOLD:     "50"
  IAC_FAILED_THRESHOLD:         "10"
  # Set to "true" to use Kaniko instead of docker-socket mount
  USE_KANIKO: "false"

# ══════════════════════════════════════════════════════════════════
# STAGE 1 · SETUP  —  Clone + language detection
# ══════════════════════════════════════════════════════════════════
hello-world:
  stage: setup
  image: alpine:latest
  retry: 2
  script:
    - echo "🚀 EnviroTest Optimized Security Pipeline"
    - echo "Environment  = $ENVIRONMENT_ID"
    - echo "Repository   = $GIT_REPO_URL"
    - echo "Branch       = $GIT_BRANCH"

clone-repository:
  stage: setup
  image: alpine:latest
  retry: 2
  needs: ["hello-world"]
  before_script:
    - apk add --no-cache git bash
  script:
    - echo "📦 Cloning repository..."
    - test -n "$GIT_REPO_URL" || (echo "❌ GIT_REPO_URL is required" && exit 1)
    - |
      if [ -n "$GITHUB_TOKEN" ]; then
        AUTH_URL=$(echo "$GIT_REPO_URL" | sed "s|https://|https://oauth2:${GITHUB_TOKEN}@|")
      else
        AUTH_URL="$GIT_REPO_URL"
      fi
      git clone --depth 1 --branch "$GIT_BRANCH" "$AUTH_URL" user-repo
    - chmod -R 777 user-repo
    - echo "🔍 Detecting project languages and infrastructure..."
    - touch build.env

    # ── Languages ──
    - if [ -f "user-repo/package.json" ];                                                   then echo "LANG_NODE=true"   >> build.env; else echo "LANG_NODE=false"   >> build.env; fi
    - if [ -f "user-repo/requirements.txt" ] || [ -f "user-repo/Pipfile" ] || [ -f "user-repo/setup.py" ]; then echo "LANG_PYTHON=true" >> build.env; else echo "LANG_PYTHON=false" >> build.env; fi
    - if [ -f "user-repo/pom.xml" ] || [ -f "user-repo/build.gradle" ];                    then echo "LANG_JAVA=true"   >> build.env; else echo "LANG_JAVA=false"   >> build.env; fi
    - if [ -f "user-repo/go.mod" ];                                                         then echo "LANG_GO=true"     >> build.env; else echo "LANG_GO=false"     >> build.env; fi
    - if [ -f "user-repo/Gemfile" ];                                                        then echo "LANG_RUBY=true"   >> build.env; else echo "LANG_RUBY=false"   >> build.env; fi
    - if [ -f "user-repo/composer.json" ];                                                  then echo "LANG_PHP=true"    >> build.env; else echo "LANG_PHP=false"    >> build.env; fi
    - if [ -f "user-repo/Cargo.toml" ];                                                     then echo "LANG_RUST=true"   >> build.env; else echo "LANG_RUST=false"   >> build.env; fi
    - if find user-repo -maxdepth 2 -name "*.csproj" -o -name "*.fsproj" | grep -q .;      then echo "LANG_DOTNET=true" >> build.env; else echo "LANG_DOTNET=false" >> build.env; fi
    - if find user-repo -name "*.c" -o -name "*.cpp" -o -name "*.h" | grep -q .;           then echo "LANG_CPP=true"    >> build.env; else echo "LANG_CPP=false"    >> build.env; fi

    # ── Framework ──
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

    # ── Infrastructure markers ──
    - if [ -f "user-repo/Dockerfile" ];                                   then echo "HAS_DOCKERFILE=true"  >> build.env; else echo "HAS_DOCKERFILE=false"  >> build.env; fi
    - if find user-repo -name "*.tf" | grep -q .;                         then echo "HAS_TERRAFORM=true"   >> build.env; else echo "HAS_TERRAFORM=false"   >> build.env; fi
    - if find user-repo -name "*.tf" -o -name "*.yaml" -o -name "*.yml" | grep -q .; then echo "HAS_IAC=true" >> build.env; else echo "HAS_IAC=false" >> build.env; fi

    - cat build.env
    - echo "✅ Detection complete"
  artifacts:
    paths:
      - user-repo/
      - build.env
    reports:
      dotenv: build.env
    expire_in: 1 day

# ══════════════════════════════════════════════════════════════════
# STAGE 2 · CODE-ANALYSIS  —  SonarCloud (quality + SAST)
# ══════════════════════════════════════════════════════════════════
sonarcloud-setup:
  stage: code-analysis
  image: alpine:latest
  needs: ["clone-repository"]
  before_script:
    - apk add --no-cache curl jq
  script:
    - |
      PROJECT_KEY=$(echo "${GIT_REPO_URL}" | sed -E 's|https?://||; s|\.git$||; s|/|_|g; s|[^a-zA-Z0-9_]|_|g')
      ORG="amanibennaceur-group"
      echo "📋 ProjectKey = ${PROJECT_KEY}"

      EXISTS=$(curl -s -u "${SONAR_ADMIN_TOKEN}:" \
        "https://sonarcloud.io/api/projects/search?organization=${ORG}&projects=${PROJECT_KEY}" \
        | jq -r '.components | length')

      if [ "$EXISTS" -eq 0 ]; then
        echo "📦 Creating SonarCloud project..."
        curl -s -X POST -u "${SONAR_ADMIN_TOKEN}:" \
          "https://sonarcloud.io/api/projects/create" \
          -d "project=${PROJECT_KEY}&name=${PROJECT_KEY}&organization=${ORG}"
      else
        echo "✅ Project already exists"
      fi

      curl -s -X POST -u "${SONAR_ADMIN_TOKEN}:" \
        "https://sonarcloud.io/api/qualitygates/select" \
        -d "projectKey=${PROJECT_KEY}&gateName=Sonar way"

      echo "PROJECT_KEY=${PROJECT_KEY}" >> project.env
  artifacts:
    reports:
      dotenv: project.env
    expire_in: 1 hour
  allow_failure: true

sonarcloud-scan:
  stage: code-analysis
  image: sonarsource/sonar-scanner-cli:latest
  needs:
    - job: clone-repository
    - job: sonarcloud-setup
  script:
    - echo "🔍 SonarCloud Scan — ProjectKey = ${PROJECT_KEY}"
    - cd user-repo
    - |
      sonar-scanner \
        -Dsonar.projectKey="${PROJECT_KEY}" \
        -Dsonar.organization="amanibennaceur-group" \
        -Dsonar.sources=. \
        -Dsonar.host.url="https://sonarcloud.io" \
        -Dsonar.token="$SONAR_TOKEN" \
        -Dsonar.exclusions="**/node_modules/**,**/dist/**,**/target/**,**/build/**" \
        -Dsonar.scm.provider=git
  allow_failure: true

# ══════════════════════════════════════════════════════════════════
# STAGE 3 · SCA  —  Trivy FS only (replaces 8 language-specific tools)
#   ✅ Covers: npm, pip, maven, gradle, go.mod, Gemfile, composer,
#              Cargo.toml, NuGet — all in one unified scan
# ══════════════════════════════════════════════════════════════════
trivy-fs-scan:
  stage: sca
  image: alpine:latest
  needs: ["clone-repository"]
  before_script:
    - apk add --no-cache curl
    - curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin
  script:
    - echo "🔍 Trivy FS — Universal SCA (all ecosystems in one pass)"
    - mkdir -p reports/trivy
    - |
      trivy fs \
        --scanners vuln \
        --format json \
        --output reports/trivy/trivy-fs.json \
        user-repo/ || true
    - |
      # Quick summary for CI logs
      if command -v jq >/dev/null 2>&1; then
        apk add --no-cache jq 2>/dev/null || true
        CRIT=$(jq '[.Results[]?.Vulnerabilities[]? | select(.Severity=="CRITICAL")] | length' reports/trivy/trivy-fs.json 2>/dev/null || echo 0)
        HIGH=$(jq '[.Results[]?.Vulnerabilities[]? | select(.Severity=="HIGH")] | length' reports/trivy/trivy-fs.json 2>/dev/null || echo 0)
        echo "📊 Trivy FS: CRITICAL=$CRIT HIGH=$HIGH"
      fi
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
    - echo "📄 Syft — License compliance (all ecosystems)"
    - mkdir -p reports/license
    - syft dir:user-repo --output spdx-json=reports/license/sbom-spdx.json || true
    - echo "✅ SBOM + license report generated"
  artifacts:
    paths:
      - reports/license/sbom-spdx.json
    expire_in: 1 day
  allow_failure: true

# ══════════════════════════════════════════════════════════════════
# STAGE 4 · SAST  —  Semgrep (replaces Bandit/Gosec/ESLint/SpotBugs/Brakeman/PHPStan/Cppcheck)
#   ✅ Semgrep auto mode covers 30+ languages with 1000+ curated rules
#   ✅ SonarCloud (stage 2) already handles deeper AST-level analysis
# ══════════════════════════════════════════════════════════════════
semgrep-sast:
  stage: sast
  image: returntocorp/semgrep:latest
  needs: ["clone-repository"]
  script:
    - echo "🔍 Semgrep — Universal SAST (all languages, auto rule selection)"
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
      echo "📊 Semgrep: HIGH/ERROR=$HIGH MEDIUM/WARNING=$MED"
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
    - echo "🔍 Hadolint — Dockerfile security lint"
    - mkdir -p reports/sast
    - |
      if [ "$HAS_DOCKERFILE" != "true" ]; then
        echo "⏭️  Skipping — No Dockerfile"
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
# STAGE 5 · SECRETS-IAC  —  Gitleaks + Checkov (parallel)
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
    - echo "🔑 Gitleaks — Secrets detection (filesystem)"
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
      echo "🔑 Secrets found: $COUNT"
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
    - echo "🏗️ Checkov — IaC scan (Terraform + K8s + Helm + Dockerfiles + GH Actions)"
    - mkdir -p reports/iac
    - |
      if [ "$HAS_IAC" != "true" ]; then
        echo "⏭️  Skipping — No IaC files detected"
        echo '{"results":{"passed_checks":[],"failed_checks":[]}}' > reports/iac/results_json.json
        exit 0
      fi
    - |
      checkov --directory user-repo \
        --output json \
        --output-file-path reports/iac/ \
        --soft-fail || true
  artifacts:
    paths:
      - reports/iac/
    expire_in: 1 day
  allow_failure: true

# ══════════════════════════════════════════════════════════════════
# STAGE 6 · BUILD  —  Docker image (socket mount, Kaniko fallback)
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
    - echo "🏗️ Building Docker image"
    - |
      if [ "$USE_KANIKO" = "true" ]; then
        echo "ℹ️  USE_KANIKO=true — skipping socket build (Kaniko job will handle it)"
        exit 0
      fi
    - until docker info 2>/dev/null; do echo "⏳ Waiting for Docker daemon..."; sleep 3; done
    - cd user-repo
    - IMAGE_NAME="${DOCKER_USERNAME}/envirotest-app:${ENVIRONMENT_ID}"
    - docker build -f ${DOCKERFILE_PATH} -t ${IMAGE_NAME} .
    - docker save -o ../image.tar ${IMAGE_NAME}
    - cd ..
    - echo "IMAGE_NAME=${IMAGE_NAME}" > image_name.env
    - echo " Image built=${IMAGE_NAME}"
  artifacts:
    paths:
      - image.tar
      - image_name.env
    expire_in: 2 hours
  allow_failure: false

# Kaniko fallback — only runs when USE_KANIKO=true
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
    - echo "🏗️ Kaniko build (no Docker daemon required)"
    - IMAGE_NAME="${DOCKER_USERNAME}/envirotest-app:${ENVIRONMENT_ID}"
    - echo "${DOCKER_ACCESS_TOKEN}" | /kaniko/executor \
        --context=dir://user-repo \
        --dockerfile=user-repo/${DOCKERFILE_PATH} \
        --destination="${IMAGE_NAME}" \
        --no-push \
        --tarPath=/workspace/image.tar
    - echo "IMAGE_NAME=${IMAGE_NAME}" > image_name.env
    - cp /workspace/image.tar image.tar
  artifacts:
    paths:
      - image.tar
      - image_name.env
    expire_in: 2 hours
  allow_failure: false

# ══════════════════════════════════════════════════════════════════
# STAGE 7 · CONTAINER-SCAN  —  Grype (replaces Trivy Image)
# ══════════════════════════════════════════════════════════════════
grype-image-scan:
  stage: container-scan
  image: alpine:latest          # ← alpine à la place de anchore/grype:latest
  retry: 2
  needs:
    - job: build-docker-image
      artifacts: true
      optional: true
    - job: build-docker-image-kaniko
      artifacts: true
      optional: true
  before_script:                # ← installe grype dans alpine
    - apk add --no-cache curl jq
    - curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin
  script:
    - echo "🐳 Grype — Container vulnerability scan"
    - mkdir -p reports/container-scan
    - |
      if [ ! -f image.tar ]; then
        echo "⏭️  No image.tar artifact — skipping container scan"
        echo '{"matches":[]}' > reports/container-scan/grype-image.json
        exit 0
      fi
    - ls -lh image.tar   # debug : confirme que le fichier est là
    - grype docker-archive:$(pwd)/image.tar -o json > reports/container-scan/grype-image.json || true
    - |
      CRIT=$(jq '[.matches[]?.vulnerability?.severity? | select(.=="Critical")] | length' reports/container-scan/grype-image.json 2>/dev/null || echo 0)
      CRIT=${CRIT:-0}
      HIGH=$(jq '[.matches[]?.vulnerability?.severity? | select(.=="High")] | length' reports/container-scan/grype-image.json 2>/dev/null || echo 0)
      HIGH=${HIGH:-0}
      echo "📊 Grype: CRITICAL=$CRIT HIGH=$HIGH"
  artifacts:
    paths:
      - reports/container-scan/grype-image.json
    expire_in: 1 day
  allow_failure: true

# ══════════════════════════════════════════════════════════════════
# STAGE 8 · PUSH-IMAGE  —  Docker Hub push
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
        echo "⏭️  No image.tar — skipping push"
        exit 0
      fi
    - until docker info 2>/dev/null; do echo "⏳ Waiting for Docker..."; sleep 3; done
    - docker load -i image.tar
    - . image_name.env
    - echo "$DOCKER_ACCESS_TOKEN" | docker login -u "$DOCKER_USERNAME" --password-stdin
    - docker push ${IMAGE_NAME}
    - echo "✅ Pushed ${IMAGE_NAME}"
  allow_failure: true

# ══════════════════════════════════════════════════════════════════
# STAGE 9 · DEPLOY-K8S  —  Ephemeral Kubernetes environment
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
    - echo "🚀 Deploying to namespace ${K8S_NAMESPACE}"
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
      echo "✅ Deployed: ${APP_URL}"
  artifacts:
    reports:
      dotenv: app_url.env
    paths:
      - app_url.env
    expire_in: 1 day
  allow_failure: true

# ══════════════════════════════════════════════════════════════════
# STAGE 10 · DAST  —  OWASP ZAP Baseline (runs against live env)
#   Only executes when deploy-to-kubernetes succeeded and APP_URL is set.
#   Baseline mode = passive scan (no active attacks) — safe for ephemeral envs.
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
    - echo " OWASP ZAP Baseline DAST Target ${APP_URL}"
    - mkdir -p reports/dast
    - |
      if [ -z "$APP_URL" ]; then
        echo "⏭️  APP_URL not set — skipping DAST (deploy likely failed)"
        echo '{"site":[]}' > reports/dast/zap-report.json
        exit 0
      fi
    - |
      # Wait for app to be healthy before scanning
      MAX=10; N=0
      until curl -sf --max-time 5 "${APP_URL}" >/dev/null 2>&1 || [ $N -ge $MAX ]; do
        echo "⏳ Waiting for app to respond... ($N/$MAX)"; sleep 10; N=$((N+1))
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
      echo "📊 DAST: Total alerts=$ALERTS High=$HIGH_DAST"
  artifacts:
    paths:
      - reports/dast/zap-report.xml
    expire_in: 7 days
  allow_failure: true

# ══════════════════════════════════════════════════════════════════
# STAGE 11 · REPORTING  —  Aggregate + DefectDojo import
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
    - grype-image-scan        # remplacé trivy-image-scan
    - owasp-zap-dast
  before_script:
    - apk add --no-cache jq
  script:
    - echo "📊 Aggregating all scan results..."
    - mkdir -p final-report
    - source build.env 2>/dev/null || true

    # ── Artifact validation ──
    - |
      echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
      echo "📦 ARTIFACT VALIDATION"
      echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
      MISSING=0; EMPTY=0; TOTAL=0

      check_file() {
        local file="$1" name="$2"
        TOTAL=$((TOTAL + 1))
        if [ ! -f "$file" ]; then
          echo "   ❌ $name — MISSING"
          MISSING=$((MISSING + 1))
        elif [ ! -s "$file" ]; then
          echo "   ⚠️  $name — EMPTY"
          EMPTY=$((EMPTY + 1))
        else
          echo "   ✅ $name — OK ($(wc -c < "$file") bytes)"
        fi
      }

      check_file "reports/trivy/trivy-fs.json"              "Trivy FS (SCA)"
      check_file "reports/license/sbom-spdx.json"           "Syft SBOM (Licenses)"
      check_file "reports/sast/semgrep.json"                "Semgrep (SAST)"
      check_file "reports/sast/hadolint.json"               "Hadolint (Dockerfile)"
      check_file "reports/secrets/gitleaks.json"            "Gitleaks (Secrets)"
      check_file "reports/iac/results_json.json"                 "Checkov (IaC)"
      check_file "reports/container-scan/grype-image.json"  "Grype Image (Container)"
      check_file "reports/dast/zap-report.json"             "OWASP ZAP (DAST)"

      echo ""
      echo "Total: $TOTAL | ✅ OK: $((TOTAL-MISSING-EMPTY)) | ❌ Missing: $MISSING | ⚠️ Empty: $EMPTY"
      echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

    # ── Extract metrics ──
    - |
      # SCA — Trivy FS
      SCA_CRITICAL=$(jq '[.Results[]?.Vulnerabilities[]? | select(.Severity=="CRITICAL")] | length' reports/trivy/trivy-fs.json 2>/dev/null || echo 0)
      SCA_CRITICAL=${SCA_CRITICAL:-0}
      SCA_HIGH=$(jq '[.Results[]?.Vulnerabilities[]? | select(.Severity=="HIGH")] | length' reports/trivy/trivy-fs.json 2>/dev/null || echo 0)
      SCA_HIGH=${SCA_HIGH:-0}
      SCA_MEDIUM=$(jq '[.Results[]?.Vulnerabilities[]? | select(.Severity=="MEDIUM")] | length' reports/trivy/trivy-fs.json 2>/dev/null || echo 0)
      SCA_MEDIUM=${SCA_MEDIUM:-0}
      SCA_LOW=$(jq '[.Results[]?.Vulnerabilities[]? | select(.Severity=="LOW")] | length' reports/trivy/trivy-fs.json 2>/dev/null || echo 0)
      SCA_LOW=${SCA_LOW:-0}

      # Container — Grype
      CONTAINER_CRITICAL=$(jq '[.matches[]?.vulnerability?.severity? | select(.=="Critical")] | length' reports/container-scan/grype-image.json 2>/dev/null || echo 0)
      CONTAINER_CRITICAL=${CONTAINER_CRITICAL:-0}
      CONTAINER_HIGH=$(jq '[.matches[]?.vulnerability?.severity? | select(.=="High")] | length' reports/container-scan/grype-image.json 2>/dev/null || echo 0)
      CONTAINER_HIGH=${CONTAINER_HIGH:-0}

      # Secrets
      SECRETS=$(jq '. | if type=="array" then length else 0 end' reports/secrets/gitleaks.json 2>/dev/null || echo 0)
      SECRETS=${SECRETS:-0}

      # SAST — Semgrep
      SEMGREP_HIGH=$(jq '[.results[]? | select(.extra.severity=="ERROR")] | length' reports/sast/semgrep.json 2>/dev/null || echo 0)
      SEMGREP_HIGH=${SEMGREP_HIGH:-0}
      SEMGREP_MEDIUM=$(jq '[.results[]? | select(.extra.severity=="WARNING")] | length' reports/sast/semgrep.json 2>/dev/null || echo 0)
      SEMGREP_MEDIUM=${SEMGREP_MEDIUM:-0}
      SEMGREP_INFO=$(jq '[.results[]? | select(.extra.severity=="INFO")] | length' reports/sast/semgrep.json 2>/dev/null || echo 0)
      SEMGREP_INFO=${SEMGREP_INFO:-0}

      # Hadolint
      HADOLINT_ERRORS=$(jq 'length' reports/sast/hadolint.json 2>/dev/null || echo 0)
      HADOLINT_ERRORS=${HADOLINT_ERRORS:-0}

      # IaC
      CHECKOV_FAILED=$(jq '.results.failed_checks | length' reports/iac/results_json.json 2>/dev/null || echo 0)
      CHECKOV_FAILED=${CHECKOV_FAILED:-0}

      # DAST
      DAST_HIGH=$(jq '[.site[]?.alerts[]? | select(.riskcode=="3")] | length' reports/dast/zap-report.json 2>/dev/null || echo 0)
      DAST_HIGH=${DAST_HIGH:-0}
      DAST_MEDIUM=$(jq '[.site[]?.alerts[]? | select(.riskcode=="2")] | length' reports/dast/zap-report.json 2>/dev/null || echo 0)
      DAST_MEDIUM=${DAST_MEDIUM:-0}
      DAST_LOW=$(jq '[.site[]?.alerts[]? | select(.riskcode=="1")] | length' reports/dast/zap-report.json 2>/dev/null || echo 0)
      DAST_LOW=${DAST_LOW:-0}
    # ── Build final summary.json ──
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
        "sca": {
          "critical": ${SCA_CRITICAL},
          "high":     ${SCA_HIGH},
          "medium":   ${SCA_MEDIUM},
          "low":      ${SCA_LOW}
        },
        "container": {
          "critical": ${CONTAINER_CRITICAL},
          "high":     ${CONTAINER_HIGH}
        },
        "secrets": ${SECRETS},
        "sast": {
          "semgrep_high":   ${SEMGREP_HIGH},
          "semgrep_medium": ${SEMGREP_MEDIUM},
          "semgrep_info":   ${SEMGREP_INFO},
          "hadolint_errors": ${HADOLINT_ERRORS}
        },
        "dast": {
          "high":   ${DAST_HIGH},
          "medium": ${DAST_MEDIUM},
          "low":    ${DAST_LOW}
        },
        "iac": {
          "checkov_failed": ${CHECKOV_FAILED}
        },
        "status": "completed",
        "reports_url": "$CI_JOB_URL/artifacts"
      }
      EOF

    - echo "📄 Summary generated:"
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
      echo "📤 DefectDojo import"
      if [ -z "$DEFECTDOJO_URL" ] || [ -z "$DEFECTDOJO_TOKEN" ]; then
        echo "⚠️  DefectDojo not configured — skipping"
        exit 0
      fi

      REPO_NAME=$(echo "${GIT_REPO_URL}" | sed -E 's|.*/||; s|\.git$||')
      PRODUCT_NAME="${REPO_NAME}"
      ENGAGEMENT_NAME="${REPO_NAME}_${GIT_BRANCH}"

      echo "Product    : $PRODUCT_NAME"
      echo "Engagement : $ENGAGEMENT_NAME"

      # ── Product type (création auto si inexistant) ──
      PROD_TYPE_ID=$(curl -s -H "Authorization: ${DEFECTDOJO_TOKEN}" \
        "${DEFECTDOJO_URL}/api/v2/product_types/" | jq -r '.results[0].id // empty')

      if [ -z "$PROD_TYPE_ID" ] || [ "$PROD_TYPE_ID" = "null" ]; then
        echo "🆕 No product type — creating one..."
        PROD_TYPE_ID=$(curl -s -X POST "${DEFECTDOJO_URL}/api/v2/product_types/" \
          -H "Authorization: ${DEFECTDOJO_TOKEN}" \
          -H "Content-Type: application/json" \
          -d '{"name":"Default CI/CD","description":"Created automatically for all projects"}' \
          | jq -r '.id // empty')
        if [ -z "$PROD_TYPE_ID" ] || [ "$PROD_TYPE_ID" = "null" ]; then
          echo "❌ Failed to create product type"
          exit 1
        fi
        echo "✅ Product type created: $PROD_TYPE_ID"
      fi

      # ── Get/create product ──
      PRODUCT_ID=$(curl -s -H "Authorization: ${DEFECTDOJO_TOKEN}" \
        "${DEFECTDOJO_URL}/api/v2/products/?name=${PRODUCT_NAME}" | jq -r '.results[0].id // empty')

      if [ -z "$PRODUCT_ID" ] || [ "$PRODUCT_ID" = "null" ]; then
        echo "🆕 Creating product '$PRODUCT_NAME'..."
        PRODUCT_ID=$(curl -s -X POST "${DEFECTDOJO_URL}/api/v2/products/" \
          -H "Authorization: ${DEFECTDOJO_TOKEN}" \
          -H "Content-Type: application/json" \
          -d "{\"name\":\"$PRODUCT_NAME\",\"description\":\"${GIT_REPO_URL}\",\"prod_type\":$PROD_TYPE_ID}" \
          | jq -r '.id')
        echo "✅ Product created: $PRODUCT_ID"
      else
        echo "✅ Product exists: $PRODUCT_ID"
      fi
      [ -z "$PRODUCT_ID" ] || [ "$PRODUCT_ID" = "null" ] && echo "❌ Failed to get product ID" && exit 1

      # ── Get/create engagement ──
      TODAY=$(date +%Y-%m-%d)
      END_DATE=$(date -d "+30 days" +%Y-%m-%d 2>/dev/null || date -v+30d +%Y-%m-%d 2>/dev/null || echo "$TODAY")

      ENGAGEMENT_ID=$(curl -s -H "Authorization: ${DEFECTDOJO_TOKEN}" \
        "${DEFECTDOJO_URL}/api/v2/engagements/?product=${PRODUCT_ID}&name=${ENGAGEMENT_NAME}" \
        | jq -r '.results[0].id // empty')

      if [ -z "$ENGAGEMENT_ID" ] || [ "$ENGAGEMENT_ID" = "null" ]; then
        echo "🆕 Creating engagement '$ENGAGEMENT_NAME'..."
        ENGAGEMENT_ID=$(curl -s -X POST "${DEFECTDOJO_URL}/api/v2/engagements/" \
          -H "Authorization: ${DEFECTDOJO_TOKEN}" \
          -H "Content-Type: application/json" \
          -d "{\"name\":\"$ENGAGEMENT_NAME\",\"product\":$PRODUCT_ID,\"target_start\":\"$TODAY\",\"target_end\":\"$END_DATE\",\"status\":\"In Progress\",\"engagement_type\":\"CI/CD\",\"branch_tag\":\"$GIT_BRANCH\"}" \
          | jq -r '.id')
        echo "✅ Engagement created: $ENGAGEMENT_ID"
      else
        echo "✅ Engagement exists: $ENGAGEMENT_ID"
      fi
      [ -z "$ENGAGEMENT_ID" ] || [ "$ENGAGEMENT_ID" = "null" ] && echo "❌ Failed to get engagement" && exit 1

      # ── smart_import avec déduplication ──
      smart_import() {
        local FILE="$1" SCAN_TYPE="$2" LABEL="$3"

        if [ ! -f "$FILE" ] || [ ! -s "$FILE" ]; then
          echo "⏭️  [$LABEL] — missing or empty"
          return
        fi

        ENCODED_TYPE=$(python3 -c "import urllib.parse,sys; print(urllib.parse.quote(sys.argv[1]))" "$SCAN_TYPE" 2>/dev/null \
          || echo "$SCAN_TYPE" | sed 's/ /%20/g')

        # ── 1. Récupérer tous les tests existants pour ce scan_type ──
        ALL_TESTS=$(curl -s -H "Authorization: ${DEFECTDOJO_TOKEN}" \
          "${DEFECTDOJO_URL}/api/v2/tests/?engagement=${ENGAGEMENT_ID}&scan_type=${ENCODED_TYPE}&limit=100" \
          | jq -r '.results[].id' | sort -n)

        COUNT=$(echo "$ALL_TESTS" | grep -c . 2>/dev/null || echo 0)

        # ── 2. Supprimer tous les tests sauf le plus récent ──
        if [ "$COUNT" -gt 1 ]; then
          LATEST=$(echo "$ALL_TESTS" | tail -1)
          for ID in $ALL_TESTS; do
            if [ "$ID" != "$LATEST" ]; then
              echo "   🗑️  Deleting old test ID $ID for [$LABEL]"
              curl -s -X DELETE -H "Authorization: ${DEFECTDOJO_TOKEN}" \
                "${DEFECTDOJO_URL}/api/v2/tests/${ID}/" >/dev/null
            fi
          done
        fi

        # ── 3. Récupérer l'ID du test restant (s'il existe) ──
        TEST_ID=$(curl -s -H "Authorization: ${DEFECTDOJO_TOKEN}" \
          "${DEFECTDOJO_URL}/api/v2/tests/?engagement=${ENGAGEMENT_ID}&scan_type=${ENCODED_TYPE}" \
          | jq -r '.results[0].id // empty')

        # ── 4. Importer ou réimporter ──
        if [ -z "$TEST_ID" ] || [ "$TEST_ID" = "null" ]; then
          echo "🆕 IMPORT [$LABEL] — first scan on this engagement..."
          HTTP_CODE=$(curl -s -o /tmp/dojo_resp.json -w "%{http_code}" -X POST \
            "${DEFECTDOJO_URL}/api/v2/import-scan/" \
            -H "Authorization: ${DEFECTDOJO_TOKEN}" \
            -F "product_name=$PRODUCT_NAME" \
            -F "engagement_name=$ENGAGEMENT_NAME" \
            -F "scan_type=$SCAN_TYPE" \
            -F "file=@$FILE" \
            -F "auto_create_context=true" \
            -F "close_old_findings=false" \
            -F "deduplication_on_engagement=true")
        else
          echo "🔄 REIMPORT [$LABEL] — test_id=$TEST_ID..."
          HTTP_CODE=$(curl -s -o /tmp/dojo_resp.json -w "%{http_code}" -X POST \
            "${DEFECTDOJO_URL}/api/v2/reimport-scan/" \
            -H "Authorization: ${DEFECTDOJO_TOKEN}" \
            -F "test=$TEST_ID" \
            -F "scan_type=$SCAN_TYPE" \
            -F "file=@$FILE" \
            -F "close_old_findings=true" \
            -F "deduplication_on_engagement=true")
        fi

        if [ "$HTTP_CODE" -ge 400 ]; then
          echo "   ❌ [$LABEL] HTTP $HTTP_CODE — $(cat /tmp/dojo_resp.json)"
        else
          echo "   ✅ [$LABEL] HTTP $HTTP_CODE — $(jq -r '.test // .detail // "success"' /tmp/dojo_resp.json)"
        fi
      }

      echo ""
      echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
      echo "📦 SCA"
      smart_import "reports/trivy/trivy-fs.json"             "Trivy Scan"               "Trivy FS"

      echo "🔎 SAST"
      smart_import "reports/sast/semgrep.json"               "Semgrep JSON Report"      "Semgrep"
      smart_import "reports/sast/hadolint.json"              "Hadolint Dockerfile check" "Hadolint"

      echo "🔑 Secrets"
      smart_import "reports/secrets/gitleaks.json"           "Gitleaks Scan"            "Gitleaks"

      echo "🏗️  IaC"
      smart_import "reports/iac/results_json.json"                "Checkov Scan"             "Checkov"

      echo "🐳 Container"
      # Utilisation de "Grype Scan" (reconnu par DefectDojo)
      smart_import "reports/container-scan/grype-image.json" "Anchore Grype"               "Grype Image"

      echo "🕷️  DAST"
      smart_import "reports/dast/zap-report.xml" "ZAP Scan" "OWASP ZAP"

      echo ""
      echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
      echo "✅ DefectDojo import complete"
      echo "🔗 ${DEFECTDOJO_URL}/product/${PRODUCT_ID}/finding/open"
  allow_failure: true

# ══════════════════════════════════════════════════════════════════
# STAGE 12 · SECURITY-VALIDATION  —  Quality gate + backend verdict
# ══════════════════════════════════════════════════════════════════
security-validation:
  stage: security-validation
  image: alpine:latest
  needs:
    - aggregate-report
    - import-defectdojo
  before_script:
    - apk add --no-cache jq curl
  script:
    - |
      echo "🔒 SECURITY QUALITY GATE"
      echo "═══════════════════════════════════════════════"

      [ ! -f final-report/summary.json ] && echo "❌ summary.json not found" && exit 1

      # Read metrics
      SCA_CRITICAL=$(jq '.sca.critical'          final-report/summary.json)
      SCA_HIGH=$(jq '.sca.high'                  final-report/summary.json)
      SCA_MEDIUM=$(jq '.sca.medium'              final-report/summary.json)
      CONTAINER_CRITICAL=$(jq '.container.critical' final-report/summary.json)
      CONTAINER_HIGH=$(jq '.container.high'      final-report/summary.json)
      SECRETS=$(jq '.secrets'                    final-report/summary.json)
      SEMGREP_HIGH=$(jq '.sast.semgrep_high'     final-report/summary.json)
      SEMGREP_MEDIUM=$(jq '.sast.semgrep_medium' final-report/summary.json)
      CHECKOV_FAILED=$(jq '.iac.checkov_failed'  final-report/summary.json)
      DAST_HIGH=$(jq '.dast.high'                final-report/summary.json)
      DAST_MEDIUM=$(jq '.dast.medium'            final-report/summary.json)

      # Print table
      echo ""
      echo "┌────────────────────────────────────────────────────────┐"
      echo "│              SCAN RESULTS SUMMARY                     │"
      echo "├────────────────────────────────────────────────────────┤"
      printf "│ %-35s : %-16s │\n" "🔴 SCA Critical"           "$SCA_CRITICAL"
      printf "│ %-35s : %-16s │\n" "🟠 SCA High"               "$SCA_HIGH"
      printf "│ %-35s : %-16s │\n" "🟡 SCA Medium"             "$SCA_MEDIUM"
      printf "│ %-35s : %-16s │\n" "🐳 Container Critical"     "$CONTAINER_CRITICAL"
      printf "│ %-35s : %-16s │\n" "🐳 Container High"         "$CONTAINER_HIGH"
      printf "│ %-35s : %-16s │\n" "🔑 Secrets"                "$SECRETS"
      printf "│ %-35s : %-16s │\n" "📝 Semgrep High"           "$SEMGREP_HIGH"
      printf "│ %-35s : %-16s │\n" "📝 Semgrep Medium"         "$SEMGREP_MEDIUM"
      printf "│ %-35s : %-16s │\n" "🏗️  Checkov Failed"        "$CHECKOV_FAILED"
      printf "│ %-35s : %-16s │\n" "🕷️  DAST High"             "$DAST_HIGH"
      printf "│ %-35s : %-16s │\n" "🕷️  DAST Medium"           "$DAST_MEDIUM"
      echo "└────────────────────────────────────────────────────────┘"

      # ── Gate evaluation ──
      GATE_PASSED=true
      WARNINGS=""

      fail()    { echo "   ❌ BLOCKING: $1"; GATE_PASSED=false; }
      pass()    { echo "   ✅ OK: $1"; }
      warn()    { WARNINGS="${WARNINGS}  - $1\n"; }

      echo ""
      echo "📋 GATE CHECKS"
      echo "───────────────────────────────────────────────"

      # Absolute blockers
      [ "$SECRETS" -gt 0 ]                                           && fail "Secrets detected ($SECRETS)"            || pass "No secrets"
      [ "$SCA_CRITICAL" -gt "${SCA_CRITICAL_THRESHOLD}" ]           && fail "SCA Critical $SCA_CRITICAL > ${SCA_CRITICAL_THRESHOLD}" || pass "SCA Critical OK"
      [ "$SCA_HIGH" -gt "${SCA_HIGH_THRESHOLD}" ]                   && fail "SCA High $SCA_HIGH > ${SCA_HIGH_THRESHOLD}" || pass "SCA High OK"
      [ "$CONTAINER_CRITICAL" -gt "${CONTAINER_CRITICAL_THRESHOLD}" ] && fail "Container Critical $CONTAINER_CRITICAL > ${CONTAINER_CRITICAL_THRESHOLD}" || pass "Container Critical OK"
      [ "$CONTAINER_HIGH" -gt "${CONTAINER_HIGH_THRESHOLD}" ]       && fail "Container High $CONTAINER_HIGH > ${CONTAINER_HIGH_THRESHOLD}" || pass "Container High OK"
      [ "$SEMGREP_HIGH" -gt "${SEMGREP_HIGH_THRESHOLD}" ]           && fail "Semgrep High $SEMGREP_HIGH > ${SEMGREP_HIGH_THRESHOLD}" || pass "Semgrep High OK"
      [ "$CHECKOV_FAILED" -gt "${IAC_FAILED_THRESHOLD}" ]           && fail "Checkov $CHECKOV_FAILED > ${IAC_FAILED_THRESHOLD}" || pass "IaC OK"
      [ "$DAST_HIGH" -gt 5 ]                                         && fail "DAST High $DAST_HIGH > 5"               || pass "DAST High OK"

      # Warnings
      [ "$SEMGREP_MEDIUM" -gt "${SEMGREP_MEDIUM_THRESHOLD}" ]       && warn "Semgrep Medium: $SEMGREP_MEDIUM"
      [ "$SCA_MEDIUM" -gt 50 ]                                       && warn "SCA Medium: $SCA_MEDIUM"
      [ "$DAST_MEDIUM" -gt 10 ]                                      && warn "DAST Medium: $DAST_MEDIUM"

      echo ""
      echo "═══════════════════════════════════════════════"
      echo "🏁 FINAL VERDICT"
      echo "═══════════════════════════════════════════════"

      if [ "$GATE_PASSED" = "true" ]; then
        if [ -n "$WARNINGS" ]; then
          echo "⚠️  Warnings:"
          printf "%b" "$WARNINGS"
          echo "✅ Gate PASSED (with warnings) — DEPLOY_WITH_WARNINGS"
          RECOMMENDATION="DEPLOY_WITH_WARNINGS"
        else
          echo "✅ Gate PASSED — RECOMMANDE"
          RECOMMENDATION="RECOMMANDE"
        fi
      else
        echo "❌ Gate FAILED — NON_RECOMMANDE"
        RECOMMENDATION="NON_RECOMMANDE"
      fi

      echo "$RECOMMENDATION" > final-report/recommendation.txt
      echo "📄 Recommendation: $RECOMMENDATION"

    # ── Notify backend ──
    - |
      if [ -n "$BACKEND_URL" ]; then
        RECOMMENDATION=$(cat final-report/recommendation.txt)
        curl -s -X POST "${BACKEND_URL}/projet/api/security-gate" \
          -H "Content-Type: application/json" \
          -H "Authorization: Bearer ${API_TOKEN}" \
          -d "{
            \"environment_id\": \"$ENVIRONMENT_ID\",
            \"recommendation\": \"$RECOMMENDATION\",
            \"critical\":           $(jq '.sca.critical'          final-report/summary.json),
            \"high\":               $(jq '.sca.high'              final-report/summary.json),
            \"secrets\":            $(jq '.secrets'               final-report/summary.json),
            \"container_critical\": $(jq '.container.critical'    final-report/summary.json),
            \"dast_high\":          $(jq '.dast.high'             final-report/summary.json)
          }" || echo "⚠️  Backend notification failed"
      fi
  artifacts:
    paths:
      - final-report/recommendation.txt
      - final-report/summary.json
    expire_in: 7 days

# ══════════════════════════════════════════════════════════════════
# STAGE 13 · SCHEDULE-DELETE  —  TTL cleanup of ephemeral image
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

        curl -s -X DELETE \
          -H \"Authorization: JWT \${TOKEN}\" \
          \"https://hub.docker.com/v2/repositories/${DOCKER_USERNAME}/envirotest-app/tags/${ENVIRONMENT_ID}/\"

        rm -- \"\$0\"
        EOFSCRIPT
        chmod +x ~/delete-image-${ENVIRONMENT_ID}.sh
        echo \"~/delete-image-${ENVIRONMENT_ID}.sh\" | at now + ${TTL_HOURS} hours
      "
      echo "🗑️  Image deletion scheduled in ${TTL_HOURS}h"
  allow_failure: true