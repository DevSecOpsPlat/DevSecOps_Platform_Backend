# ════════════════════════════════════════════════════════════════════════════
# ENVIROTEST — Pipeline GitLab CI unifié (scan + déploiement)
#
# Un seul .gitlab-ci.yml : le backend choisit le flux via ACTION :
#   • Scan    : ACTION absent ou != "deploy" → jobs scan (default rules)
#   • Deploy  : ACTION=deploy → jobs deploy:* uniquement
#
# DefectDojo : tag pipeline-${CI_PIPELINE_ID} (+ scan ou deploy) pour filtrer
# les résultats par exécution GitLab (dashboard / quality gate).
#
# Webhook GitLab : OPTIONNEL. Sans webhook, la synchro se fait via :
#   • job security-validation → POST /api/security-gate (quality gate + snapshot)
#   • ouverture du détail pipeline dans l'UI → sync API GitLab
# Le nettoyage registry (ex-delete-docker-image) est géré par le backend.
# ════════════════════════════════════════════════════════════════════════════

workflow:
  rules:
    - if: '$CI_PIPELINE_SOURCE == "api"'
    - if: '$CI_PIPELINE_SOURCE == "trigger"'
    - if: '$CI_PIPELINE_SOURCE == "web"'
    - when: never

.scan-rules:
  rules:
    - if: '$ACTION != "deploy"'

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

# BACKEND_URL, PIPELINE_SECRET : variables CI/CD GitLab uniquement (Settings → CI/CD → Variables).
# Mettez l'URL complète du tunnel telle quelle (ex. https://xxx.trycloudflare.com/projet).
variables:
  ACTION:             ""
  GIT_REPO_URL:       ""
  GIT_BRANCH:         "main"
  GITHUB_TOKEN:       ""
  APPLICATION_ID:     ""
  ENVIRONMENT_ID:     ""
  DEPLOYMENT_ID:      ""
  NAMESPACE:          ""
  IMAGE_TAG:          ""
  DOCKERFILE_PATH:    "./Dockerfile"
  BUILD_CONTEXT:      "."
  DEFECTDOJO_URL:     ""
  DEFECTDOJO_TOKEN:   ""
  SONAR_HOST_URL:     ""
  SONAR_TOKEN:        ""
  DOCKER_USERNAME:    ""
  DOCKER_ACCESS_TOKEN: ""
  ENVIRONMENT_URL:    ""
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
  DAST_HIGH_THRESHOLD:          "5"
  DEPLOY_GATE_ENFORCE:          "false"
  DD_IMPORT_ENABLED:  "false"
  USE_KANIKO: "false"
  # dind = GitLab SaaS (service docker:dind + TLS). socket = runner self-hosted avec /var/run/docker.sock monté.
  DOCKER_BUILD_MODE: "dind"

# ──────────────────────────────────────────────────────────────────
# STAGE 1 · SETUP
# ──────────────────────────────────────────────────────────────────
hello-world:
  extends: .scan-rules
  stage: setup
  image: alpine:latest
  retry: 2
  script:
    - echo "EnviroTest Security Pipeline (scan)"
    - echo "Pipeline ID = $CI_PIPELINE_ID"
    - echo "Repository  = $GIT_REPO_URL"
    - echo "Branch      = $GIT_BRANCH"

clone-repository:
  extends: .scan-rules
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

    # ── Bloc A : export pour RAG ──
    - |
      . ./build.env
      LANGS=""
      [ "$LANG_NODE" = "true" ] && LANGS="${LANGS:+$LANGS, }node"
      [ "$LANG_PYTHON" = "true" ] && LANGS="${LANGS:+$LANGS, }python"
      [ "$LANG_JAVA" = "true" ] && LANGS="${LANGS:+$LANGS, }java"
      [ "$LANG_GO" = "true" ] && LANGS="${LANGS:+$LANGS, }go"
      [ "$LANG_RUBY" = "true" ] && LANGS="${LANGS:+$LANGS, }ruby"
      [ "$LANG_PHP" = "true" ] && LANGS="${LANGS:+$LANGS, }php"
      [ "$LANG_RUST" = "true" ] && LANGS="${LANGS:+$LANGS, }rust"
      [ "$LANG_DOTNET" = "true" ] && LANGS="${LANGS:+$LANGS, }dotnet"
      [ "$LANG_CPP" = "true" ] && LANGS="${LANGS:+$LANGS, }cpp"
      [ -z "$LANGS" ] && LANGS="unknown"
      echo "DETECTED_LANGUAGES=${LANGS}" >> detected.env

      PKG_MANAGERS=""
      [ -f "user-repo/package.json" ] && PKG_MANAGERS="${PKG_MANAGERS:+$PKG_MANAGERS, }npm/yarn"
      [ -f "user-repo/requirements.txt" ] && PKG_MANAGERS="${PKG_MANAGERS:+$PKG_MANAGERS, }pip"
      [ -f "user-repo/Pipfile" ] && PKG_MANAGERS="${PKG_MANAGERS:+$PKG_MANAGERS, }pipenv"
      [ -f "user-repo/pom.xml" ] && PKG_MANAGERS="${PKG_MANAGERS:+$PKG_MANAGERS, }maven"
      [ -f "user-repo/build.gradle" ] && PKG_MANAGERS="${PKG_MANAGERS:+$PKG_MANAGERS, }gradle"
      [ -f "user-repo/go.mod" ] && PKG_MANAGERS="${PKG_MANAGERS:+$PKG_MANAGERS, }go mod"
      [ -f "user-repo/Gemfile" ] && PKG_MANAGERS="${PKG_MANAGERS:+$PKG_MANAGERS, }bundler"
      [ -f "user-repo/composer.json" ] && PKG_MANAGERS="${PKG_MANAGERS:+$PKG_MANAGERS, }composer"
      [ -f "user-repo/Cargo.toml" ] && PKG_MANAGERS="${PKG_MANAGERS:+$PKG_MANAGERS, }cargo"
      if find user-repo -maxdepth 2 -name "*.csproj" -o -name "*.fsproj" | grep -q .; then
        PKG_MANAGERS="${PKG_MANAGERS:+$PKG_MANAGERS, }nuget"
      fi
      [ -z "$PKG_MANAGERS" ] && PKG_MANAGERS="unknown"
      echo "PACKAGE_MANAGERS=${PKG_MANAGERS}" >> detected.env

      cat detected.env
  artifacts:
    paths:
      - user-repo/
      - build.env
      - detected.env
    reports:
      dotenv: detected.env
    expire_in: 1 day

# ──────────────────────────────────────────────────────────────────
# STAGE 2 · CODE-ANALYSIS – SonarQube
# ──────────────────────────────────────────────────────────────────
sonarqube-setup:
  extends: .scan-rules
  stage: code-analysis
  image: alpine:latest
  needs: ["clone-repository"]
  before_script:
    - apk add --no-cache curl jq
  script:
    - |
      if [ -z "$SONAR_HOST_URL" ] || [ -z "$SONAR_TOKEN" ]; then
        echo "SonarQube non configuré — skip"
        echo "PROJECT_KEY=" >> project.env
        exit 0
      fi
      REPO_NAME=$(echo "${GIT_REPO_URL}" | sed -E 's|.*/||; s|\.git$||')
      PROJECT_KEY=$(echo "${GIT_REPO_URL}" | sed -E 's|https?://||; s|\.git$||; s|/|_|g; s|[^a-zA-Z0-9_]|_|g')
      echo "Project key = ${PROJECT_KEY}"
      RESPONSE=$(curl -s -w "\n%{http_code}" -u "${SONAR_TOKEN}:" \
        "${SONAR_HOST_URL}/api/projects/search?projects=${PROJECT_KEY}" 2>&1) || true
      HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
      BODY=$(echo "$RESPONSE" | head -n-1)
      if [ "$HTTP_CODE" != "200" ]; then
        echo "SonarQube API error HTTP $HTTP_CODE — skip"
        echo "PROJECT_KEY=" >> project.env
        exit 0
      fi
      EXISTS=$(echo "$BODY" | jq -r '.components | length // 0')
      if [ "$EXISTS" -eq 0 ]; then
        curl -s -X POST -u "${SONAR_TOKEN}:" \
          "${SONAR_HOST_URL}/api/projects/create" \
          -d "project=${PROJECT_KEY}&name=${REPO_NAME}&visibility=private"
      fi
      curl -s -X POST -u "${SONAR_TOKEN}:" \
        "${SONAR_HOST_URL}/api/qualitygates/select" \
        -d "projectKey=${PROJECT_KEY}&gateName=Sonar way"
      echo "PROJECT_KEY=${PROJECT_KEY}" >> project.env
      printf 'SONAR_DASHBOARD_URL="%s/dashboard?id=%s&branch=%s"\n' \
        "$SONAR_HOST_URL" "$PROJECT_KEY" "$GIT_BRANCH" >> project.env
  artifacts:
    reports:
      dotenv: project.env
    expire_in: 1 hour
  allow_failure: true

sonarqube-scan:
  extends: .scan-rules
  stage: code-analysis
  image: sonarsource/sonar-scanner-cli:latest
  needs:
    - clone-repository
    - sonarqube-setup
  script:
    - |
      if [ -z "$SONAR_HOST_URL" ] || [ -z "$SONAR_TOKEN" ] || [ -z "$PROJECT_KEY" ]; then
        echo "SonarQube non configuré — skip"
        exit 0
      fi
    - cd user-repo
    - |
      sonar-scanner \
        -Dsonar.projectKey="${PROJECT_KEY}" \
        -Dsonar.sources=. \
        -Dsonar.host.url="${SONAR_HOST_URL}" \
        -Dsonar.token="${SONAR_TOKEN}" \
        -Dsonar.branch.name="${GIT_BRANCH}" \
        -Dsonar.exclusions="**/node_modules/**,**/dist/**,**/target/**,**/build/**"
  allow_failure: true

# ──────────────────────────────────────────────────────────────────
# STAGE 3 · SCA – Trivy FS + Syft
# ──────────────────────────────────────────────────────────────────
trivy-fs-scan:
  extends: .scan-rules
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
  extends: .scan-rules
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

# ──────────────────────────────────────────────────────────────────
# STAGE 4 · SAST – Semgrep + Hadolint
# ──────────────────────────────────────────────────────────────────
semgrep-sast:
  extends: .scan-rules
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
  extends: .scan-rules
  stage: sast
  image: hadolint/hadolint:latest-debian
  needs: ["clone-repository"]
  script:
    - echo "Hadolint — Dockerfile security lint"
    - mkdir -p reports/sast
    - . ./build.env 2>/dev/null || true
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

# ──────────────────────────────────────────────────────────────────
# STAGE 5 · SECRETS-IAC – Gitleaks + Checkov
# ──────────────────────────────────────────────────────────────────
gitleaks-secrets:
  extends: .scan-rules
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
  extends: .scan-rules
  stage: secrets-iac
  image: python:3.11-alpine
  needs:
    - clone-repository
  before_script:
    - pip install checkov --quiet
  script:
    - echo "Checkov — IaC scan"
    - mkdir -p reports/iac
    - . ./build.env 2>/dev/null || true
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
      if [ ! -f reports/iac/results_json.json ]; then
        if [ -f reports/iac/checkov_results.json ]; then
          cp reports/iac/checkov_results.json reports/iac/results_json.json
        elif ls reports/iac/*.json 2>/dev/null | head -1 | grep -q .; then
          FIRST=$(ls reports/iac/*.json | head -1)
          cp "$FIRST" reports/iac/results_json.json
        else
          echo '{"results":{"passed_checks":[],"failed_checks":[]}}' > reports/iac/results_json.json
        fi
      fi
  artifacts:
    paths:
      - reports/iac/
    expire_in: 1 day
  allow_failure: true

# ──────────────────────────────────────────────────────────────────
# STAGE 6 · BUILD – Docker image
#
# Erreur « open /certs/client/ca.pem » ou « docker.sock: device or resource busy » :
#   → runner self-hosted : DOCKER_BUILD_MODE=socket (Settings → CI/CD → Variables)
#   → ou USE_KANIKO=true (build sans daemon Docker)
# ──────────────────────────────────────────────────────────────────
.docker-wait: &docker-wait |
  wait_for_docker() {
    TRIES=0
    while ! docker info >/dev/null 2>&1; do
      TRIES=$((TRIES + 1))
      if [ "$TRIES" -ge 40 ]; then
        echo "Docker indisponible après 2 minutes"
        docker info 2>&1 || true
        exit 1
      fi
      if [ -S /var/run/docker.sock ] && [ "${DOCKER_HOST:-}" != "unix:///var/run/docker.sock" ]; then
        echo "Bascule sur le socket Docker hôte (/var/run/docker.sock)"
        export DOCKER_HOST=unix:///var/run/docker.sock
        unset DOCKER_TLS_VERIFY DOCKER_CERT_PATH
      fi
      echo "Waiting for Docker daemon... ($TRIES/40)"
      sleep 3
    done
    echo "Docker OK — $(docker version --format '{{.Server.Version}}' 2>/dev/null || echo unknown)"
  }
  wait_for_docker

.build-docker-scan-script: &build-docker-scan-script
  - echo "Building Docker image"
  - |
    if [ "$USE_KANIKO" = "true" ]; then
      echo "USE_KANIKO=true — skipping socket build"
      exit 0
    fi
  - *docker-wait
  - cd user-repo
  - test -n "$DOCKER_USERNAME" || (echo "DOCKER_USERNAME is required" && exit 1)
  - SCAN_TAG="${ENVIRONMENT_ID:-$CI_PIPELINE_ID}"
  - '[ -n "$SCAN_TAG" ] || SCAN_TAG="latest"'
  - IMAGE_NAME="${DOCKER_USERNAME}/envirotest-app:${SCAN_TAG}"
  - docker build -f ${DOCKERFILE_PATH} -t ${IMAGE_NAME} "${BUILD_CONTEXT:-.}"
  - docker save -o ../image.tar ${IMAGE_NAME}
  - cd ..
  - echo "IMAGE_NAME=${IMAGE_NAME}" > image_name.env
  - echo "Image built $IMAGE_NAME"

build-docker-image:
  extends: .scan-rules
  stage: build
  image: docker:29.5.3
  services:
    - docker:29.5.3-dind
  retry: 2
  rules:
    - if: '$ACTION == "deploy"'
      when: never
    - if: '$USE_KANIKO == "true"'
      when: never
    - if: '$DOCKER_BUILD_MODE == "socket"'
      when: never
    - when: on_success
  needs:
    - clone-repository
  variables:
    DOCKER_HOST: tcp://docker:2376
    DOCKER_TLS_CERTDIR: "/certs"
    DOCKER_TLS_VERIFY: "1"
    DOCKER_CERT_PATH: "/certs/client"
  script: *build-docker-scan-script
  artifacts:
    paths:
      - image.tar
      - image_name.env
    expire_in: 2 hours
  allow_failure: false

build-docker-image-host:
  extends: .scan-rules
  stage: build
  image: docker:29.5.3
  retry: 2
  rules:
    - if: '$ACTION == "deploy"'
      when: never
    - if: '$USE_KANIKO == "true"'
      when: never
    - if: '$DOCKER_BUILD_MODE == "socket"'
    - when: never
  needs:
    - clone-repository
  variables:
    DOCKER_HOST: unix:///var/run/docker.sock
  script: *build-docker-scan-script
  artifacts:
    paths:
      - image.tar
      - image_name.env
    expire_in: 2 hours
  allow_failure: false

build-docker-image-kaniko:
  extends: .scan-rules
  stage: build
  image:
    name: gcr.io/kaniko-project/executor:debug
    entrypoint: [""]
  needs:
    - clone-repository
  rules:
    - if: '$USE_KANIKO == "true" && $ACTION != "deploy"'
  script:
    - echo "Kaniko build"
    - mkdir -p /workspace
    - |
      test -n "$DOCKER_USERNAME" || (echo "DOCKER_USERNAME is required" && exit 1)
      SCAN_TAG="${ENVIRONMENT_ID:-$CI_PIPELINE_ID}"
      [ -n "$SCAN_TAG" ] || SCAN_TAG="latest"
      IMAGE_NAME="${DOCKER_USERNAME}/envirotest-app:${SCAN_TAG}"
      /kaniko/executor \
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

# ──────────────────────────────────────────────────────────────────
# STAGE 7 · CONTAINER-SCAN – Grype
# ──────────────────────────────────────────────────────────────────
grype-image-scan:
  extends: .scan-rules
  stage: container-scan
  image: alpine:latest
  retry: 2
  needs:
    - job: build-docker-image
      artifacts: true
      optional: true
    - job: build-docker-image-host
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

# ──────────────────────────────────────────────────────────────────
# STAGE 8 · REPORTING – Agrégation + DefectDojo + RAG
# ──────────────────────────────────────────────────────────────────
aggregate-report:
  extends: .scan-rules
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
    
  before_script:
    - apk add --no-cache jq
  script:
    - echo "Aggregating all scan results..."
    - mkdir -p final-report
    - . ./build.env 2>/dev/null || true

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
      IS_ARRAY=$(jq 'if type=="array" then "yes" else "no" end' reports/iac/results_json.json 2>/dev/null || echo "no")
      if [ "$IS_ARRAY" = "yes" ]; then
        CHECKOV_FAILED=$(jq '[.[].results.failed_checks // [] | length] | add // 0' reports/iac/results_json.json 2>/dev/null || echo 0)
      else
        CHECKOV_FAILED=$(jq '.results.failed_checks | length' reports/iac/results_json.json 2>/dev/null || echo 0)
      fi
      CHECKOV_FAILED=${CHECKOV_FAILED:-0}
     
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
        "dast": { "high": ${DAST_HIGH:-0}, "medium": ${DAST_MEDIUM:-0}, "low": ${DAST_LOW:-0} },
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
  extends: .scan-rules
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
      case "${DEFECTDOJO_TOKEN}" in
        Token\ *) DOJO_AUTH="${DEFECTDOJO_TOKEN}" ;;
        *) DOJO_AUTH="Token ${DEFECTDOJO_TOKEN}" ;;
      esac

      REPO_NAME=$(echo "${GIT_REPO_URL}" | sed -E 's|.*/||; s|\.git$||')
      PRODUCT_NAME="${REPO_NAME}"
      ENGAGEMENT_NAME="${REPO_NAME}_${GIT_BRANCH}"

      PROD_TYPE_ID=$(curl -s -H "Authorization: ${DOJO_AUTH}" \
        "${DEFECTDOJO_URL}/api/v2/product_types/" | jq -r '.results[0].id // empty')
      if [ -z "$PROD_TYPE_ID" ] || [ "$PROD_TYPE_ID" = "null" ]; then
        PROD_TYPE_ID=$(curl -s -X POST "${DEFECTDOJO_URL}/api/v2/product_types/" \
          -H "Authorization: ${DOJO_AUTH}" -H "Content-Type: application/json" \
          -d '{"name":"Default CI/CD","description":"Created automatically"}' | jq -r '.id // empty')
      fi

      PRODUCT_ID=$(curl -s -H "Authorization: ${DOJO_AUTH}" \
        "${DEFECTDOJO_URL}/api/v2/products/?name=${PRODUCT_NAME}" | jq -r '.results[0].id // empty')
      if [ -z "$PRODUCT_ID" ] || [ "$PRODUCT_ID" = "null" ]; then
        CREATE_RESP=$(curl -s -X POST "${DEFECTDOJO_URL}/api/v2/products/" \
          -H "Authorization: ${DOJO_AUTH}" -H "Content-Type: application/json" \
          -d "{\"name\":\"$PRODUCT_NAME\",\"description\":\"${GIT_REPO_URL}\",\"prod_type\":$PROD_TYPE_ID}")
        PRODUCT_ID=$(echo "$CREATE_RESP" | jq -r '.id // empty')
        echo "Product created: $PRODUCT_ID"
        if [ -z "$PRODUCT_ID" ] || [ "$PRODUCT_ID" = "null" ]; then
          echo "DefectDojo product create error (prod_type=${PROD_TYPE_ID}): $CREATE_RESP"
        fi
      fi
      [ -z "$PRODUCT_ID" ] || [ "$PRODUCT_ID" = "null" ] && echo "Failed to get product ID" && exit 1

      TODAY=$(date +%Y-%m-%d)
      END_DATE=$(date -d "+30 days" +%Y-%m-%d 2>/dev/null || date -v+30d +%Y-%m-%d 2>/dev/null || echo "$TODAY")

      ENGAGEMENT_ID=$(curl -s -H "Authorization: ${DOJO_AUTH}" \
        "${DEFECTDOJO_URL}/api/v2/engagements/?product=${PRODUCT_ID}&name=${ENGAGEMENT_NAME}" \
        | jq -r '.results[0].id // empty')
      if [ -z "$ENGAGEMENT_ID" ] || [ "$ENGAGEMENT_ID" = "null" ]; then
        ENGAGEMENT_ID=$(curl -s -X POST "${DEFECTDOJO_URL}/api/v2/engagements/" \
          -H "Authorization: ${DOJO_AUTH}" -H "Content-Type: application/json" \
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
        ALL_TESTS=$(curl -s -H "Authorization: ${DOJO_AUTH}" \
          "${DEFECTDOJO_URL}/api/v2/tests/?engagement=${ENGAGEMENT_ID}&scan_type=${ENCODED_TYPE}&limit=100" \
          | jq -r '.results[].id' | sort -n)
        COUNT=$(echo "$ALL_TESTS" | grep -c . 2>/dev/null || echo 0)
        if [ "$COUNT" -gt 1 ]; then
          LATEST=$(echo "$ALL_TESTS" | tail -1)
          for ID in $ALL_TESTS; do
            [ "$ID" != "$LATEST" ] && curl -s -X DELETE -H "Authorization: ${DOJO_AUTH}" "${DEFECTDOJO_URL}/api/v2/tests/${ID}/" >/dev/null
          done
        fi
        TEST_ID=$(curl -s -H "Authorization: ${DOJO_AUTH}" \
          "${DEFECTDOJO_URL}/api/v2/tests/?engagement=${ENGAGEMENT_ID}&scan_type=${ENCODED_TYPE}" \
          | jq -r '.results[0].id // empty')
        if [ -z "$TEST_ID" ] || [ "$TEST_ID" = "null" ]; then
          HTTP_CODE=$(curl -s -o /tmp/dojo_resp.json -w "%{http_code}" -X POST \
            "${DEFECTDOJO_URL}/api/v2/import-scan/" -H "Authorization: ${DOJO_AUTH}" \
            -F "product_name=$PRODUCT_NAME" -F "engagement_name=$ENGAGEMENT_NAME" \
            -F "scan_type=$SCAN_TYPE" -F "file=@$FILE"             -F "tags=env-${ENVIRONMENT_ID}" -F "tags=pipeline-${CI_PIPELINE_ID}" -F "tags=scan" \
            -F "auto_create_context=true" -F "close_old_findings=false" -F "deduplication_on_engagement=true")
        else
          HTTP_CODE=$(curl -s -o /tmp/dojo_resp.json -w "%{http_code}" -X POST \
            "${DEFECTDOJO_URL}/api/v2/reimport-scan/" -H "Authorization: ${DOJO_AUTH}" \
            -F "test=$TEST_ID" -F "scan_type=$SCAN_TYPE" -F "file=@$FILE" \
            -F "tags=env-${ENVIRONMENT_ID}" -F "tags=pipeline-${CI_PIPELINE_ID}" -F "tags=scan" \
            -F "close_old_findings=true" -F "deduplication_on_engagement=true")
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
    
      echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
      echo "DefectDojo import complete"
  allow_failure: true

# ──────────────────────────────────────────────────────────────────
# STAGE 9 · SECURITY-VALIDATION – Quality gate
# ──────────────────────────────────────────────────────────────────
security-validation:
  extends: .scan-rules
  stage: security-validation
  image: alpine:latest
  needs:
    - job: aggregate-report
      artifacts: true
    - job: import-defectdojo
      artifacts: false
    - job: sonarqube-setup
      artifacts: true
  before_script:
    - apk add --no-cache jq curl
  script:
    - |
      set -eu
      test -f final-report/summary.json || (echo "summary.json not found" && exit 1)
      mkdir -p final-report

      # PROJECT_KEY vient du dotenv sonarqube-setup (ne pas « source » project.env : & dans l'URL casse sh)
      to_int() {
        case "$1" in ''|null|*[!0-9]*) echo 0 ;; *) echo "$1" ;; esac
      }

      SCA_CRITICAL=$(to_int "$(jq -r '.sca.critical // 0' final-report/summary.json)")
      SCA_HIGH=$(to_int "$(jq -r '.sca.high // 0' final-report/summary.json)")
      SCA_MEDIUM=$(to_int "$(jq -r '.sca.medium // 0' final-report/summary.json)")
      CONTAINER_CRITICAL=$(to_int "$(jq -r '.container.critical // 0' final-report/summary.json)")
      CONTAINER_HIGH=$(to_int "$(jq -r '.container.high // 0' final-report/summary.json)")
      SECRETS=$(to_int "$(jq -r '.secrets // 0' final-report/summary.json)")
      SEMGREP_HIGH=$(to_int "$(jq -r '.sast.semgrep_high // 0' final-report/summary.json)")
      SEMGREP_MEDIUM=$(to_int "$(jq -r '.sast.semgrep_medium // 0' final-report/summary.json)")
      CHECKOV_FAILED=$(to_int "$(jq -r '.iac.checkov_failed // 0' final-report/summary.json)")
      DAST_HIGH=$(to_int "$(jq -r '.dast.high // 0' final-report/summary.json)")
      DAST_MEDIUM=$(to_int "$(jq -r '.dast.medium // 0' final-report/summary.json)")
      DAST_LOW=$(to_int "$(jq -r '.dast.low // 0' final-report/summary.json)")

      SCA_CRITICAL_THRESHOLD=${SCA_CRITICAL_THRESHOLD:-5}
      SCA_HIGH_THRESHOLD=${SCA_HIGH_THRESHOLD:-20}
      CONTAINER_CRITICAL_THRESHOLD=${CONTAINER_CRITICAL_THRESHOLD:-0}
      CONTAINER_HIGH_THRESHOLD=${CONTAINER_HIGH_THRESHOLD:-10}
      SEMGREP_HIGH_THRESHOLD=${SEMGREP_HIGH_THRESHOLD:-10}
      SEMGREP_MEDIUM_THRESHOLD=${SEMGREP_MEDIUM_THRESHOLD:-50}
      IAC_FAILED_THRESHOLD=${IAC_FAILED_THRESHOLD:-10}

      GATE_PASSED=true; WARNINGS=""; BLOCKING=""
      fail() { echo "BLOCKING : $1"; GATE_PASSED=false; BLOCKING="${BLOCKING}${1}; "; }
      pass() { echo "OK       : $1"; }
      warn() { echo "WARNING  : $1"; WARNINGS="${WARNINGS}${1}; "; }

      [ "$SCA_CRITICAL" -gt "$SCA_CRITICAL_THRESHOLD" ] \
        && fail "SCA Critical: $SCA_CRITICAL > $SCA_CRITICAL_THRESHOLD" \
        || pass "SCA Critical ($SCA_CRITICAL <= $SCA_CRITICAL_THRESHOLD)"
      [ "$SCA_HIGH" -gt "$SCA_HIGH_THRESHOLD" ] \
        && fail "SCA High: $SCA_HIGH > $SCA_HIGH_THRESHOLD" \
        || pass "SCA High ($SCA_HIGH <= $SCA_HIGH_THRESHOLD)"
      [ "$CONTAINER_CRITICAL" -gt "$CONTAINER_CRITICAL_THRESHOLD" ] \
        && fail "Container Critical: $CONTAINER_CRITICAL > $CONTAINER_CRITICAL_THRESHOLD" \
        || pass "Container Critical ($CONTAINER_CRITICAL <= $CONTAINER_CRITICAL_THRESHOLD)"
      [ "$CONTAINER_HIGH" -gt "$CONTAINER_HIGH_THRESHOLD" ] \
        && fail "Container High: $CONTAINER_HIGH > $CONTAINER_HIGH_THRESHOLD" \
        || pass "Container High ($CONTAINER_HIGH <= $CONTAINER_HIGH_THRESHOLD)"
      [ "$SECRETS" -gt 0 ] && fail "Secrets détectés: $SECRETS" || pass "Secrets ($SECRETS)"
      [ "$SEMGREP_HIGH" -gt "$SEMGREP_HIGH_THRESHOLD" ] \
        && fail "Semgrep High: $SEMGREP_HIGH > $SEMGREP_HIGH_THRESHOLD" \
        || pass "Semgrep High ($SEMGREP_HIGH <= $SEMGREP_HIGH_THRESHOLD)"
      [ "$SEMGREP_MEDIUM" -gt "$SEMGREP_MEDIUM_THRESHOLD" ] \
        && warn "Semgrep Medium: $SEMGREP_MEDIUM > $SEMGREP_MEDIUM_THRESHOLD" \
        || pass "Semgrep Medium ($SEMGREP_MEDIUM <= $SEMGREP_MEDIUM_THRESHOLD)"
      [ "$CHECKOV_FAILED" -gt "$IAC_FAILED_THRESHOLD" ] \
        && fail "Checkov Failed: $CHECKOV_FAILED > $IAC_FAILED_THRESHOLD" \
        || pass "Checkov Failed ($CHECKOV_FAILED <= $IAC_FAILED_THRESHOLD)"

      if [ "$GATE_PASSED" = "true" ]; then
        [ -n "$WARNINGS" ] && RECOMMENDATION="DEPLOY_WITH_WARNINGS" || RECOMMENDATION="RECOMMANDE"
      else
        RECOMMENDATION="NON_RECOMMANDE"
      fi
      echo "VERDICT: $RECOMMENDATION"
      echo "$RECOMMENDATION" > final-report/recommendation.txt

      SONAR_AVAILABLE=false
      SONAR_QUALITY_GATE="N/A"
      SONAR_BUGS=0; SONAR_VULNERABILITIES=0; SONAR_SECURITY_HOTSPOTS=0; SONAR_NCLOC=0
      SONAR_SECURITY_RATING="N/A"
      if [ -n "${SONAR_HOST_URL:-}" ] && [ -n "${SONAR_TOKEN:-}" ] && [ -n "${PROJECT_KEY:-}" ]; then
        MEASURES=$(curl -sf -u "${SONAR_TOKEN}:" \
          "${SONAR_HOST_URL}/api/measures/component?component=${PROJECT_KEY}&branch=${GIT_BRANCH}&metricKeys=bugs,vulnerabilities,security_hotspots,ncloc,software_quality_security_rating" \
          2>/dev/null || echo "")
        if [ -n "$MEASURES" ]; then
          SONAR_AVAILABLE=true
          SONAR_BUGS=$(to_int "$(echo "$MEASURES" | jq -r '.component.measures[]? | select(.metric=="bugs") | .value // "0"')")
          SONAR_VULNERABILITIES=$(to_int "$(echo "$MEASURES" | jq -r '.component.measures[]? | select(.metric=="vulnerabilities") | .value // "0"')")
          SONAR_SECURITY_HOTSPOTS=$(to_int "$(echo "$MEASURES" | jq -r '.component.measures[]? | select(.metric=="security_hotspots") | .value // "0"')")
          SONAR_NCLOC=$(to_int "$(echo "$MEASURES" | jq -r '.component.measures[]? | select(.metric=="ncloc") | .value // "0"')")
          SONAR_SECURITY_RATING=$(echo "$MEASURES" | jq -r '.component.measures[]? | select(.metric=="software_quality_security_rating") | .value // "N/A"')
          QG=$(curl -sf -u "${SONAR_TOKEN}:" \
            "${SONAR_HOST_URL}/api/qualitygates/project_status?projectKey=${PROJECT_KEY}&branch=${GIT_BRANCH}" 2>/dev/null || echo "")
          SONAR_QUALITY_GATE=$(echo "$QG" | jq -r '.projectStatus.status // "N/A"')
        fi
      fi

      if [ "$SONAR_AVAILABLE" = "true" ]; then
        tmp=$(mktemp)
        jq --arg qg "$SONAR_QUALITY_GATE" \
           --argjson bugs "$SONAR_BUGS" \
           --argjson vulns "$SONAR_VULNERABILITIES" \
           --argjson hotspots "$SONAR_SECURITY_HOTSPOTS" \
           --argjson ncloc "$SONAR_NCLOC" \
           --arg rating "$SONAR_SECURITY_RATING" \
           '. + {sonar: ((.sonar // {}) + {
             quality_gate: $qg, bugs: $bugs, vulnerabilities: $vulns,
             security_hotspots: $hotspots, ncloc: $ncloc, security_rating: $rating
           })}' final-report/summary.json > "$tmp" && mv "$tmp" final-report/summary.json
      fi

      if [ -n "${BACKEND_URL:-}" ] && [ -n "${PIPELINE_SECRET:-}" ] && [ -n "${APPLICATION_ID:-}" ]; then
        jq -n \
          --arg application_id "$APPLICATION_ID" \
          --arg pipeline_id "${CI_PIPELINE_ID}" \
          --arg kind "scan" \
          --arg recommendation "$RECOMMENDATION" \
          --arg sonar_quality_gate "$SONAR_QUALITY_GATE" \
          --arg sonar_security_rating "$SONAR_SECURITY_RATING" \
          --argjson critical "$SCA_CRITICAL" \
          --argjson high "$SCA_HIGH" \
          --argjson sca_medium "$SCA_MEDIUM" \
          --argjson secrets "$SECRETS" \
          --argjson container_critical "$CONTAINER_CRITICAL" \
          --argjson container_high "$CONTAINER_HIGH" \
          --argjson semgrep_high "$SEMGREP_HIGH" \
          --argjson semgrep_medium "$SEMGREP_MEDIUM" \
          --argjson checkov_failed "$CHECKOV_FAILED" \
          --argjson dast_high "$DAST_HIGH" \
          --argjson dast_medium "$DAST_MEDIUM" \
          --argjson dast_low "$DAST_LOW" \
          --argjson sonar_bugs "$SONAR_BUGS" \
          --argjson sonar_vulnerabilities "$SONAR_VULNERABILITIES" \
          --argjson sonar_hotspots "$SONAR_SECURITY_HOTSPOTS" \
          --argjson sonar_ncloc "$SONAR_NCLOC" \
          --argjson summary "$(cat final-report/summary.json)" \
          '{
            application_id: $application_id,
            pipeline_id: $pipeline_id,
            kind: $kind,
            recommendation: $recommendation,
            critical: $critical,
            high: $high,
            sca_medium: $sca_medium,
            secrets: $secrets,
            container_critical: $container_critical,
            container_high: $container_high,
            semgrep_high: $semgrep_high,
            semgrep_medium: $semgrep_medium,
            checkov_failed: $checkov_failed,
            dast_high: $dast_high,
            dast_medium: $dast_medium,
            dast_low: $dast_low,
            sonar_quality_gate: $sonar_quality_gate,
            sonar_bugs: $sonar_bugs,
            sonar_vulnerabilities: $sonar_vulnerabilities,
            sonar_hotspots: $sonar_hotspots,
            sonar_ncloc: $sonar_ncloc,
            sonar_security_rating: $sonar_security_rating,
            summary: $summary
          }' > /tmp/security-gate.json
        echo "security-gate payload pipeline_id=$(jq -r .pipeline_id /tmp/security-gate.json)"
        HTTP=$(curl -s -o /tmp/sg-resp.json -w "%{http_code}" -X POST "${BACKEND_URL}/api/security-gate" \
          -H "Content-Type: application/json" \
          -H "X-Pipeline-Secret: ${PIPELINE_SECRET}" \
          -d @/tmp/security-gate.json) || HTTP="000"
        echo "security-gate → HTTP $HTTP"
        cat /tmp/sg-resp.json 2>/dev/null || true
        [ "$HTTP" = "200" ] || echo "⚠ Backend security-gate non enregistré (HTTP $HTTP)"
      elif [ -n "${BACKEND_URL:-}" ]; then
        echo "⚠ APPLICATION_ID ou PIPELINE_SECRET manquant — ingestion security-gate ignorée"
      fi
  artifacts:
    paths:
      - final-report/recommendation.txt
      - final-report/summary.json
    expire_in: 7 days

# ──────────────────────────────────────────────────────────────────
# STAGE 10 · RAG – Alimentation du contexte IA (version robuste)
# ──────────────────────────────────────────────────────────────────
publish-ai-context:
  extends: .scan-rules
  stage: reporting
  image: alpine:latest
  needs:
    - clone-repository
    - aggregate-report
    - import-defectdojo
  allow_failure: true
  before_script:
    - apk add --no-cache curl jq git
  script:
    # Charger detected.env
    - |
      if [ -f detected.env ]; then
        . detected.env
      else
        echo "detected.env missing — using defaults"
        DETECTED_LANGUAGES="inconnus"
        PACKAGE_MANAGERS="inconnus"
      fi

    # Collecte des manifests
    - |
      MANIFEST_FILE=$(mktemp)
      for f in user-repo/package.json user-repo/pom.xml user-repo/build.gradle \
               user-repo/requirements.txt user-repo/pyproject.toml user-repo/go.mod \
               user-repo/Dockerfile; do
        if [ -f "$f" ]; then
          echo "### ${f#user-repo/} (extrait)" >> "$MANIFEST_FILE"
          echo '```' >> "$MANIFEST_FILE"
          head -c 600 "$f" >> "$MANIFEST_FILE"
          echo '```' >> "$MANIFEST_FILE"
          echo "" >> "$MANIFEST_FILE"
        fi
      done
      MANIFESTS=$(cat "$MANIFEST_FILE")
      rm -f "$MANIFEST_FILE"

    # Contexte markdown
    - |
      CONTEXT=$(cat <<-END
      ## Contexte pipeline (généré automatiquement)

      - Dépôt: ${GIT_REPO_URL}
      - Branche: ${GIT_BRANCH}
      - Langages détectés: ${DETECTED_LANGUAGES:-inconnus}
      - Gestionnaires de paquets: ${PACKAGE_MANAGERS:-inconnus}
      - Outils exécutés: semgrep, trivy, gitleaks, checkov, grype, hadolint, zap, sonarqube
      - Seuils quality gate: SCA crit=${SCA_CRITICAL_THRESHOLD} high=${SCA_HIGH_THRESHOLD} | Container crit=${CONTAINER_CRITICAL_THRESHOLD} high=${CONTAINER_HIGH_THRESHOLD} | Semgrep high=${SEMGREP_HIGH_THRESHOLD} medium=${SEMGREP_MEDIUM_THRESHOLD} | IaC failed=${IAC_FAILED_THRESHOLD}
      - Dockerfile: ${DOCKERFILE_PATH}

      ${MANIFESTS}
      END
      )

    # Envoi
    - |
      jq -n \
        --arg app "$APPLICATION_ID" \
        --arg env "$ENVIRONMENT_ID" \
        --arg br  "$GIT_BRANCH" \
        --arg ctx "$CONTEXT" \
        '{branch: $br, contextMarkdown: $ctx}
         + (if $app != "" then {applicationId: $app} else {} end)
         + (if $env != "" then {environmentId: $env} else {} end)' > payload.json

    - |
      echo "publish-ai-context → BACKEND_URL=${BACKEND_URL:-<non défini>}"
      if [ -z "$BACKEND_URL" ]; then
        echo "⚠ BACKEND_URL vide — définir la variable CI/CD GitLab (Settings → CI/CD → Variables)"
        exit 0
      fi
      if echo "$BACKEND_URL" | grep -qE 'host\.docker\.internal|localhost|127\.0\.0\.1'; then
        echo "⚠ BACKEND_URL injoignable depuis GitLab SaaS — contexte RAG ignoré"
        exit 0
      fi
      HTTP_CODE=$(curl -s -o response.json -w "%{http_code}" -X POST \
        "$BACKEND_URL/api/knowledge/pipeline-context" \
        -H "Content-Type: application/json" \
        -H "X-Pipeline-Secret: $PIPELINE_SECRET" \
        -d @payload.json) || {
          echo "⚠ curl exit $? — impossible de joindre $BACKEND_URL (tunnel actif ?)"
          exit 0
        }
      echo "Backend HTTP $HTTP_CODE"; cat response.json || true
      [ "$HTTP_CODE" = "200" ] || echo "⚠ Contexte RAG non publié (HTTP $HTTP_CODE, non bloquant)"

# ══════════════════════════════════════════════════════════════════
# DÉPLOIEMENT — jobs ACTION=deploy (rules explicites)
# ══════════════════════════════════════════════════════════════════
deploy:clone:
  stage: setup
  image: alpine:latest
  retry: 2
  rules:
    - if: '$ACTION == "deploy"'
  before_script:
    - apk add --no-cache git bash
  script:
    - test -n "$GIT_REPO_URL" || (echo "GIT_REPO_URL is required" && exit 1)
    - |
      DEPLOY_ID="${DEPLOYMENT_ID:-$ENVIRONMENT_ID}"
      NS="${NAMESPACE:-$K8S_NAMESPACE}"
      TAG="${IMAGE_TAG:-$DEPLOY_ID}"
      test -n "$DEPLOY_ID" || (echo "DEPLOYMENT_ID ou ENVIRONMENT_ID requis" && exit 1)
      echo "DEPLOY_ID=$DEPLOY_ID"   >  deploy.env
      echo "NS=$NS"                 >> deploy.env
      echo "TAG=$TAG"               >> deploy.env
      echo "IMAGE_NAME=${CI_REGISTRY_IMAGE}:${TAG}" >> deploy.env
      cat deploy.env
    - |
      if [ -n "$GITHUB_TOKEN" ]; then
        AUTH_URL=$(echo "$GIT_REPO_URL" | sed "s|https://|https://oauth2:${GITHUB_TOKEN}@|")
      else
        AUTH_URL="$GIT_REPO_URL"
      fi
      git clone --depth 1 --branch "$GIT_BRANCH" "$AUTH_URL" user-repo
    - chmod -R 777 user-repo
    - test -f "user-repo/${DOCKERFILE_PATH#./}" || echo "⚠ Dockerfile ${DOCKERFILE_PATH} introuvable — le build échouera"
  artifacts:
    reports:
      dotenv: deploy.env
    paths:
      - user-repo/
      - deploy.env
    expire_in: 2 hours

.deploy-docker-wait: &deploy-docker-wait |
  wait_for_docker() {
    TRIES=0
    while ! docker info >/dev/null 2>&1; do
      TRIES=$((TRIES + 1))
      if [ "$TRIES" -ge 40 ]; then
        echo "Docker indisponible après 2 minutes"
        docker info 2>&1 || true
        exit 1
      fi
      if [ -S /var/run/docker.sock ] && [ "${DOCKER_HOST:-}" != "unix:///var/run/docker.sock" ]; then
        echo "Bascule sur le socket Docker hôte (/var/run/docker.sock)"
        export DOCKER_HOST=unix:///var/run/docker.sock
        unset DOCKER_TLS_VERIFY DOCKER_CERT_PATH
      fi
      echo "Waiting for Docker daemon... ($TRIES/40)"
      sleep 3
    done
  }
  wait_for_docker

deploy:build-docker:
  stage: build
  image: docker:29.5.3
  services:
    - docker:29.5.3-dind
  retry: 2
  rules:
    - if: '$ACTION == "deploy" && $USE_KANIKO != "true" && $DOCKER_BUILD_MODE != "socket"'
  needs:
    - job: "deploy:clone"
      artifacts: true
  variables:
    DOCKER_HOST: tcp://docker:2376
    DOCKER_TLS_CERTDIR: "/certs"
    DOCKER_TLS_VERIFY: "1"
    DOCKER_CERT_PATH: "/certs/client"
  script:
    - *deploy-docker-wait
    - cd user-repo
    - docker build -f ${DOCKERFILE_PATH} -t ${IMAGE_NAME} "${BUILD_CONTEXT:-.}"
    - docker save -o ../image.tar ${IMAGE_NAME}
    - cd ..
    - echo "Image built ${IMAGE_NAME}"
  artifacts:
    paths:
      - image.tar
    expire_in: 2 hours

deploy:build-docker-host:
  stage: build
  image: docker:29.5.3
  retry: 2
  rules:
    - if: '$ACTION == "deploy" && $USE_KANIKO != "true" && $DOCKER_BUILD_MODE == "socket"'
  needs:
    - job: "deploy:clone"
      artifacts: true
  variables:
    DOCKER_HOST: unix:///var/run/docker.sock
  script:
    - *deploy-docker-wait
    - cd user-repo
    - docker build -f ${DOCKERFILE_PATH} -t ${IMAGE_NAME} "${BUILD_CONTEXT:-.}"
    - docker save -o ../image.tar ${IMAGE_NAME}
    - cd ..
    - echo "Image built ${IMAGE_NAME}"
  artifacts:
    paths:
      - image.tar
    expire_in: 2 hours

deploy:build-kaniko:
  stage: build
  image:
    name: gcr.io/kaniko-project/executor:debug
    entrypoint: [""]
  rules:
    - if: '$ACTION == "deploy" && $USE_KANIKO == "true"'
  needs:
    - job: "deploy:clone"
      artifacts: true
  script:
    - mkdir -p /kaniko/.docker
    - echo "{\"auths\":{\"${CI_REGISTRY}\":{\"auth\":\"$(printf '%s:%s' "$CI_REGISTRY_USER" "$CI_JOB_TOKEN" | base64 | tr -d '\n')\"}}}" > /kaniko/.docker/config.json
    - |
      /kaniko/executor \
        --context=dir://user-repo \
        --dockerfile=user-repo/${DOCKERFILE_PATH} \
        --destination="${IMAGE_NAME}" \
        --tarPath=image.tar
  artifacts:
    paths:
      - image.tar
    expire_in: 2 hours

deploy:grype-scan:
  stage: container-scan
  image: alpine:latest
  retry: 2
  rules:
    - if: '$ACTION == "deploy"'
  needs:
    - job: "deploy:clone"
      artifacts: true
    - job: "deploy:build-docker"
      artifacts: true
      optional: true
    - job: "deploy:build-docker-host"
      artifacts: true
      optional: true
    - job: "deploy:build-kaniko"
      artifacts: true
      optional: true
  before_script:
    - apk add --no-cache curl jq
    - curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin
  script:
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
      echo "Grype: CRITICAL=$CRIT HIGH=$HIGH (gate au stage security-validation)"
  artifacts:
    paths:
      - reports/container-scan/grype-image.json
    expire_in: 7 days
  allow_failure: true

deploy:push-image:
  stage: push-image
  image: docker:29.5.3
  services:
    - docker:29.5.3-dind
  retry: 2
  rules:
    - if: '$ACTION == "deploy" && $DOCKER_BUILD_MODE != "socket"'
  needs:
    - job: "deploy:clone"
      artifacts: true
    - job: "deploy:build-docker"
      artifacts: true
      optional: true
    - job: "deploy:build-docker-host"
      artifacts: true
      optional: true
    - job: "deploy:build-kaniko"
      artifacts: false
      optional: true
  variables:
    DOCKER_HOST: tcp://docker:2376
    DOCKER_TLS_CERTDIR: "/certs"
    DOCKER_TLS_VERIFY: "1"
    DOCKER_CERT_PATH: "/certs/client"
  script:
    - |
      if [ "$USE_KANIKO" = "true" ]; then
        echo "Kaniko a déjà poussé ${IMAGE_NAME} — no-op."
        exit 0
      fi
    - |
      if [ ! -f image.tar ]; then
        echo "No image.tar — nothing to push" && exit 1
      fi
    - *deploy-docker-wait
    - docker load -i image.tar
    - docker login -u "$CI_REGISTRY_USER" -p "$CI_JOB_TOKEN" "$CI_REGISTRY"
    - docker push ${IMAGE_NAME}
    - echo "Pushed ${IMAGE_NAME}"

deploy:push-image-host:
  stage: push-image
  image: docker:29.5.3
  retry: 2
  rules:
    - if: '$ACTION == "deploy" && $DOCKER_BUILD_MODE == "socket"'
  needs:
    - job: "deploy:clone"
      artifacts: true
    - job: "deploy:build-docker-host"
      artifacts: true
      optional: true
    - job: "deploy:build-docker"
      artifacts: true
      optional: true
    - job: "deploy:build-kaniko"
      artifacts: false
      optional: true
  variables:
    DOCKER_HOST: unix:///var/run/docker.sock
  script:
    - |
      if [ "$USE_KANIKO" = "true" ]; then
        echo "Kaniko a déjà poussé ${IMAGE_NAME} — no-op."
        exit 0
      fi
    - |
      if [ ! -f image.tar ]; then
        echo "No image.tar — nothing to push" && exit 1
      fi
    - *deploy-docker-wait
    - docker load -i image.tar
    - docker login -u "$CI_REGISTRY_USER" -p "$CI_JOB_TOKEN" "$CI_REGISTRY"
    - docker push ${IMAGE_NAME}
    - echo "Pushed ${IMAGE_NAME}"

deploy:trigger-backend:
  stage: deploy-k8s
  image: alpine:latest
  retry: 1
  rules:
    - if: '$ACTION == "deploy"'
  needs:
    - job: "deploy:clone"
      artifacts: true
    - job: "deploy:push-image"
      optional: true
    - job: "deploy:push-image-host"
      optional: true
    - job: "deploy:build-kaniko"
      optional: true
  before_script:
    - apk add --no-cache curl bash jq
  script:
    - |
      echo "deploy:trigger-backend → BACKEND_URL=${BACKEND_URL:-<non défini>}"
      test -n "$BACKEND_URL" || (echo "BACKEND_URL vide — définir la variable CI/CD GitLab" && exit 1)
      jq -n \
        --arg dep "$DEPLOYMENT_ID" --arg env "$ENVIRONMENT_ID" \
        --arg img "$IMAGE_NAME"    --arg ns  "$NS" \
        '{image: $img, namespace: $ns}
         + (if $dep != "" then {deploymentId: $dep} else {} end)
         + (if $env != "" then {environmentId: $env} else {} end)' > deploy-body.json
      echo "POST ${BACKEND_URL}/api/deploy (id=${DEPLOY_ID}, ns=${NS})"
      HTTP=$(curl -s -o deploy-resp.json -w "%{http_code}" -X POST "${BACKEND_URL}/api/deploy" \
        -H "Content-Type: application/json" \
        -H "X-Pipeline-Secret: ${PIPELINE_SECRET}" \
        -d @deploy-body.json)
      cat deploy-resp.json
      [ "$HTTP" = "200" ] || [ "$HTTP" = "202" ] || (echo "Backend a refusé le déploiement (HTTP $HTTP)" && exit 1)
    - |
      echo "Polling ${BACKEND_URL}/api/deploy/status/${DEPLOY_ID} ..."
      for i in $(seq 1 30); do
        STATUS=$(curl -s -H "X-Pipeline-Secret: ${PIPELINE_SECRET}" \
          "${BACKEND_URL}/api/deploy/status/${DEPLOY_ID}")
        READY=$(echo "$STATUS" | jq -r '.ready // false')
        STATE=$(echo "$STATUS" | jq -r '.status // "UNKNOWN"')
        echo "[$i/30] status=$STATE ready=$READY"
        if [ "$STATE" = "FAILED" ]; then
          echo "$STATUS" | jq -r '.message // "Déploiement en échec côté backend"'
          exit 1
        fi
        if [ "$READY" = "true" ]; then
          APP_URL=$(echo "$STATUS" | jq -r '.appUrl // empty')
          [ -n "$APP_URL" ] && echo "APP_URL=$APP_URL" > app.env && break
        fi
        sleep 10
      done
      [ -f app.env ] || (echo "Timeout : application non prête après 5 min." && exit 1)
      cat app.env
  artifacts:
    reports:
      dotenv: app.env
    paths:
      - app.env
    expire_in: 1 day

deploy:zap-dast:
  stage: zap-scan
  image: ghcr.io/zaproxy/zaproxy:stable
  rules:
    - if: '$ACTION == "deploy"'
  needs:
    - job: "deploy:trigger-backend"
      artifacts: true
  script:
    - mkdir -p reports/dast /zap/wrk
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
        -J zap-report.json \
        -x zap-report.xml \
        -I || true
    - cp /zap/wrk/zap-report.json reports/dast/zap-report.json 2>/dev/null || echo '{"site":[]}' > reports/dast/zap-report.json
    - cp /zap/wrk/zap-report.xml  reports/dast/zap-report.xml  2>/dev/null || true
  artifacts:
    paths:
      - reports/dast/zap-report.json
      - reports/dast/zap-report.xml
    expire_in: 7 days
  allow_failure: true

deploy:aggregate-report:
  stage: reporting
  image: alpine:latest
  rules:
    - if: '$ACTION == "deploy"'
  needs:
    - job: "deploy:clone"
      artifacts: true
    - job: "deploy:grype-scan"
      artifacts: true
    - job: "deploy:zap-dast"
      artifacts: true
    - job: "deploy:trigger-backend"
      artifacts: true
  before_script:
    - apk add --no-cache jq
  script:
    - mkdir -p final-report
    - |
      CONTAINER_CRITICAL=$(jq '[.matches[]?.vulnerability?.severity? | select(.=="Critical")] | length' reports/container-scan/grype-image.json 2>/dev/null || echo 0)
      CONTAINER_HIGH=$(jq '[.matches[]?.vulnerability?.severity? | select(.=="High")] | length'         reports/container-scan/grype-image.json 2>/dev/null || echo 0)
      DAST_HIGH=$(jq   '[.site[]?.alerts[]? | select(.riskcode=="3")] | length' reports/dast/zap-report.json 2>/dev/null || echo 0)
      DAST_MEDIUM=$(jq '[.site[]?.alerts[]? | select(.riskcode=="2")] | length' reports/dast/zap-report.json 2>/dev/null || echo 0)
      DAST_LOW=$(jq    '[.site[]?.alerts[]? | select(.riskcode=="1")] | length' reports/dast/zap-report.json 2>/dev/null || echo 0)
      jq -n \
        --arg env "${DEPLOY_ID}" --arg repo "$GIT_REPO_URL" --arg br "$GIT_BRANCH" \
        --arg pid "$CI_PIPELINE_ID" --arg url "${APP_URL:-}" --arg img "${IMAGE_NAME}" \
        --argjson cc "${CONTAINER_CRITICAL:-0}" --argjson ch "${CONTAINER_HIGH:-0}" \
        --argjson dh "${DAST_HIGH:-0}" --argjson dm "${DAST_MEDIUM:-0}" --argjson dl "${DAST_LOW:-0}" \
        '{deployment_id:$env, git_repository:$repo, git_branch:$br, pipeline_id:$pid,
          app_url:$url, image:$img,
          scan_date:(now | todate),
          container:{critical:$cc, high:$ch},
          dast:{high:$dh, medium:$dm, low:$dl},
          status:"completed"}' > final-report/summary.json
    - cat final-report/summary.json
  artifacts:
    paths:
      - reports/
      - final-report/summary.json
    expire_in: 7 days

deploy:defectdojo-import:
  stage: reporting
  image: alpine:latest
  rules:
    - if: '$ACTION == "deploy" && $DD_IMPORT_ENABLED == "true"'
  needs:
    - job: "deploy:clone"
      artifacts: true
    - job: "deploy:aggregate-report"
      artifacts: true
  before_script:
    - apk add --no-cache curl jq
  allow_failure: true
  script:
    - |
      [ -n "$DEFECTDOJO_URL" ] && [ -n "$DEFECTDOJO_TOKEN" ] || (echo "DefectDojo non configuré" && exit 0)
      case "${DEFECTDOJO_TOKEN}" in
        Token\ *) DOJO_AUTH="${DEFECTDOJO_TOKEN}" ;;
        *) DOJO_AUTH="Token ${DEFECTDOJO_TOKEN}" ;;
      esac
      REPO_NAME=$(basename "$GIT_REPO_URL" .git)
      ENGAGEMENT="${REPO_NAME}_${GIT_BRANCH}"
      dd_import() {
        FILE="$1"; SCAN_TYPE="$2"
        [ -s "$FILE" ] || { echo "skip $SCAN_TYPE (fichier vide)"; return 0; }
        curl -s -X POST "${DEFECTDOJO_URL}/api/v2/import-scan/" \
          -H "Authorization: ${DOJO_AUTH}" \
          -F "product_name=${REPO_NAME}" -F "engagement_name=${ENGAGEMENT}" \
          -F "auto_create_context=true" \
          -F "scan_type=${SCAN_TYPE}" -F "file=@${FILE}" \
          -F "tags=deploy" -F "tags=pipeline-${CI_PIPELINE_ID}" \
          -F "close_old_findings=true" -F "deduplication_on_engagement=true" \
          | jq -r '.test // .message // "import ok"'
      }
      dd_import reports/container-scan/grype-image.json "Anchore Grype"
      dd_import reports/dast/zap-report.xml            "ZAP Scan"

deploy:security-validation:
  stage: security-validation
  image: alpine:latest
  rules:
    - if: '$ACTION == "deploy"'
  needs:
    - job: "deploy:clone"
      artifacts: true
    - job: "deploy:aggregate-report"
      artifacts: true
  before_script:
    - apk add --no-cache jq curl
  script:
    - test -f final-report/summary.json || (echo "summary.json not found" && exit 1)
    - |
      CONTAINER_CRITICAL=$(jq '.container.critical' final-report/summary.json)
      CONTAINER_HIGH=$(jq    '.container.high'      final-report/summary.json)
      DAST_HIGH=$(jq         '.dast.high'           final-report/summary.json)
      DAST_MEDIUM=$(jq       '.dast.medium'         final-report/summary.json)
      GATE_PASSED=true; WARNINGS=""; BLOCKING=""
      fail() { echo "BLOCKING : $1"; GATE_PASSED=false; BLOCKING="${BLOCKING}${1}; "; }
      pass() { echo "OK       : $1"; }
      warn() { echo "WARNING  : $1"; WARNINGS="${WARNINGS}${1}; "; }
      [ "$CONTAINER_CRITICAL" -gt "${CONTAINER_CRITICAL_THRESHOLD}" ] \
        && fail "Container Critical: $CONTAINER_CRITICAL > ${CONTAINER_CRITICAL_THRESHOLD}" \
        || pass "Container Critical ($CONTAINER_CRITICAL <= ${CONTAINER_CRITICAL_THRESHOLD})"
      [ "$CONTAINER_HIGH" -gt "${CONTAINER_HIGH_THRESHOLD}" ] \
        && fail "Container High: $CONTAINER_HIGH > ${CONTAINER_HIGH_THRESHOLD}" \
        || pass "Container High ($CONTAINER_HIGH <= ${CONTAINER_HIGH_THRESHOLD})"
      [ "$DAST_HIGH" -gt "${DAST_HIGH_THRESHOLD}" ] \
        && fail "DAST High: $DAST_HIGH > ${DAST_HIGH_THRESHOLD}" \
        || pass "DAST High ($DAST_HIGH <= ${DAST_HIGH_THRESHOLD})"
      [ "$DAST_MEDIUM" -gt 10 ] && warn "DAST Medium: $DAST_MEDIUM (> 10)"
      if [ "$GATE_PASSED" = "true" ]; then
        [ -n "$WARNINGS" ] && RECOMMENDATION="DEPLOY_WITH_WARNINGS" || RECOMMENDATION="RECOMMANDE"
      else
        RECOMMENDATION="NON_RECOMMANDE"
      fi
      echo "VERDICT: $RECOMMENDATION"
      echo "$RECOMMENDATION" > final-report/recommendation.txt
    - |
      RECOMMENDATION=$(cat final-report/recommendation.txt)
      if [ -n "${BACKEND_URL:-}" ] && [ -n "${PIPELINE_SECRET:-}" ]; then
        jq -n \
          --arg deployment_id "${DEPLOYMENT_ID}" \
          --arg environment_id "${ENVIRONMENT_ID}" \
          --arg application_id "${APPLICATION_ID:-}" \
          --arg pipeline_id "${CI_PIPELINE_ID}" \
          --arg kind "deploy" \
          --arg recommendation "$RECOMMENDATION" \
          --argjson container_critical "$(jq '.container.critical' final-report/summary.json)" \
          --argjson container_high "$(jq '.container.high' final-report/summary.json)" \
          --argjson dast_high "$(jq '.dast.high' final-report/summary.json)" \
          --argjson dast_medium "$(jq '.dast.medium' final-report/summary.json)" \
          --argjson dast_low "$(jq '.dast.low' final-report/summary.json)" \
          --argjson summary "$(jq -c . final-report/summary.json)" \
          '{
            pipeline_id: $pipeline_id,
            kind: $kind,
            recommendation: $recommendation,
            container_critical: $container_critical,
            container_high: $container_high,
            dast_high: $dast_high,
            dast_medium: $dast_medium,
            dast_low: $dast_low,
            summary: $summary
          }
          + (if $application_id != "" then {application_id: $application_id} else {} end)
          + (if $deployment_id != "" then {deployment_id: $deployment_id} else {} end)
          + (if $environment_id != "" then {environment_id: $environment_id} else {} end)' > /tmp/security-gate.json
        HTTP=$(curl -s -o /tmp/sg-resp.json -w "%{http_code}" -X POST "${BACKEND_URL}/api/security-gate" \
          -H "Content-Type: application/json" \
          -H "X-Pipeline-Secret: ${PIPELINE_SECRET}" \
          -d @/tmp/security-gate.json) || HTTP="000"
        echo "security-gate → HTTP $HTTP"
        cat /tmp/sg-resp.json 2>/dev/null || true
        [ "$HTTP" = "200" ] || echo "⚠ Backend security-gate non enregistré (HTTP $HTTP)"
      else
        echo "⚠ BACKEND_URL ou PIPELINE_SECRET manquant — ingestion security-gate ignorée"
      fi
    - |
      RECOMMENDATION=$(cat final-report/recommendation.txt)
      if [ "$DEPLOY_GATE_ENFORCE" = "true" ] && [ "$RECOMMENDATION" = "NON_RECOMMANDE" ]; then
        echo "DEPLOY_GATE_ENFORCE=true → pipeline en échec (le backend peut déclencher un teardown)."
        exit 1
      fi
  artifacts:
    paths:
      - final-report/
    expire_in: 7 days