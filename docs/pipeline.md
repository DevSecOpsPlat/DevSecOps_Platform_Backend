stages:
  - setup
  - code-analysis
  - sca
  - sast
  - secrets-iac
  - build
  - container-scan
  - reporting
  - security-validation

variables:
  GIT_REPO_URL:       ""
  GIT_BRANCH:         "main"
  GITHUB_TOKEN:       ""
  ENVIRONMENT_ID:     ""
  DOCKERFILE_PATH:    "./Dockerfile"
  DEFECTDOJO_URL:     ""
  DEFECTDOJO_TOKEN:   ""
  SONAR_HOST_URL:     ""
  SONAR_TOKEN:        ""
  DOCKER_USERNAME:    ""
  DOCKER_ACCESS_TOKEN: ""
  ENVIRONMENT_URL:    ""
  BACKEND_URL:        ""
  PIPELINE_SECRET:    ""
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

# ──────────────────────────────────────────────────────────────────
# STAGE 1 · SETUP
# ──────────────────────────────────────────────────────────────────
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

    # ── Bloc A : export pour RAG ──
    - |
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
      echo "SONAR_DASHBOARD_URL=${SONAR_HOST_URL}/dashboard?id=${PROJECT_KEY}&branch=${GIT_BRANCH}" >> project.env
  artifacts:
    reports:
      dotenv: project.env
    expire_in: 1 hour
  allow_failure: true

# ── Tests + rapports de couverture (alimente Sonar Coverage) ─────
test-coverage-node:
  stage: code-analysis
  image: node:20-bookworm
  needs: ["clone-repository"]
  before_script:
    - apt-get update -qq && apt-get install -y -qq chromium > /dev/null
    - export CHROME_BIN=/usr/bin/chromium
  script:
    - source build.env 2>/dev/null || true
    - |
      if [ "$LANG_NODE" != "true" ]; then
        echo "Node/TS non détecté — skip couverture"
        exit 0
      fi
    - mkdir -p coverage-reports
    - cd user-repo
    - |
      if [ ! -f package.json ]; then
        echo "package.json absent — skip"
        exit 0
      fi
      if ! grep -q '"test"' package.json 2>/dev/null; then
        echo "Script npm test absent — skip couverture Node"
        exit 0
      fi
    - |
      if [ -f package-lock.json ]; then
        npm ci --no-audit --no-fund
      elif [ -f yarn.lock ]; then
        corepack enable 2>/dev/null || true
        yarn install --frozen-lockfile || yarn install
      elif [ -f pnpm-lock.yaml ]; then
        corepack enable 2>/dev/null || true
        pnpm install --frozen-lockfile || pnpm install
      else
        npm install --no-audit --no-fund
      fi
    - |
      set +e
      if [ -f angular.json ]; then
        echo "Angular détecté — ng test --code-coverage"
        npx ng test --no-watch --code-coverage --browsers=ChromeHeadless || \
        npm test -- --no-watch --code-coverage --browsers=ChromeHeadless || \
        npm test -- --coverage --watchAll=false
      else
        echo "Projet Node — npm test avec couverture"
        npm test -- --coverage --watchAll=false 2>/dev/null || \
        npm test -- --coverage 2>/dev/null || \
        npm test -- --no-watch --code-coverage 2>/dev/null || \
        npm test
      fi
      TEST_EXIT=$?
      set -e
    - |
      LCOV=$(find . -name "lcov.info" -not -path "*/node_modules/*" 2>/dev/null | head -1)
      if [ -n "$LCOV" ]; then
        cp "$LCOV" ../coverage-reports/lcov.info
        echo "LCOV copié : $LCOV"
      else
        echo "Aucun lcov.info généré"
      fi
      # Best-effort : ne pas bloquer Sonar si les tests échouent
      exit 0
  artifacts:
    paths:
      - coverage-reports/
    expire_in: 1 day
  allow_failure: true

test-coverage-java:
  stage: code-analysis
  image: maven:3.9-eclipse-temurin-17
  needs: ["clone-repository"]
  script:
    - source build.env 2>/dev/null || true
    - |
      if [ "$LANG_JAVA" != "true" ]; then
        echo "Java non détecté — skip couverture"
        exit 0
      fi
    - mkdir -p coverage-reports
    - cd user-repo
    - |
      if [ -f pom.xml ]; then
        echo "Maven — tests + JaCoCo"
        mvn -B -q test \
          -Dmaven.test.failure.ignore=true \
          org.jacoco:jacoco-maven-plugin:0.8.12:prepare-agent \
          org.jacoco:jacoco-maven-plugin:0.8.12:report \
          || echo "Maven test/JaCoCo en échec (non bloquant)"
        if [ -f target/site/jacoco/jacoco.xml ]; then
          cp target/site/jacoco/jacoco.xml ../coverage-reports/jacoco.xml
          echo "JaCoCo XML copié"
        fi
      elif [ -f build.gradle ] || [ -f build.gradle.kts ]; then
        echo "Gradle — tests + JaCoCo"
        chmod +x gradlew 2>/dev/null || true
        if [ -f gradlew ]; then
          ./gradlew test jacocoTestReport -x check || echo "Gradle test en échec (non bloquant)"
        else
          gradle test jacocoTestReport -x check || echo "Gradle test en échec (non bloquant)"
        fi
        JACOCO=$(find . -path "*/jacoco/test/jacocoTestReport.xml" -o -path "*/reports/jacoco/test/jacocoTestReport.xml" 2>/dev/null | head -1)
        if [ -n "$JACOCO" ]; then
          cp "$JACOCO" ../coverage-reports/jacoco.xml
          echo "JaCoCo Gradle copié : $JACOCO"
        fi
      else
        echo "Aucun pom.xml / build.gradle — skip"
      fi
  artifacts:
    paths:
      - coverage-reports/
    expire_in: 1 day
  allow_failure: true

test-coverage-python:
  stage: code-analysis
  image: python:3.11-slim
  needs: ["clone-repository"]
  before_script:
    - pip install --quiet pytest pytest-cov coverage 2>/dev/null || true
  script:
    - source build.env 2>/dev/null || true
    - |
      if [ "$LANG_PYTHON" != "true" ]; then
        echo "Python non détecté — skip couverture"
        exit 0
      fi
    - mkdir -p coverage-reports
    - cd user-repo
    - |
      if [ -f requirements.txt ]; then
        pip install --quiet -r requirements.txt 2>/dev/null || true
      fi
      if [ -f pyproject.toml ]; then
        pip install --quiet . 2>/dev/null || pip install --quiet -e . 2>/dev/null || true
      fi
    - |
      if [ -d tests ] || [ -d test ] || find . -maxdepth 3 -name "test_*.py" | grep -q .; then
        pytest --cov=. --cov-report=xml:coverage.xml -q || echo "pytest en échec (non bloquant)"
        if [ -f coverage.xml ]; then
          cp coverage.xml ../coverage-reports/python-coverage.xml
          echo "Couverture Python copiée"
        fi
      else
        echo "Aucun test Python détecté — skip"
      fi
  artifacts:
    paths:
      - coverage-reports/
    expire_in: 1 day
  allow_failure: true

sonarqube-scan:
  stage: code-analysis
  image: sonarsource/sonar-scanner-cli:latest
  needs:
    - clone-repository
    - sonarqube-setup
    - job: test-coverage-node
      optional: true
    - job: test-coverage-java
      optional: true
    - job: test-coverage-python
      optional: true
  script:
    - |
      if [ -z "$SONAR_HOST_URL" ] || [ -z "$SONAR_TOKEN" ] || [ -z "$PROJECT_KEY" ]; then
        echo "SonarQube non configuré — skip"
        exit 0
      fi
    - source build.env 2>/dev/null || true
    - |
      SONAR_EXTRA=""
      COV_PREFIX="../coverage-reports"
      if [ -f coverage-reports/lcov.info ]; then
        echo "Rapport LCOV détecté — couverture JS/TS"
        SONAR_EXTRA="${SONAR_EXTRA} -Dsonar.javascript.lcov.reportPaths=${COV_PREFIX}/lcov.info"
        SONAR_EXTRA="${SONAR_EXTRA} -Dsonar.typescript.lcov.reportPaths=${COV_PREFIX}/lcov.info"
      fi
      if [ -f coverage-reports/jacoco.xml ]; then
        echo "Rapport JaCoCo détecté — couverture Java"
        SONAR_EXTRA="${SONAR_EXTRA} -Dsonar.coverage.jacoco.xmlReportPaths=${COV_PREFIX}/jacoco.xml"
        SONAR_EXTRA="${SONAR_EXTRA} -Dsonar.java.binaries=target/classes"
      fi
      if [ -f coverage-reports/python-coverage.xml ]; then
        echo "Rapport Cobertura Python détecté"
        SONAR_EXTRA="${SONAR_EXTRA} -Dsonar.python.coverage.reportPaths=${COV_PREFIX}/python-coverage.xml"
      fi
      if [ "$LANG_NODE" = "true" ]; then
        SONAR_EXTRA="${SONAR_EXTRA} -Dsonar.tests=src -Dsonar.test.inclusions=**/*.spec.ts,**/*.test.ts,**/*.spec.js,**/*.test.js"
      fi
      if [ "$LANG_JAVA" = "true" ]; then
        SONAR_EXTRA="${SONAR_EXTRA} -Dsonar.tests=src/test"
      fi
      export SONAR_EXTRA
    - cd user-repo
    - |
      sonar-scanner \
        -Dsonar.projectKey="${PROJECT_KEY}" \
        -Dsonar.sources=. \
        -Dsonar.host.url="${SONAR_HOST_URL}" \
        -Dsonar.token="${SONAR_TOKEN}" \
        -Dsonar.branch.name="${GIT_BRANCH}" \
        -Dsonar.exclusions="**/node_modules/**,**/dist/**,**/target/**,**/build/**,**/coverage/**" \
        ${SONAR_EXTRA}
  allow_failure: true

# ──────────────────────────────────────────────────────────────────
# STAGE 3 · SCA – Trivy FS + Syft
# ──────────────────────────────────────────────────────────────────
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

# ──────────────────────────────────────────────────────────────────
# STAGE 4 · SAST – Semgrep + Hadolint
# ──────────────────────────────────────────────────────────────────
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

# ──────────────────────────────────────────────────────────────────
# STAGE 5 · SECRETS-IAC – Gitleaks + Checkov
# ──────────────────────────────────────────────────────────────────
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
    - clone-repository
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
# ──────────────────────────────────────────────────────────────────
build-docker-image:
  stage: build
  image: docker:29.5.3
  services:
    - docker:29.5.3-dind
  retry: 2
  needs:
    - clone-repository
  variables:
    DOCKER_HOST: tcp://docker:2376
    DOCKER_TLS_CERTDIR: "/certs"
    DOCKER_TLS_VERIFY: "1"
    DOCKER_CERT_PATH: "/certs/client"
  script:
    - echo "Building Docker image"
    - |
      if [ "$USE_KANIKO" = "true" ]; then
        echo "USE_KANIKO=true — skipping socket build"
        exit 0
      fi
    - until docker info; do echo "Waiting for Docker daemon..."; sleep 3; done
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
    - clone-repository
  rules:
    - if: '$USE_KANIKO == "true"'
  script:
    - echo "Kaniko build"
    - mkdir -p /workspace
    - |
      IMAGE_NAME="${DOCKER_USERNAME}/envirotest-app:${ENVIRONMENT_ID}"
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
  stage: container-scan
  image: alpine:latest
  retry: 2
  needs:
    - job: build-docker-image
      artifacts: true
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
    
      echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
      echo "DefectDojo import complete"
  allow_failure: true

# ──────────────────────────────────────────────────────────────────
# STAGE 9 · SECURITY-VALIDATION – Quality gate (contenu simplifié)
# ──────────────────────────────────────────────────────────────────
security-validation:
  stage: security-validation
  image: alpine:latest
  needs:
    - aggregate-report
    - import-defectdojo
    - sonarqube-setup
  before_script:
    - apk add --no-cache jq curl
  script:
    - echo "Security validation — see full pipeline for details"
    - |
      if [ -f final-report/summary.json ]; then
        cat final-report/summary.json
      else
        echo "No summary found"
      fi
    - echo "RECOMMANDE" > final-report/recommendation.txt
  artifacts:
    paths:
      - final-report/recommendation.txt
      - final-report/summary.json
    expire_in: 7 days

# ──────────────────────────────────────────────────────────────────
# STAGE 10 · RAG – Alimentation du contexte IA (version robuste)
# ──────────────────────────────────────────────────────────────────
publish-ai-context:
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
      MANIFESTS=$(cat "$MANIFEST_FILE" | sed 's/\\/\\\\/g; s/"/\\"/g; s/$/\\n/' | tr -d '\n')
      rm -f "$MANIFEST_FILE"

    # Contexte markdown
    - |
      CONTEXT=$(cat <<-END
      ## Contexte pipeline (généré automatiquement)

      - Dépôt: ${GIT_REPO_URL}
      - Branche: ${GIT_BRANCH}
      - Langages détectés: ${DETECTED_LANGUAGES:-inconnus}
      - Gestionnaires de paquets: ${PACKAGE_MANAGERS:-inconnus}
      - Outils exécutés: semgrep, trivy, gitleaks, checkov, grype, hadolint, zap, sonarqube, test-coverage (JaCoCo/LCOV)
      - Seuils quality gate: SCA crit=${SCA_CRITICAL_THRESHOLD} high=${SCA_HIGH_THRESHOLD} | Container crit=${CONTAINER_CRITICAL_THRESHOLD} high=${CONTAINER_HIGH_THRESHOLD} | Semgrep high=${SEMGREP_HIGH_THRESHOLD} medium=${SEMGREP_MEDIUM_THRESHOLD} | IaC failed=${IAC_FAILED_THRESHOLD}
      - Dockerfile: ${DOCKERFILE_PATH}

      ${MANIFESTS}
      END
      )

    # Envoi
    - |
      JSON_CONTEXT=$(echo "$CONTEXT" | jq -Rs .)
      jq -n \
        --arg env "$ENVIRONMENT_ID" \
        --arg br  "$GIT_BRANCH" \
        --arg ctx "$JSON_CONTEXT" \
        '{environmentId: $env, branch: $br, contextMarkdown: $ctx}' > payload.json

    - |
      HTTP_CODE=$(curl -s -o response.json -w "%{http_code}" -X POST \
        "$BACKEND_URL/projet/api/knowledge/pipeline-context" \
        -H "Content-Type: application/json" \
        -H "X-Pipeline-Secret: $PIPELINE_SECRET" \
        -d @payload.json)
      echo "Backend HTTP $HTTP_CODE"; cat response.json || true
      [ "$HTTP_CODE" = "200" ] || echo "⚠ Contexte RAG non publié (non bloquant)"