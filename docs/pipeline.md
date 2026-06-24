stages:
  - hello
  - clone
  - sonarqube-setup
  - sonarqube-scan
  - sca-trivy
  - sca-node
  - sca-python
  - sca-java
  - sast-generic
  - sast-angular
  - secrets
  - container
  - iac
  - license-node
  - license-python
  - build-image
  - container-scan
  - push-image
  - aggregate-report
  - import-defectdojo
  - security-validation

variables:
  GIT_REPO_URL: ""
  GIT_BRANCH: "main"
  GITHUB_TOKEN: ""
  ENVIRONMENT_ID: ""
  DOCKERFILE_PATH: "./Dockerfile"
  CRITICAL_THRESHOLD: "5"
  DEFECTDOJO_URL: ""
  DEFECTDOJO_TOKEN: ""

# ========================================
# STAGE 1 : HELLO
# ========================================
hello-world:
  stage: hello
  image: alpine:latest
  script:
    - echo "🚀 EnviroTest Multi-Language Pipeline"
    - echo "Environment ID = $ENVIRONMENT_ID"
    - echo "Repository     = $GIT_REPO_URL"
    - echo "Branch         = $GIT_BRANCH"

# ========================================
# STAGE 2 : CLONE
# ========================================
clone-repository:
  stage: clone
  image: alpine:latest
  before_script:
    - apk add --no-cache git bash
  script:
    - echo "📦 Cloning repository..."
    - test -n "$GIT_REPO_URL" || exit 1
    - |
      if [ -n "$GITHUB_TOKEN" ]; then
        AUTH_URL=$(echo "$GIT_REPO_URL" | sed "s|https://|https://oauth2:${GITHUB_TOKEN}@|")
      else
        AUTH_URL="$GIT_REPO_URL"
      fi
      git clone --depth 1 --branch "$GIT_BRANCH" "$AUTH_URL" user-repo
    - chmod -R 777 user-repo
    - echo "🔍 Detecting project languages..."
    - touch build.env
    - if [ -f "user-repo/package.json" ]; then echo "LANG_NODE=true" >> build.env; else echo "LANG_NODE=false" >> build.env; fi
    - if [ -f "user-repo/requirements.txt" ] || [ -f "user-repo/setup.py" ] || [ -f "user-repo/Pipfile" ]; then echo "LANG_PYTHON=true" >> build.env; else echo "LANG_PYTHON=false" >> build.env; fi
    - if [ -f "user-repo/pom.xml" ] || [ -f "user-repo/build.gradle" ]; then echo "LANG_JAVA=true" >> build.env; else echo "LANG_JAVA=false" >> build.env; fi
    - if [ -f "user-repo/go.mod" ]; then echo "LANG_GO=true" >> build.env; else echo "LANG_GO=false" >> build.env; fi
    - if [ -f "user-repo/Gemfile" ]; then echo "LANG_RUBY=true" >> build.env; else echo "LANG_RUBY=false" >> build.env; fi
    - if [ -f "user-repo/composer.json" ]; then echo "LANG_PHP=true" >> build.env; else echo "LANG_PHP=false" >> build.env; fi
    - if [ -f "user-repo/Cargo.toml" ]; then echo "LANG_RUST=true" >> build.env; else echo "LANG_RUST=false" >> build.env; fi
    - |
      if [ -f "user-repo/angular.json" ]; then
        echo "FRAMEWORK=angular" >> build.env
      elif grep -q '"react"' user-repo/package.json 2>/dev/null; then
        echo "FRAMEWORK=react" >> build.env
      elif [ -f "user-repo/vue.config.js" ]; then
        echo "FRAMEWORK=vue" >> build.env
      else
        echo "FRAMEWORK=unknown" >> build.env
      fi
    - if [ -f "user-repo/Dockerfile" ]; then echo "HAS_DOCKERFILE=true" >> build.env; else echo "HAS_DOCKERFILE=false" >> build.env; fi
    - |
      if find user-repo -name "*.tf" -o -name "*.yaml" -o -name "*.yml" | grep -q .; then
        echo "HAS_IAC=true" >> build.env
      else
        echo "HAS_IAC=false" >> build.env
      fi
    - cat build.env
  artifacts:
    paths:
      - user-repo/
      - build.env
    reports:
      dotenv: build.env
    expire_in: 2 hours

# ========================================
# STAGE 3a : SONARCLOUD SETUP
# ========================================
sonarqube-create-project:
  stage: sonarqube-setup
  image: alpine:latest
  needs: ["clone-repository"]
  before_script:
    - apk add --no-cache curl jq
  script:
    - |
      PROJECT_KEY=$(echo "${GIT_REPO_URL}" | sed -E 's|https?://||; s|\.git$||; s|/|_|g; s|[^a-zA-Z0-9_]|_|g')
      ORG="amanibennaceur-group"
      echo "📋 ProjectKey = ${PROJECT_KEY}"
      RESPONSE=$(curl -s -u "${SONAR_ADMIN_TOKEN}:" "https://sonarcloud.io/api/projects/search?organization=${ORG}&projects=${PROJECT_KEY}")
      EXISTS=$(echo "$RESPONSE" | jq -r '.components | length')
      if [ "$EXISTS" -eq 0 ]; then
        echo "📦 Création du projet SonarCloud: ${PROJECT_KEY}"
        curl -X POST -u "${SONAR_ADMIN_TOKEN}:" \
          "https://sonarcloud.io/api/projects/create" \
          -d "project=${PROJECT_KEY}" \
          -d "name=${PROJECT_KEY}" \
          -d "organization=${ORG}"
        echo "✅ Projet créé"
      else
        echo "✅ Projet existe déjà"
      fi
      GATE_NAME="Sonar way"
      curl -X POST -u "${SONAR_ADMIN_TOKEN}:" \
        "https://sonarcloud.io/api/qualitygates/select" \
        -d "projectKey=${PROJECT_KEY}" \
        -d "gateName=${GATE_NAME}"
      echo "✅ Quality Gate assigné"
      curl -X POST -u "${SONAR_ADMIN_TOKEN}:" \
        "https://sonarcloud.io/api/settings/set" \
        -d "key=sonar.newCodeDefinition" \
        -d "value=PREVIOUS_VERSION" \
        -d "component=${PROJECT_KEY}"
      echo "✅ New Code Definition configuré"
      echo "PROJECT_KEY=${PROJECT_KEY}" >> project.env
  artifacts:
    reports:
      dotenv: project.env
    expire_in: 1 hour

# ========================================
# STAGE 3b : SONARCLOUD SCAN
# ========================================
sonarqube-scan:
  stage: sonarqube-scan
  image: sonarsource/sonar-scanner-cli:latest
  needs:
    - job: clone-repository
    - job: sonarqube-create-project
  script:
    - echo "🔍 SonarQube Scan - ProjectKey = ${PROJECT_KEY}"
    - cd user-repo
    - |
      sonar-scanner \
        -Dsonar.projectKey="${PROJECT_KEY}" \
        -Dsonar.organization="amanibennaceur-group" \
        -Dsonar.sources=. \
        -Dsonar.host.url="https://sonarcloud.io" \
        -Dsonar.token="$SONAR_TOKEN" \
        -Dsonar.exclusions="**/node_modules/**,**/dist/**,**/target/**,**/build/**" \
        -Dsonar.coverage.exclusions="**/*.test.js,**/*.spec.js,**/test/**" \
        -Dsonar.scm.provider=git
    - cd ..
  allow_failure: true

# ========================================
# STAGE 4a : TRIVY (SCA - tous langages)
# ========================================
trivy-scan:
  stage: sca-trivy
  image: alpine:latest
  needs: ["clone-repository"]
  before_script:
    - apk add --no-cache curl
    - curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin
  script:
    - echo "🔍 Trivy - Universal Vulnerability Scanner"
    - mkdir -p reports/trivy
    - trivy fs --format json --output reports/trivy/trivy.json --severity CRITICAL,HIGH,MEDIUM user-repo/ || true
    - trivy fs --scanners vuln,secret,config --format json --output reports/trivy/trivy-full.json user-repo/ || true
  artifacts:
    paths:
      - reports/trivy/
  allow_failure: true

# ========================================
# STAGE 4b : NODE SCA
# ========================================
npm-audit:
  stage: sca-node
  image: node:18-alpine
  needs:
    - job: clone-repository
      artifacts: true
  script:
    - echo "🔍 NPM Audit for Node.js"
    - mkdir -p reports/node
    - if [ "$LANG_NODE" != "true" ]; then echo "⏭️  Skipping - Not a Node.js project"; exit 0; fi
    - cd user-repo
    - rm -rf node_modules package-lock.json 2>/dev/null || true
    - npm install --package-lock-only --silent || echo "⚠️ npm install failed"
    - |
      if [ -f "package-lock.json" ]; then
        npm audit --json > ../reports/node/npm-audit.json 2>&1 || true
      else
        echo '{"error":"No lockfile available"}' > ../reports/node/npm-audit.json
      fi
    - npm outdated --json > ../reports/node/npm-outdated.json 2>/dev/null || echo '{}' > ../reports/node/npm-outdated.json
    - cd ..
  artifacts:
    paths:
      - reports/node/
  allow_failure: true

# ========================================
# STAGE 4c : PYTHON SCA
# ========================================
pip-audit:
  stage: sca-python
  image: python:3.11-alpine
  needs:
    - job: clone-repository
      artifacts: true
  before_script:
    - pip install pip-audit safety --quiet
  script:
    - echo "🔍 Python Security Audit"
    - mkdir -p reports/python
    - if [ "$LANG_PYTHON" != "true" ]; then echo "⏭️  Skipping - Not a Python project"; exit 0; fi
    - cd user-repo
    - |
      if [ -f "requirements.txt" ]; then
        pip-audit --requirement requirements.txt --format json -o ../reports/python/pip-audit.json || true
        safety check --json --file requirements.txt > ../reports/python/safety.json || true
      fi
    - cd ..
  artifacts:
    paths:
      - reports/python/
  allow_failure: true

# ========================================
# STAGE 4d : JAVA SCA
# ========================================
maven-dependency-check:
  stage: sca-java
  image: maven:3.8-openjdk-17
  needs:
    - job: clone-repository
      artifacts: true
  script:
    - echo "🔍 Java/Maven Dependency Check"
    - mkdir -p reports/java
    - if [ "$LANG_JAVA" != "true" ]; then echo "⏭️  Skipping - Not a Java project"; exit 0; fi
    - cd user-repo
    - |
      if [ -f "pom.xml" ]; then
        mvn -q dependency:tree -DoutputFile=../reports/java/dependencies.txt || true
        mvn -q org.owasp:dependency-check-maven:check -Dformat=JSON -DoutputDirectory=../reports/java/ || true
      fi
    - cd ..
  artifacts:
    paths:
      - reports/java/
  allow_failure: true

# ========================================
# STAGE 5a : SEMGREP (SAST - tous langages)
# ========================================
semgrep-scan:
  stage: sast-generic
  image: returntocorp/semgrep:latest
  needs: ["clone-repository"]
  script:
    - echo "🔍 Semgrep - Multi-language SAST"
    - mkdir -p reports/sast
    - semgrep scan --config auto --json -o reports/sast/semgrep.json user-repo || true
  artifacts:
    paths:
      - reports/sast/
  allow_failure: true

# ========================================
# STAGE 5b : SAFE (ANGULAR/REACT)
# ========================================
safe-analysis:
  stage: sast-angular
  image: node:18-alpine
  needs:
    - job: clone-repository
      artifacts: true
  script:
    - echo "🔍 SAFE Analysis for Angular/React"
    - mkdir -p reports/sast
    - |
      if [ "$FRAMEWORK" != "angular" ] && [ "$FRAMEWORK" != "react" ]; then
        echo "⏭️  Skipping - Not an Angular/React project"
        exit 0
      fi
    - npm install -g @safe/cli || echo "⚠️ SAFE installation failed"
    - cd user-repo
    - |
      if [ "$FRAMEWORK" = "angular" ]; then
        npx @safe/cli scan:source --path . --format json > ../reports/sast/safe-report.json || true
        if [ -f "angular.json" ]; then
          npx ng lint --format json --output-file ../reports/sast/angular-lint.json || true
        fi
      elif [ "$FRAMEWORK" = "react" ]; then
        npx eslint . --ext .jsx,.tsx --format json > ../reports/sast/react-lint.json || true
      fi
    - cd ..
  artifacts:
    paths:
      - reports/sast/
  allow_failure: true

# ========================================
# STAGE 6 : GITLEAKS (SECRETS)
# ========================================
gitleaks-secrets:
  stage: secrets
  image: alpine:latest
  needs: ["clone-repository"]
  before_script:
    - apk add --no-cache git curl
    - curl -sSfL https://github.com/zricethezav/gitleaks/releases/download/v8.18.2/gitleaks_8.18.2_linux_x64.tar.gz | tar xz
    - mv gitleaks /usr/local/bin/
  script:
    - echo "🔍 Gitleaks - Secrets Scan"
    - mkdir -p reports/secrets
    - gitleaks detect --source user-repo --report-path reports/secrets/gitleaks.json --report-format json || true
  artifacts:
    paths:
      - reports/secrets/
  allow_failure: true

# ========================================
# STAGE 7 : CHECKOV (IaC)
# ========================================
checkov-scan:
  stage: iac
  image: python:3.11-alpine
  needs:
    - job: clone-repository
      artifacts: true
  before_script:
    - pip install checkov --quiet
  script:
    - echo "🔍 Checkov - IaC Scan"
    - mkdir -p reports/iac
    - |
      if [ "$HAS_IAC" != "true" ]; then
        echo "⏭️  Skipping - No IaC files found"
        echo '{"scanned": false}' > reports/iac/checkov.json
        exit 0
      fi
    - checkov --directory user-repo --output json --output-file-path reports/iac/checkov.json || true
  artifacts:
    paths:
      - reports/iac/
  allow_failure: true

# ========================================
# STAGE 8a : LICENSE NODE
# ========================================
license-node:
  stage: license-node
  image: node:18-alpine
  needs:
    - job: clone-repository
      artifacts: true
  script:
    - echo "🔍 License Scan (Node.js)"
    - mkdir -p reports/license/node
    - if [ "$LANG_NODE" != "true" ]; then echo "⏭️  Skipping - Not a Node.js project"; exit 0; fi
    - cd user-repo
    - npx license-checker --json > ../reports/license/node/license-node.json || echo '{"error":"license-checker failed"}' > ../reports/license/node/license-node.json
    - cd ..
  artifacts:
    paths:
      - reports/license/node/
  allow_failure: true

# ========================================
# STAGE 8b : LICENSE PYTHON
# ========================================
license-python:
  stage: license-python
  image: python:3.11-alpine
  needs:
    - job: clone-repository
      artifacts: true
  before_script:
    - pip install licensecheck --quiet
  script:
    - echo "🔍 License Scan (Python)"
    - mkdir -p reports/license/python
    - if [ "$LANG_PYTHON" != "true" ]; then echo "⏭️  Skipping - Not a Python project"; exit 0; fi
    - cd user-repo
    - licensecheck --format json --output ../reports/license/python/license-python.json . || echo '{"error":"licensecheck failed"}' > ../reports/license/python/license-python.json
    - cd ..
  artifacts:
    paths:
      - reports/license/python/
  allow_failure: true

# ========================================
# STAGE 9 : BUILD DOCKER IMAGE
# ========================================
build-docker-image:
  stage: build-image
  image: docker:latest
  services:
    - docker:dind
  needs:
    - job: clone-repository
      artifacts: true
  variables:
    DOCKER_HOST: tcp://docker:2375
    DOCKER_TLS_CERTDIR: ""
  script:
    - echo "🏗️ Building Docker image from ${DOCKERFILE_PATH}"
    - cd user-repo
    - IMAGE_NAME="${DOCKER_USERNAME}/envirotest-app:${ENVIRONMENT_ID}"
    - docker build -f ${DOCKERFILE_PATH} -t ${IMAGE_NAME} .
    - docker save -o ../image.tar ${IMAGE_NAME}
    - cd ..
    - echo "IMAGE_NAME=${IMAGE_NAME}" > image_name.env
  artifacts:
    paths:
      - image.tar
      - image_name.env
    expire_in: 2 hours

# ========================================
# STAGE 10 : CONTAINER SCAN (TRIVY)
# ========================================
trivy-image-scan:
  stage: container-scan
  image: docker:latest
  services:
    - docker:dind
  needs: ["build-docker-image"]
  variables:
    DOCKER_HOST: tcp://docker:2375
    DOCKER_TLS_CERTDIR: ""
  script:
    - apk add --no-cache curl
    - curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin
    - docker load -i image.tar
    - mkdir -p reports/container-scan
    - trivy image --severity CRITICAL,HIGH --format json --output reports/container-scan/trivy-image.json ${DOCKER_USERNAME}/envirotest-app:${ENVIRONMENT_ID} || true
  artifacts:
    paths:
      - reports/container-scan/
    expire_in: 1 day
  allow_failure: true

# ========================================
# STAGE 11 : PUSH IMAGE
# ========================================
push-docker-image:
  stage: push-image
  image: docker:latest
  services:
    - docker:dind
  needs:
    - job: build-docker-image
      artifacts: true
  variables:
    DOCKER_HOST: tcp://docker:2375
    DOCKER_TLS_CERTDIR: ""
  script:
    - |
      echo "📤 Loading and pushing image to Docker Hub"
      docker load -i image.tar
      . image_name.env
      echo "$DOCKER_ACCESS_TOKEN" | docker login -u "$DOCKER_USERNAME" --password-stdin
      docker push ${IMAGE_NAME}
      echo "✅ Image pushed: ${IMAGE_NAME}"

# ========================================
# STAGE 12 : AGGREGATE REPORT
# ========================================
aggregate-report:
  stage: aggregate-report
  image: alpine:latest
  needs:
    - clone-repository
    - trivy-scan
    - npm-audit
    - pip-audit
    - maven-dependency-check
    - semgrep-scan
    - safe-analysis
    - gitleaks-secrets
    - checkov-scan
    - license-node
    - license-python
    - trivy-image-scan
  before_script:
    - apk add --no-cache curl jq
  script:
    - echo "📊 Aggregating security reports"
    - mkdir -p final-report
    - source build.env 2>/dev/null || true
    - |
      CRITICAL=0; HIGH=0; MEDIUM=0; LOW=0
      if [ -f reports/trivy/trivy.json ]; then
        CRITICAL=$(jq '[.Results[]?.Vulnerabilities[]? | select(.Severity=="CRITICAL")] | length' reports/trivy/trivy.json 2>/dev/null || echo 0)
        HIGH=$(jq '[.Results[]?.Vulnerabilities[]? | select(.Severity=="HIGH")] | length' reports/trivy/trivy.json 2>/dev/null || echo 0)
        MEDIUM=$(jq '[.Results[]?.Vulnerabilities[]? | select(.Severity=="MEDIUM")] | length' reports/trivy/trivy.json 2>/dev/null || echo 0)
        LOW=$(jq '[.Results[]?.Vulnerabilities[]? | select(.Severity=="LOW")] | length' reports/trivy/trivy.json 2>/dev/null || echo 0)
      fi
    - |
      CONTAINER_CRITICAL=0; CONTAINER_HIGH=0
      if [ -f reports/container-scan/trivy-image.json ]; then
        CONTAINER_CRITICAL=$(jq '[.Results[]?.Vulnerabilities[]? | select(.Severity=="CRITICAL")] | length' reports/container-scan/trivy-image.json 2>/dev/null || echo 0)
        CONTAINER_HIGH=$(jq '[.Results[]?.Vulnerabilities[]? | select(.Severity=="HIGH")] | length' reports/container-scan/trivy-image.json 2>/dev/null || echo 0)
      fi
    - |
      TOTAL_CRITICAL=$((CRITICAL + CONTAINER_CRITICAL))
      TOTAL_HIGH=$((HIGH + CONTAINER_HIGH))
    - |
      cat > final-report/summary.json << EOF
      {
        "environment_id": "$ENVIRONMENT_ID",
        "git_repository": "$GIT_REPO_URL",
        "git_branch": "$GIT_BRANCH",
        "pipeline_id": "$CI_PIPELINE_ID",
        "languages_detected": {
          "node": ${LANG_NODE:-false},
          "python": ${LANG_PYTHON:-false},
          "java": ${LANG_JAVA:-false},
          "go": ${LANG_GO:-false},
          "ruby": ${LANG_RUBY:-false},
          "php": ${LANG_PHP:-false},
          "rust": ${LANG_RUST:-false}
        },
        "framework": "${FRAMEWORK:-unknown}",
        "has_dockerfile": ${HAS_DOCKERFILE:-false},
        "has_iac": ${HAS_IAC:-false},
        "vulnerabilities": {
          "critical": ${TOTAL_CRITICAL},
          "high": ${TOTAL_HIGH},
          "medium": ${MEDIUM},
          "low": ${LOW}
        },
        "container_vulnerabilities": {
          "critical": ${CONTAINER_CRITICAL},
          "high": ${CONTAINER_HIGH}
        },
        "status": "completed",
        "reports_url": "$CI_JOB_URL/artifacts"
      }
      EOF
    - echo "📄 Summary:"
    - cat final-report/summary.json
    - |
      if [ -n "$BACKEND_URL" ]; then
        curl -X POST "${BACKEND_URL}/projet/api/deploy" \
          -H "Content-Type: application/json" \
          -H "Authorization: Bearer ${API_TOKEN}" \
          -d @final-report/summary.json || echo "⚠️ Notification failed"
      else
        echo "⚠️ BACKEND_URL not set, skipping notification"
      fi
    - echo "✅ Aggregate report created"
  artifacts:
    paths:
      - reports/
      - final-report/
    expire_in: 7 days

# ========================================
# STAGE 13 : IMPORT DEFECTDOJO
# ========================================
import-defectdojo:
  stage: import-defectdojo
  image: alpine:latest
  needs:
    - aggregate-report
  before_script:
    - apk add --no-cache curl jq
  script:
    - |
      echo "📤 Importing findings to DefectDojo"
      if [ -z "$DEFECTDOJO_URL" ] || [ -z "$DEFECTDOJO_TOKEN" ]; then
        echo "⚠️ DefectDojo not configured. Skipping."
        exit 0
      fi

      # =============================================
      # NAMING STRATEGY
      # Produit    = nom du repo  (ex: my-app)
      # Engagement = repo_branche (ex: my-app_main)
      #            → chaque branche a son propre engagement
      #            → même repo = même produit = comparaison possible
      # =============================================
      REPO_NAME=$(echo "${GIT_REPO_URL}" | sed -E 's|.*/||; s|\.git$||')
      PRODUCT_NAME="${REPO_NAME}"
      ENGAGEMENT_NAME="${REPO_NAME}_${GIT_BRANCH}"

      echo "Product    : $PRODUCT_NAME"
      echo "Engagement : $ENGAGEMENT_NAME"
      echo "Branch     : $GIT_BRANCH"

      # =============================================
      # RÉCUPÉRER LE PROD_TYPE (obligatoire)
      # =============================================
      PROD_TYPE_ID=$(curl -s -H "Authorization: ${DEFECTDOJO_TOKEN}" \
        "${DEFECTDOJO_URL}/api/v2/product_types/" \
        | jq -r '.results[0].id // empty')

      if [ -z "$PROD_TYPE_ID" ]; then
        echo "❌ No product type found in DefectDojo."
        exit 1
      fi
      echo "Product type ID: $PROD_TYPE_ID"

      # =============================================
      # VÉRIFIER / CRÉER LE PRODUIT
      # =============================================
      PRODUCT_ID=$(curl -s -H "Authorization: ${DEFECTDOJO_TOKEN}" \
        "${DEFECTDOJO_URL}/api/v2/products/?name=${PRODUCT_NAME}" \
        | jq -r '.results[0].id // empty')

      if [ -z "$PRODUCT_ID" ]; then
        echo "🆕 Creating product '$PRODUCT_NAME'..."
        PRODUCT_ID=$(curl -s -X POST "${DEFECTDOJO_URL}/api/v2/products/" \
          -H "Authorization: ${DEFECTDOJO_TOKEN}" \
          -H "Content-Type: application/json" \
          -d "{
            \"name\": \"$PRODUCT_NAME\",
            \"description\": \"Repo: ${GIT_REPO_URL}\",
            \"prod_type\": $PROD_TYPE_ID
          }" | jq -r '.id // empty')
        echo "✅ Product created: $PRODUCT_ID"
      else
        echo "✅ Product exists: $PRODUCT_ID"
      fi

      if [ -z "$PRODUCT_ID" ] || [ "$PRODUCT_ID" = "null" ]; then
        echo "❌ Failed to get product ID."
        exit 1
      fi

      # =============================================
      # VÉRIFIER / CRÉER L'ENGAGEMENT (par branche)
      # =============================================
      TODAY=$(date +%Y-%m-%d)
      END_DATE=$(awk 'BEGIN{t=systime()+2592000; print strftime("%Y-%m-%d", t)}')

      ENGAGEMENT_ID=$(curl -s -H "Authorization: ${DEFECTDOJO_TOKEN}" \
        "${DEFECTDOJO_URL}/api/v2/engagements/?product=${PRODUCT_ID}&name=${ENGAGEMENT_NAME}" \
        | jq -r '.results[0].id // empty')

      if [ -z "$ENGAGEMENT_ID" ]; then
        echo "🆕 Creating engagement '$ENGAGEMENT_NAME'..."
        ENGAGEMENT_ID=$(curl -s -X POST "${DEFECTDOJO_URL}/api/v2/engagements/" \
          -H "Authorization: ${DEFECTDOJO_TOKEN}" \
          -H "Content-Type: application/json" \
          -d "{
            \"name\": \"$ENGAGEMENT_NAME\",
            \"product\": $PRODUCT_ID,
            \"target_start\": \"$TODAY\",
            \"target_end\": \"$END_DATE\",
            \"status\": \"In Progress\",
            \"engagement_type\": \"CI/CD\",
            \"branch_tag\": \"$GIT_BRANCH\",
            \"description\": \"Branch: $GIT_BRANCH | Repo: $GIT_REPO_URL\"
          }" | jq -r '.id // empty')
        echo "✅ Engagement created: $ENGAGEMENT_ID"
      else
        echo "✅ Engagement exists: $ENGAGEMENT_ID"
      fi

      if [ -z "$ENGAGEMENT_ID" ] || [ "$ENGAGEMENT_ID" = "null" ]; then
        echo "❌ Failed to get engagement ID."
        exit 1
      fi

      # =============================================
      # SMART IMPORT : import si nouveau, reimport si existant
      # Noms exacts des scan_type supportés par DefectDojo
      # =============================================
      smart_import() {
        FILE=$1
        SCAN_TYPE=$2
        LABEL=$3

        if [ ! -f "$FILE" ]; then
          echo "⏭️  Skipping [$LABEL] - file not found: $FILE"
          return
        fi

        # Vérifier si un test de ce type existe déjà dans cet engagement
        ENCODED_TYPE=$(echo "$SCAN_TYPE" | sed 's/ /%20/g')
        TEST_ID=$(curl -s -H "Authorization: ${DEFECTDOJO_TOKEN}" \
          "${DEFECTDOJO_URL}/api/v2/tests/?engagement=${ENGAGEMENT_ID}&scan_type=${ENCODED_TYPE}" \
          | jq -r '.results[0].id // empty')

        if [ -z "$TEST_ID" ]; then
          echo "🆕 IMPORT [$LABEL] (first scan on this branch)..."
          RESULT=$(curl -s -X POST "${DEFECTDOJO_URL}/api/v2/import-scan/" \
            -H "Authorization: ${DEFECTDOJO_TOKEN}" \
            -F "product_name=$PRODUCT_NAME" \
            -F "engagement_name=$ENGAGEMENT_NAME" \
            -F "scan_type=$SCAN_TYPE" \
            -F "file=@$FILE" \
            -F "auto_create_context=true" \
            -F "close_old_findings=false")
        else
          echo "🔄 REIMPORT [$LABEL] (test_id=$TEST_ID) - comparing with previous scan..."
          RESULT=$(curl -s -X POST "${DEFECTDOJO_URL}/api/v2/reimport-scan/" \
            -H "Authorization: ${DEFECTDOJO_TOKEN}" \
            -F "test=$TEST_ID" \
            -F "scan_type=$SCAN_TYPE" \
            -F "file=@$FILE" \
            -F "close_old_findings=true" \
            -F "push_to_jira=false")
        fi

        STATUS=$(echo "$RESULT" | jq -r '.test // .detail // "unknown"')
        echo "   → Result: $STATUS"
      }

      # =============================================
      # IMPORTS PAR TECHNOLOGIE
      # Noms exacts DefectDojo (case-sensitive)
      # =============================================

      echo ""
      echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
      echo "🔐 SCA - Dependencies"
      echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
      # Trivy filesystem scan (tous langages)
      smart_import "reports/trivy/trivy.json" \
        "Trivy Scan" \
        "Trivy FS"

      # Node.js - npm audit
      smart_import "reports/node/npm-audit.json" \
        "NPM Audit Scan" \
        "NPM Audit"

      # Python - pip-audit
      smart_import "reports/python/pip-audit.json" \
        "pip-audit Scan" \
        "pip-audit"

      # Java - OWASP Dependency Check
      smart_import "reports/java/dependency-check-report.json" \
        "Dependency Check Scan" \
        "OWASP Dependency Check"

      echo ""
      echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
      echo "🔎 SAST - Code Analysis"
      echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
      # Semgrep (tous langages)
      smart_import "reports/sast/semgrep.json" \
        "Semgrep JSON Report" \
        "Semgrep"

      echo ""
      echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
      echo "🔑 Secrets Detection"
      echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
      # Gitleaks
      smart_import "reports/secrets/gitleaks.json" \
        "Gitleaks Scan" \
        "Gitleaks"

      echo ""
      echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
      echo "🏗️  IaC Security"
      echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
      # Checkov
      smart_import "reports/iac/checkov.json" \
        "Checkov Scan" \
        "Checkov"

      echo ""
      echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
      echo "🐳 Container Security"
      echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
      # Trivy container image scan
      smart_import "reports/container-scan/trivy-image.json" \
        "Trivy Scan" \
        "Trivy Container"

      echo ""
      echo "✅ DefectDojo import completed."
      echo "🔗 Dashboard: ${DEFECTDOJO_URL}/product/${PRODUCT_ID}/finding/open"
  allow_failure: true

# ========================================
# STAGE 14 : SECURITY VALIDATION
# ========================================
security-validation:
  stage: security-validation
  image: alpine:latest
  needs:
    - aggregate-report
    - import-defectdojo
  before_script:
    - apk add --no-cache jq
  script:
    - |
      echo "🔒 Security Quality Gate"
      if [ ! -f final-report/summary.json ]; then
        echo "❌ Summary report not found"
        exit 1
      fi
      CRITICAL=$(jq '.vulnerabilities.critical' final-report/summary.json)
      HIGH=$(jq '.vulnerabilities.high' final-report/summary.json)
      MEDIUM=$(jq '.vulnerabilities.medium' final-report/summary.json)
      LOW=$(jq '.vulnerabilities.low' final-report/summary.json)
      echo "Critical : $CRITICAL"
      echo "High     : $HIGH"
      echo "Medium   : $MEDIUM"
      echo "Low      : $LOW"
      if [ "$CRITICAL" -gt "${CRITICAL_THRESHOLD:-5}" ]; then
        echo "❌ Quality gate FAILED: $CRITICAL critical vulnerabilities (threshold: ${CRITICAL_THRESHOLD:-5})"
        echo "Deploiement NON RECOMMANDE"
        echo "NON_RECOMMANDE" > final-report/recommendation.txt
      else
        echo "✅ Quality gate PASSED: $CRITICAL critical vulnerabilities (≤ ${CRITICAL_THRESHOLD:-5})"
        echo "Deploiement RECOMMANDE"
        echo "RECOMMANDE" > final-report/recommendation.txt
      fi
  artifacts:
    paths:
      - final-report/recommendation.txt
      - final-report/summary.json
    expire_in: 7 days
