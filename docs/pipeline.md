# EnviroTest — pipeline multi-langage (GitLab CI)
#
# SonarCloud : un projet par environnement
#   projectKey = EnviroTest_${ENVIRONMENT_ID}  (ne remplace plus amanibennaceur-group_EnviroTest)
# Variables CI masquees : SONAR_TOKEN, GITHUB_TOKEN, API_TOKEN, BACKEND_URL
# sonar.qualitygate.wait=true : le job attend le Quality Gate → exit 1 si QG FAILED (comportement voulu).
#   Ce n'est PAS une panne CI : ouvrir le lien dashboard dans les logs, corriger le code, ou assouplir le QG
#   dans SonarCloud (Quality Gates / projet). Pour ne pas faire echouer le job : retirer qualitygate.wait
#   ou mettre SONAR_QUALITYGATE_WAIT=false (voir variables du job).
# sonar.scm.disabled=true : analyse simple sans historique Git (evite refs main/master / new code).
#
# Tree-sitter / IaC Shell : le moteur (apres JRE provisioning) ignore souvent SONAR_SCANNER_OPTS.
#   Mettre JAVA_TOOL_OPTIONS en variables: du job (env heritee par toutes les JVM) + mkdir .tree-sitter ;
#   secours : /home/scanner-cli/.tree-sitter/lib (user.home par defaut de l'image).
#
# Option allow_failure sur sonarqube-scan : true = pipeline continue ; le job reste rouge si QG KO.


stages:
  - hello
  - clone
  - sonarqube
  - sca-trivy
  - sca-node
  - sca-python
  - sca-java
  - sca-owasp
  - sast-generic
  - sast-angular
  - secrets
  - container
  - iac
  - license-node
  - license-python
  - report

variables:
  GIT_REPO_URL: ""
  GIT_BRANCH: "main"
  GITHUB_TOKEN: ""
  ENVIRONMENT_ID: ""

# ========================================
# STAGE 1 : HELLO
# ========================================
hello-world:
  stage: hello
  image: alpine:latest
  script:
    - echo "🚀 EnviroTest Multi-Language Pipeline"
    - echo "Environment ID = $ENVIRONMENT_ID"
    - echo "Repository = $GIT_REPO_URL"
    - echo "Branch = $GIT_BRANCH"

# ========================================
# STAGE 2 : CLONE + DÉTECTION LANGAGES / FRAMEWORKS / IAC
# ========================================
clone-repository:
  stage: clone
  image: alpine:latest
  before_script:
    - apk add --no-cache git bash
  script:
    - echo "📦 Cloning repository with multi-language detection"
    - test -n "$GIT_REPO_URL" || exit 1

    # Clone avec éventuel token GitHub
    - |
      if [ -n "$GITHUB_TOKEN" ]; then
        AUTH_URL=$(echo "$GIT_REPO_URL" | sed "s|https://|https://oauth2:${GITHUB_TOKEN}@|")
      else
        AUTH_URL="$GIT_REPO_URL"
      fi
      git clone --depth 1 --branch "$GIT_BRANCH" "$AUTH_URL" user-repo

    - chmod -R 777 user-repo

    # Détection des langages
    - echo "🔍 Detecting project languages..."
    - touch build.env

    # Node.js
    - if [ -f "user-repo/package.json" ]; then
        echo "LANG_NODE=true" >> build.env;
        echo "  ✅ Node.js detected";
      else
        echo "LANG_NODE=false" >> build.env;
      fi

    # Python
    - if [ -f "user-repo/requirements.txt" ] || [ -f "user-repo/setup.py" ] || [ -f "user-repo/Pipfile" ]; then
        echo "LANG_PYTHON=true" >> build.env;
        echo "  ✅ Python detected";
      else
        echo "LANG_PYTHON=false" >> build.env;
      fi

    # Java
    - if [ -f "user-repo/pom.xml" ] || [ -f "user-repo/build.gradle" ]; then
        echo "LANG_JAVA=true" >> build.env;
        echo "  ✅ Java detected";
      else
        echo "LANG_JAVA=false" >> build.env;
      fi

    # Go
    - if [ -f "user-repo/go.mod" ]; then
        echo "LANG_GO=true" >> build.env;
        echo "  ✅ Go detected";
      else
        echo "LANG_GO=false" >> build.env;
      fi

    # Ruby
    - if [ -f "user-repo/Gemfile" ]; then
        echo "LANG_RUBY=true" >> build.env;
        echo "  ✅ Ruby detected";
      else
        echo "LANG_RUBY=false" >> build.env;
      fi

    # PHP
    - if [ -f "user-repo/composer.json" ]; then
        echo "LANG_PHP=true" >> build.env;
        echo "  ✅ PHP detected";
      else
        echo "LANG_PHP=false" >> build.env;
      fi

    # Rust
    - if [ -f "user-repo/Cargo.toml" ]; then
        echo "LANG_RUST=true" >> build.env;
        echo "  ✅ Rust detected";
      else
        echo "LANG_RUST=false" >> build.env;
      fi

    # Détection framework Frontend
    - |
      if [ -f "user-repo/angular.json" ]; then
        echo "FRAMEWORK=angular" >> build.env
        echo "  ✅ Angular framework detected"
      elif grep -q '"react"' user-repo/package.json 2>/dev/null; then
        echo "FRAMEWORK=react" >> build.env
        echo "  ✅ React framework detected"
      elif [ -f "user-repo/vue.config.js" ]; then
        echo "FRAMEWORK=vue" >> build.env
        echo "  ✅ Vue framework detected"
      else
        echo "FRAMEWORK=unknown" >> build.env
      fi

    # Détection Dockerfile
    - if [ -f "user-repo/Dockerfile" ]; then
        echo "HAS_DOCKERFILE=true" >> build.env;
        echo "  ✅ Dockerfile detected";
      else
        echo "HAS_DOCKERFILE=false" >> build.env;
      fi

    # Détection IaC
    - |
      if find user-repo -name "*.tf" -o -name "*.yaml" -o -name "*.yml" | grep -q .; then
        echo "HAS_IAC=true" >> build.env
        echo "  ✅ IaC files detected"
      else
        echo "HAS_IAC=false" >> build.env
      fi

    - echo "📋 Build environment:"
    - cat build.env

  artifacts:
    paths:
      - user-repo/
      - build.env
    reports:
      dotenv: build.env
    expire_in: 2 hours

# ========================================
# STAGE 3 : SONARQUBE — projet par ENVIRONMENT_ID + Quality Gate
# ========================================
sonarqube-scan:
  stage: sonarqube
  image: sonarsource/sonar-scanner-cli:latest
  needs: ["clone-repository"]
  variables:
    # Herite par toutes les JVM (CLI + moteur provisionne) — ne pas seulement export dans le shell
    JAVA_TOOL_OPTIONS: "-Duser.home=$CI_PROJECT_DIR/.sonar-scanner-home"
  before_script:
    - |
      SCANNER_HOME="${CI_PROJECT_DIR}/.sonar-scanner-home"
      mkdir -p "${SCANNER_HOME}/.tree-sitter/lib"
      export SONAR_SCANNER_OPTS="${SONAR_SCANNER_OPTS:-} -Duser.home=${SCANNER_HOME}"
      mkdir -p /home/scanner-cli/.tree-sitter/lib 2>/dev/null || true
      chmod -R a+rwx /home/scanner-cli/.tree-sitter 2>/dev/null || true
      if command -v apt-get >/dev/null 2>&1; then
        apt-get update -qq && apt-get install -y -qq curl
      elif command -v apk >/dev/null 2>&1; then
        apk add --no-cache curl
      fi
  script:
    - |
      set -e
      test -n "$ENVIRONMENT_ID" || (echo "ENVIRONMENT_ID is required" && exit 1)
      PROJ="EnviroTest_${ENVIRONMENT_ID}"
      echo "SonarCloud project key: ${PROJ}"
      RESP=$(curl -s -w "\n%{http_code}" -X POST "https://sonarcloud.io/api/projects/create" \
        -H "Authorization: Bearer ${SONAR_TOKEN}" \
        -d "project=${PROJ}" \
        -d "organization=amanibennaceur-group" \
        -d "name=${PROJ}" \
        -d "visibility=private")
      BODY=$(echo "$RESP" | head -n -1)
      CODE=$(echo "$RESP" | tail -n1)
      echo "projects/create HTTP ${CODE}"
      if [ "$CODE" != "200" ] && ! echo "$BODY" | grep -qiE 'already exists|key is already taken|already been taken'; then
        echo "Warning: create returned ${CODE} — continue if project already exists in SonarCloud"
      fi
      cd user-repo
      # SONAR_QUALITYGATE_WAIT=false dans GitLab CI pour desactiver l'attente QG (job vert meme si QG KO)
      QG_WAIT="${SONAR_QUALITYGATE_WAIT:-true}"
      sonar-scanner \
        -Dsonar.projectKey="${PROJ}" \
        -Dsonar.organization=amanibennaceur-group \
        -Dsonar.projectName="${PROJ}" \
        -Dsonar.sources=. \
        -Dsonar.host.url=https://sonarcloud.io \
        -Dsonar.token="${SONAR_TOKEN}" \
        -Dsonar.qualitygate.wait="${QG_WAIT}" \
        -Dsonar.scm.disabled=true \
        -Dsonar.exclusions='**/node_modules/**,**/dist/**,**/target/**,**/build/**' \
        -Dsonar.coverage.exclusions='**/*.test.js,**/*.spec.js,**/test/**'
      cd ..
  allow_failure: true


# ========================================
# STAGE 4a : TRIVY (Universal SCA)
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
    - trivy fs --security-checks vuln,secret,config --format json --output reports/trivy/trivy-full.json user-repo/ || true
  artifacts:
    paths:
      - reports/trivy/
  allow_failure: true

# ========================================
# STAGE 4b : NODE SCA - NE S'EXÉCUTE QUE POUR NODE.JS
# ========================================
npm-audit:
  stage: sca-node
  image: node:18-alpine
  needs:
    - job: clone-repository
      artifacts: true
  script:
    - echo "🔍 NPM/Yarn Audit for Node.js"
    - mkdir -p reports/node
    
    # Vérifier si c'est un projet Node.js
    - if [ "$LANG_NODE" != "true" ]; then
        echo "⏭️  Skipping - Not a Node.js project";
        exit 0;
      fi
    
    - cd user-repo
    - echo "✅ Node.js project detected, running npm audit"
    - npm audit --json > ../reports/node/npm-audit.json || echo '{"error":"npm audit failed"}' > ../reports/node/npm-audit.json
    - npm outdated --json > ../reports/node/npm-outdated.json || true
    - cd ..
  artifacts:
    paths:
      - reports/node/
  allow_failure: true

# ========================================
# STAGE 4c : PYTHON SCA - NE S'EXÉCUTE QUE POUR PYTHON
# ========================================
pip-audit:
  stage: sca-python
  image: python:3.11-alpine
  needs:
    - job: clone-repository
      artifacts: true
  before_script:
    - pip install pip-audit safety
  script:
    - echo "🔍 Python Security Audit"
    - mkdir -p reports/python
    
    # Vérifier si c'est un projet Python
    - if [ "$LANG_PYTHON" != "true" ]; then
        echo "⏭️  Skipping - Not a Python project";
        exit 0;
      fi
    
    - cd user-repo
    - echo "✅ Python project detected, running security audit"
    - if [ -f "requirements.txt" ]; then
        pip-audit --requirement requirements.txt --format json > ../reports/python/pip-audit.json || true;
        safety check --json --file requirements.txt --output ../reports/python/safety.json || true;
      fi
    - cd ..
  artifacts:
    paths:
      - reports/python/
  allow_failure: true

# ========================================
# STAGE 4d : JAVA SCA - NE S'EXÉCUTE QUE POUR JAVA
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
    
    # Vérifier si c'est un projet Java
    - if [ "$LANG_JAVA" != "true" ]; then
        echo "⏭️  Skipping - Not a Java project";
        exit 0;
      fi
    
    - cd user-repo
    - echo "✅ Java project detected, running dependency check"
    - if [ -f "pom.xml" ]; then
        mvn -q dependency:tree -DoutputFile=../reports/java/dependencies.txt || true;
        mvn -q org.owasp:dependency-check-maven:check -Dformat=JSON -DoutputDirectory=../reports/java/ || true;
      fi
    - cd ..
  artifacts:
    paths:
      - reports/java/
  allow_failure: true

# ========================================
# STAGE 4e : OWASP (Universal SCA)
# ========================================
owasp-dependency-check:
  stage: sca-owasp
  image: alpine:latest
  needs: ["clone-repository"]
  before_script:
    - apk add --no-cache openjdk17-jre curl unzip
    - curl -sSLo dependency-check.zip https://github.com/jeremylong/DependencyCheck/releases/download/v10.0.3/dependency-check-10.0.3-release.zip
    - unzip -q dependency-check.zip
  script:
    - echo "🔍 OWASP Dependency-Check - Universal SCA (peut être long)"
    - mkdir -p reports/owasp
    - ./dependency-check/bin/dependency-check.sh --project "$ENVIRONMENT_ID" --format JSON --out reports/owasp --scan user-repo --enableExperimental --disableAssembly || true
  artifacts:
    paths:
      - reports/owasp/
  allow_failure: true

# ========================================
# STAGE 5a : SEMGREP (Universal SAST)
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
# STAGE 5b : SAFE - NE S'EXÉCUTE QUE POUR ANGULAR/REACT
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
    
    # Vérifier le framework
    - |
      if [ "$FRAMEWORK" != "angular" ] && [ "$FRAMEWORK" != "react" ]; then
        echo "⏭️  Skipping - Not an Angular/React project (framework: $FRAMEWORK)"
        exit 0
      fi
    
    - npm install -g @safe/cli || echo "⚠️ SAFE installation failed"
    - cd user-repo
    
    - |
      if [ "$FRAMEWORK" = "angular" ]; then
        echo "✅ Angular project detected"
        npx @safe/cli scan:source --path . --format json > ../reports/sast/safe-report.json || true
        if [ -f "angular.json" ]; then
          npx ng lint --format json --output-file ../reports/sast/angular-lint.json || true
        fi
      elif [ "$FRAMEWORK" = "react" ]; then
        echo "✅ React project detected"
        npx eslint . --ext .jsx,.tsx --format json > ../reports/sast/react-lint.json || true
      fi
    - cd ..
  artifacts:
    paths:
      - reports/sast/
  allow_failure: true

# ========================================
# STAGE 6 : GITLEAKS (Secrets)
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
# STAGE 7 : GRYPE - NE S'EXÉCUTE QUE SI DOCKERFILE
# ========================================
grype-scan:
  stage: container
  image: docker:latest
  services:
    - docker:dind
  needs:
    - job: clone-repository
      artifacts: true
  before_script:
    - apk add --no-cache curl
    - curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin
  script:
    - echo "🔍 Grype - Container Image Scan"
    - mkdir -p reports/container
    - |
      if [ "$HAS_DOCKERFILE" != "true" ]; then
        echo "⏭️  Skipping - No Dockerfile found"
        echo '{"scanned": false}' > reports/container/grype.json
        exit 0
      fi
    - |
      cd user-repo
      echo "✅ Dockerfile found, building and scanning image"
      docker build -t app-image:$ENVIRONMENT_ID .
      grype app-image:$ENVIRONMENT_ID --output json --file ../reports/container/grype.json || true
      cd ..
  artifacts:
    paths:
      - reports/container/
  allow_failure: true

# ========================================
# STAGE 8 : CHECKOV - NE S'EXÉCUTE QUE SI IAC
# ========================================
checkov-scan:
  stage: iac
  image: python:3.11-alpine
  needs:
    - job: clone-repository
      artifacts: true
  before_script:
    - pip install checkov
  script:
    - echo "🔍 Checkov - IaC Scan"
    - mkdir -p reports/iac
    - |
      if [ "$HAS_IAC" != "true" ]; then
        echo "⏭️  Skipping - No IaC files found"
        echo '{"scanned": false}' > reports/iac/checkov.json
        exit 0
      fi
    - |
      echo "✅ IaC files found, running Checkov"
      checkov --directory user-repo --output json --output-file-path reports/iac/checkov.json || true
  artifacts:
    paths:
      - reports/iac/
  allow_failure: true

# ========================================
# STAGE 9a : LICENSE NODE
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
    
    # Vérifier si c'est un projet Node
    - if [ "$LANG_NODE" != "true" ]; then
        echo "⏭️  Skipping - Not a Node.js project";
        exit 0;
      fi
    
    - cd user-repo
    - echo "✅ Node.js project detected, scanning licenses"
    - npx license-checker --json > ../reports/license/node/license-node.json || echo '{"error":"license-checker failed"}' > ../reports/license/node/license-node.json
    - cd ..
  artifacts:
    paths:
      - reports/license/node/
  allow_failure: true

# ========================================
# STAGE 9b : LICENSE PYTHON
# ========================================
license-python:
  stage: license-python
  image: python:3.11-alpine
  needs:
    - job: clone-repository
      artifacts: true
  before_script:
    - pip install licensecheck
  script:
    - echo "🔍 License Scan (Python)"
    - mkdir -p reports/license/python
    
    # Vérifier si c'est un projet Python
    - if [ "$LANG_PYTHON" != "true" ]; then
        echo "⏭️  Skipping - Not a Python project";
        exit 0;
      fi
    
    - cd user-repo
    - echo "✅ Python project detected, scanning licenses"
    - licensecheck --format json --output ../reports/license/python/license-python.json . || echo '{"error":"licensecheck failed"}' > ../reports/license/python/license-python.json
    - cd ..
  artifacts:
    paths:
      - reports/license/python/
  allow_failure: true

# ========================================
# STAGE 10 : REPORT / AGGREGATION
# ========================================
aggregate-report:
  stage: report
  image: alpine:latest
  needs:
    - clone-repository
    - sonarqube-scan
    - trivy-scan
    - npm-audit
    - pip-audit
    - maven-dependency-check
    - owasp-dependency-check
    - semgrep-scan
    - safe-analysis
    - gitleaks-secrets
    - grype-scan
    - checkov-scan
    - license-node
    - license-python
  before_script:
    - apk add --no-cache curl jq
  script:
    - echo "📊 Aggregating security reports"
    - mkdir -p final-report

    # Charger les variables depuis build.env
    - source build.env 2>/dev/null || true

    # Générer le résumé avec valeurs par défaut
    - |
      cat > final-report/summary.json << EOF
      {
        "environment_id": "$ENVIRONMENT_ID",
        "sonar_project_key": "EnviroTest_${ENVIRONMENT_ID}",
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
        "status": "completed",
        "reports_url": "$CI_JOB_URL/artifacts"
      }
      EOF

    - echo "📄 Summary:"
    - cat final-report/summary.json

    - echo "📧 Sending notification to backend"
    - |
      if [ -n "$BACKEND_URL" ]; then
        curl -X POST "${BACKEND_URL}/projet/api/deploy" \
          -H "Content-Type: application/json" \
          -H "Authorization: Bearer ${API_TOKEN}" \
          -d @final-report/summary.json || echo "⚠️ Notification failed"
      else
        echo "⚠️ BACKEND_URL not set, skipping notification"
      fi

    - echo "✅ Pipeline completed successfully"
  artifacts:
    paths:
      - reports/
      - final-report/