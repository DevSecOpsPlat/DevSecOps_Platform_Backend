stages:
  - hello
  - clone
  - sonarqube-setup
  - sonarqube-scan
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
  - build-image
  - container-scan       
  - push-image
  - deploy-k8s
  - schedule-delete
  - report

variables:
  GIT_REPO_URL: ""
  GIT_BRANCH: "main"
  GITHUB_TOKEN: ""
  ENVIRONMENT_ID: ""
  K8S_NAMESPACE: ""
  DOCKERFILE_PATH: "./Dockerfile"
  TTL_HOURS: "4"

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

    # Détection des langages (Node, Python, Java, Go, Ruby, PHP, Rust)
    - if [ -f "user-repo/package.json" ]; then echo "LANG_NODE=true" >> build.env; else echo "LANG_NODE=false" >> build.env; fi
    - if [ -f "user-repo/requirements.txt" ] || [ -f "user-repo/setup.py" ] || [ -f "user-repo/Pipfile" ]; then echo "LANG_PYTHON=true" >> build.env; else echo "LANG_PYTHON=false" >> build.env; fi
    - if [ -f "user-repo/pom.xml" ] || [ -f "user-repo/build.gradle" ]; then echo "LANG_JAVA=true" >> build.env; else echo "LANG_JAVA=false" >> build.env; fi
    - if [ -f "user-repo/go.mod" ]; then echo "LANG_GO=true" >> build.env; else echo "LANG_GO=false" >> build.env; fi
    - if [ -f "user-repo/Gemfile" ]; then echo "LANG_RUBY=true" >> build.env; else echo "LANG_RUBY=false" >> build.env; fi
    - if [ -f "user-repo/composer.json" ]; then echo "LANG_PHP=true" >> build.env; else echo "LANG_PHP=false" >> build.env; fi
    - if [ -f "user-repo/Cargo.toml" ]; then echo "LANG_RUST=true" >> build.env; else echo "LANG_RUST=false" >> build.env; fi

    # Détection framework frontend
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
# STAGE 3a : CRÉATION DU PROJET + ASSIGNATION QUALITY GATE
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

      # Vérifier/créer le projet
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

      # Assigner Quality Gate "Sonar way"
      GATE_NAME="Sonar way"
      curl -X POST -u "${SONAR_ADMIN_TOKEN}:" \
        "https://sonarcloud.io/api/qualitygates/select" \
        -d "projectKey=${PROJECT_KEY}" \
        -d "gateName=${GATE_NAME}"
      echo "✅ Quality Gate '${GATE_NAME}' assigné"

      # Définir New Code Definition via l'API settings (valable pour la prochaine analyse)
      echo "📋 Configuration New Code Definition : PREVIOUS_VERSION"
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
# STAGE 3b : ANALYSE SONARCLOUD
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
# STAGE 4b : NODE SCA
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
    - if [ "$LANG_NODE" != "true" ]; then echo "⏭️  Skipping - Not a Node.js project"; exit 0; fi
    - cd user-repo
    - echo "✅ Node.js project detected"
    - rm -rf node_modules package-lock.json 2>/dev/null || true
    - echo "📦 Installing dependencies..."
    - npm install --package-lock-only --silent || echo "⚠️ npm install failed"
    - |
      if [ -f "package-lock.json" ]; then
        echo "🔍 Running npm audit with lockfile..."
        npm audit --json > ../reports/node/npm-audit.json 2>&1 || {
          echo "⚠️ npm audit failed, checking if vulnerabilities exist..."
          npm audit --json --dry-run > ../reports/node/npm-audit.json 2>&1 || true
        }
      else
        echo "❌ No package-lock.json generated, skipping audit"
        echo '{"error":"No lockfile available"}' > ../reports/node/npm-audit.json
      fi
    - npm outdated --json > ../reports/node/npm-outdated.json 2>/dev/null || echo '{}' > ../reports/node/npm-outdated.json
    - |
      echo "📊 Generating vulnerability summary..."
      cat > ../reports/node/vulnerability-summary.json << EOF
      {
        "outdated_packages": $(cat ../reports/node/npm-outdated.json | wc -l),
        "angular_version": "$(cat ../reports/node/npm-outdated.json | grep @angular | head -1 | cut -d'"' -f2 || echo 'unknown')",
        "recommendation": "Update Angular from 16 to 19 to fix known CVEs"
      }
      EOF
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
    - pip install pip-audit safety
  script:
    - echo "🔍 Python Security Audit"
    - mkdir -p reports/python
    - if [ "$LANG_PYTHON" != "true" ]; then echo "⏭️  Skipping - Not a Python project"; exit 0; fi
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
# STAGE 5b : SAFE - ANGULAR/REACT
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
# STAGE 7 : CHECKOV (IaC)
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
    - echo "✅ Node.js project detected, scanning licenses"
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
    - pip install licensecheck
  script:
    - echo "🔍 License Scan (Python)"
    - mkdir -p reports/license/python
    - if [ "$LANG_PYTHON" != "true" ]; then echo "⏭️  Skipping - Not a Python project"; exit 0; fi
    - cd user-repo
    - echo "✅ Python project detected, scanning licenses"
    - licensecheck --format json --output ../reports/license/python/license-python.json . || echo '{"error":"licensecheck failed"}' > ../reports/license/python/license-python.json
    - cd ..
  artifacts:
    paths:
      - reports/license/python/
  allow_failure: true

# ========================================
# STAGE 9 : BUILD IMAGE DOCKER
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
# STAGE 10 : SCAN DE L'IMAGE DOCKER (Trivy)
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
# STAGE 11 : PUSH IMAGE DOCKER
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
# STAGE 12 : DÉPLOIEMENT SUR KUBERNETES (HTTPS)
# ========================================
deploy-to-kubernetes:
  stage: deploy-k8s
  image: alpine:3.18
  tags:
    - k8s-deployer
  needs:
    - job: push-docker-image
    - job: clone-repository
      artifacts: true
  before_script:
    - apk add --no-cache curl jq gettext openssh-client
    - curl -LO "https://dl.k8s.io/release/v1.28.0/bin/linux/amd64/kubectl"
    - chmod +x kubectl
    - mv kubectl /usr/local/bin/
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
    - kubectl version --client=true || true
  script:
    - |
      echo "🚀 Deploying to Kubernetes namespace ${K8S_NAMESPACE}"
      kubectl create namespace ${K8S_NAMESPACE} --dry-run=client -o yaml | \
        kubectl annotate --local -f - janitor/ttl=${TTL_HOURS}h -o yaml | \
        kubectl apply -f -

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

      cat > ingress.yaml << EOF
      apiVersion: networking.k8s.io/v1
      kind: Ingress
      metadata:
        name: app-${ENVIRONMENT_ID}-ingress
        namespace: ${K8S_NAMESPACE}
        annotations:
          kubernetes.io/ingress.class: nginx
          nginx.ingress.kubernetes.io/ssl-redirect: "true"
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

      kubectl apply -f deployment.yaml
      kubectl apply -f service.yaml
      kubectl apply -f ingress.yaml
      kubectl rollout status deployment/app-${ENVIRONMENT_ID} -n ${K8S_NAMESPACE} --timeout=5m

      INGRESS_HTTPS_PORT=$(kubectl get svc -n ingress-nginx ingress-nginx-controller -o jsonpath='{.spec.ports[?(@.name=="https")].nodePort}')
      if [ -z "$INGRESS_HTTPS_PORT" ]; then
        INGRESS_HTTPS_PORT="443"
      fi
      echo "✅ Application deployed successfully!"
      echo "🌐 Access it at: https://app-${ENVIRONMENT_ID}.${K8S_MASTER_IP}.nip.io:${INGRESS_HTTPS_PORT}"
      echo "   (Use TLS with auto‑signed certificate – accept the security warning)"

# ========================================
# STAGE 13 : SUPPRESSION PLANIFIÉE DE L'IMAGE DOCKER
# ========================================
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
        cat > ~/delete-image-${ENVIRONMENT_ID}.sh << 'EOF'
        #!/bin/bash
        DOCKER_USERNAME=\"${DOCKER_USERNAME}\"
        DOCKER_PASSWORD=\"${DOCKER_ACCESS_TOKEN}\"
        ENV_ID=\"${ENVIRONMENT_ID}\"

        TOKEN=\$(curl -s -X POST -H \"Content-Type: application/json\" \\
          -d \"{\\\"username\\\": \\\"\${DOCKER_USERNAME}\\\", \\\"password\\\": \\\"\${DOCKER_PASSWORD}\\\"}\" \\
          https://hub.docker.com/v2/users/login/ | jq -r .token)

        curl -X DELETE \\
          -H \"Authorization: JWT \${TOKEN}\" \\
          \"https://hub.docker.com/v2/repositories/\${DOCKER_USERNAME}/envirotest-app/tags/\${ENV_ID}/\"

        rm -- \"\$0\"
      EOF
      "
      ssh ${K8S_SSH_USER}@${K8S_MASTER_IP} "
        chmod +x ~/delete-image-${ENVIRONMENT_ID}.sh
        echo '~/delete-image-${ENVIRONMENT_ID}.sh' | at now + ${TTL_HOURS} hours
      "
      echo "🗑️ Suppression de l'image ${DOCKER_USERNAME}/envirotest-app:${ENVIRONMENT_ID} planifiée dans ${TTL_HOURS} heures"

# ========================================
# STAGE 14 : RAPPORT FINAL (AGGREGATION)
# ========================================
aggregate-report:
  stage: report
  image: alpine:latest
  needs:
    - clone-repository
    - trivy-scan
    - npm-audit
    - pip-audit
    - maven-dependency-check
    - owasp-dependency-check
    - semgrep-scan
    - safe-analysis
    - gitleaks-secrets
    - checkov-scan
    - license-node
    - license-python
    - trivy-image-scan          # ← correction : inclusion du scan container
  before_script:
    - apk add --no-cache curl jq
  script:
    - echo "📊 Aggregating security reports"
    - mkdir -p final-report

    # Charger les variables depuis build.env
    - source build.env 2>/dev/null || true

    # Compter les vulnérabilités du conteneur
    - |
      CONTAINER_VULNS=0
      if [ -f reports/container-scan/trivy-image.json ]; then
        CONTAINER_VULNS=$(jq '[.Results[]?.Vulnerabilities[]?] | length' reports/container-scan/trivy-image.json 2>/dev/null || echo 0)
      fi

    # Générer le résumé enrichi
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
        "container_vulnerabilities": ${CONTAINER_VULNS},
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

