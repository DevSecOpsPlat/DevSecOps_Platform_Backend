stages:
- hello
- clone
- build
- scan
- report

variables:
GIT_REPO_URL: ""
GIT_BRANCH: "main"
GITHUB_TOKEN: ""
ENVIRONMENT_ID: ""

hello-world:
stage: hello
image: alpine:latest
script:
- echo "Hello World!"
- echo "Pipeline declenche pour l'environnement $ENVIRONMENT_ID"
- echo "Repository GitHub = $GIT_REPO_URL"
- echo "Branche = $GIT_BRANCH"
clone-repository:
stage: clone
image: alpine:latest  # ✅ Image propre
before_script:
- apk add --no-cache git bash  # ✅ Installation de git
script:
- echo "Clonage du repository"
- echo "Repository = $GIT_REPO_URL"
- test -n "$GIT_REPO_URL" || exit 1
- |
if [ -n "$GITHUB_TOKEN" ]; then
AUTH_URL=$(echo "$GIT_REPO_URL" | sed "s|https://|https://oauth2:${GITHUB_TOKEN}@|")
else
AUTH_URL="$GIT_REPO_URL"
fi
git clone --depth 1 --branch "$GIT_BRANCH" "$AUTH_URL" user-repo
- ls -la user-repo
- test -f "user-repo/pom.xml" && echo "BUILD_TOOL=maven" >> build.env || true
- test -f "user-repo/package.json" && echo "BUILD_TOOL=node" >> build.env || true
- test -f build.env || echo "BUILD_TOOL=unknown" >> build.env
- cat build.env
artifacts:
paths:
- user-repo/
reports:
dotenv: build.env
expire_in: 2 hours

build-maven:
stage: build
image: maven:3.9-eclipse-temurin-17
script:
- echo "Build Maven - BUILD_TOOL=$BUILD_TOOL"
- cd user-repo
- mvn clean compile -DskipTests
artifacts:
paths:
- user-repo/target/
expire_in: 2 hours
rules:
- if: $BUILD_TOOL == "maven"
allow_failure: true

build-node:
stage: build
image: node:20-alpine
script:
- echo "Build Node - BUILD_TOOL=$BUILD_TOOL"
- cd user-repo
- npm install
- npm run build || echo "Pas de script build"
artifacts:
paths:
- user-repo/dist/
expire_in: 2 hours
rules:
- if: $BUILD_TOOL == "node"
allow_failure: true

trivy-scan:
stage: scan
image: aquasec/trivy:latest
script:
- echo "Scan Trivy"
- trivy fs --format json --output trivy-report.json --severity CRITICAL,HIGH,MEDIUM user-repo || echo "Erreur scan"
artifacts:
paths:
- trivy-report.json
expire_in: 1 month
allow_failure: true

generate-report:
stage: report
image: alpine:latest
script:
- echo "Rapport final"
- echo "{\"environment_id\":\"$ENVIRONMENT_ID\",\"git_repository\":\"$GIT_REPO_URL\",\"git_branch\":\"$GIT_BRANCH\",\"pipeline_id\":\"$CI_PIPELINE_ID\",\"status\":\"completed\"}" > security-summary.json
- cat security-summary.json
artifacts:
paths:
- security-summary.json
- trivy-report.json
expire_in: 3 months
