## Build stage
FROM maven:3.9-eclipse-temurin-17 AS build
WORKDIR /app

# Cache Maven dependencies
COPY pom.xml .
COPY mvnw mvnw.cmd ./
COPY .mvn .mvn

RUN mvn -q -DskipTests dependency:go-offline

COPY src ./src
RUN mvn -q -DskipTests package

## Runtime stage
FROM eclipse-temurin:17-jdk AS runtime
WORKDIR /app

COPY --from=build /app/target/*.jar ./app.jar

EXPOSE 8089

# allowRestrictedHeaders=host : sonde health domaines custom via IP Traefik + Host
ENTRYPOINT ["java", "-Djdk.httpclient.allowRestrictedHeaders=host", "-jar", "/app/app.jar"]
