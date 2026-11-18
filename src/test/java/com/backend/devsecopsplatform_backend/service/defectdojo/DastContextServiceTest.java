package com.backend.devsecopsplatform_backend.service.defectdojo;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class DastContextServiceTest {

    @Test
    void uvicornJsonCmdPointsToMainPy() {
        String dockerfile = """
                FROM python:3.12-slim
                WORKDIR /app
                COPY . .
                EXPOSE 8000
                CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000", "--reload"]
                """;
        DastContextService.Candidate c = DastContextService.candidateFromDockerfile(dockerfile);
        assertNotNull(c);
        assertEquals("main.py", c.path());
        assertTrue(c.evidence().contains("uvicorn main:app"));
    }

    @Test
    void gunicornWithBindAndDottedModule() {
        String dockerfile = "FROM python:3.12\nCMD gunicorn -k uvicorn.workers.UvicornWorker --bind 0.0.0.0:8000 app.server:api\n";
        DastContextService.Candidate c = DastContextService.candidateFromDockerfile(dockerfile);
        assertNotNull(c);
        assertEquals("app/server.py", c.path());
    }

    @Test
    void pythonScriptAndNodeEntrypoint() {
        assertEquals("run.py",
                DastContextService.candidateFromDockerfile("CMD [\"python\", \"run.py\"]").path());
        assertEquals("server/index.js",
                DastContextService.candidateFromDockerfile("ENTRYPOINT [\"node\", \"server/index.js\"]").path());
    }

    @Test
    void nginxConfigCopiedIntoImage() {
        String dockerfile = "FROM nginx:alpine\nCOPY nginx/default.conf /etc/nginx/conf.d/default.conf\nCOPY dist/ /usr/share/nginx/html\n";
        assertEquals("nginx/default.conf", DastContextService.candidateFromDockerfile(dockerfile).path());
    }

    @Test
    void javaJarHasNoGuess() {
        assertNull(DastContextService.candidateFromDockerfile("FROM eclipse-temurin:17\nCMD [\"java\", \"-jar\", \"app.jar\"]"));
    }
}
