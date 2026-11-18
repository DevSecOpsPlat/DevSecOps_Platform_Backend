package com.backend.devsecopsplatform_backend.service.defectdojo;

import com.backend.devsecopsplatform_backend.entity.AppService;
import com.backend.devsecopsplatform_backend.entity.appmgmt.AppServiceRole;
import com.backend.devsecopsplatform_backend.entity.appmgmt.ManagedApplication;
import com.backend.devsecopsplatform_backend.repository.AppServiceRepository;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

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
    void npmDevCommandIsReadAsAScript() {
        // Dockerfile du frontend Vite de l'application « Dockerfile » : géré par la lecture de package.json.
        String dockerfile = "FROM node:20-alpine\nCMD [\"npm\", \"run\", \"dev\", \"--\", \"--host\", \"0.0.0.0\"]\n";
        assertNull(DastContextService.candidateFromDockerfile(dockerfile));
        assertEquals("npm run dev -- --host 0.0.0.0", DastContextService.lastCommand(dockerfile));
    }

    @Test
    void javaJarHasNoGuess() {
        assertNull(DastContextService.candidateFromDockerfile("FROM eclipse-temurin:17\nCMD [\"java\", \"-jar\", \"app.jar\"]"));
    }

    @Test
    void longFileExcerptKeepsOnlyHttpConfiguration() {
        StringBuilder file = new StringBuilder("from fastapi import FastAPI\n");
        for (int i = 0; i < 60; i++) file.append("def route_").append(i).append("():\n    return session.query(Model).all()\n");
        file.append("app = FastAPI(title='demo')\n");
        file.append("app.add_middleware(CORSMiddleware, allow_origins=['http://localhost:5173'])\n");
        String excerpt = DastContextService.aiExcerpt(file.toString());
        assertTrue(excerpt.startsWith("(extrait ciblé"), excerpt);
        assertTrue(excerpt.contains("add_middleware"));
        assertFalse(excerpt.contains("route_30"), "les routes ne concernent pas le finding");
    }

    @Test
    void targetHeadersFollowZapRule() {
        assertEquals(List.of("Content-Security-Policy"),
                DastContextService.targetHeaders("10038", "Content Security Policy (CSP) Header Not Set"));
        assertEquals(List.of("X-Frame-Options", "frame-ancestors"),
                DastContextService.targetHeaders("10020", "Missing Anti-clickjacking Header"));
    }

    @Test
    void rootUrlIsAnsweredByTheFrontendNotByTheFindingService() {
        ManagedApplication managed = new ManagedApplication();
        managed.setId(UUID.randomUUID());
        AppService back = service("back", AppServiceRole.BACKEND, managed);
        AppService front = service("front", AppServiceRole.FRONTEND, managed);
        AppServiceRepository repo = mock(AppServiceRepository.class);
        when(repo.findByManagedApplication_Id(managed.getId())).thenReturn(List.of(back, front));
        DastContextService svc = new DastContextService(null, repo, null);

        List<String> urls = List.of("https://aoo-1.envirotest.cloud/", "https://aoo-1.envirotest.cloud/vite.svg");
        DastContextService.Responder r = svc.resolveResponder(back, urls.get(0), urls);
        assertSame(front, r.service());
        assertTrue(r.reason().contains("FRONTEND"), r.reason());

        DastContextService.Responder api = svc.resolveResponder(back, "https://aoo-1.envirotest.cloud/api/configs", urls);
        assertSame(back, api.service());
    }

    private static AppService service(String name, AppServiceRole role, ManagedApplication managed) {
        AppService s = new AppService();
        s.setId(UUID.randomUUID());
        s.setName(name);
        s.setRole(role);
        s.setManagedApplication(managed);
        s.setGitRepositoryUrl("https://github.com/demo/" + name + ".git");
        return s;
    }
}
