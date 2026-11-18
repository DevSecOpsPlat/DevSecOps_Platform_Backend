package com.backend.devsecopsplatform_backend.service.appmgmt;

import org.junit.jupiter.api.Test;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

class GitAccessVerifierTest {

    @Test
    void githubUrlsAreRecognised() {
        assertEquals(Optional.of("Amenybn/eventpass_front"),
                GitAccessVerifier.githubPath("https://github.com/Amenybn/eventpass_front.git"));
        assertEquals(Optional.of("Amenybn/eventpass_front"),
                GitAccessVerifier.githubPath("https://github.com/Amenybn/eventpass_front/"));
        assertEquals(Optional.of("Amenybn/eventpass_back"),
                GitAccessVerifier.githubPath("git@github.com:Amenybn/eventpass_back.git"));
        assertTrue(GitAccessVerifier.githubPath("https://gitlab.com/group/repo.git").isEmpty());
        assertTrue(GitAccessVerifier.githubPath(null).isEmpty());
    }

    @Test
    void gitlabUrlsAreRecognised() {
        GitAccessVerifier verifier = new GitAccessVerifier();
        assertEquals(Optional.of("amanibennaceur-group/envirotest"),
                verifier.gitlabPath("https://gitlab.com/amanibennaceur-group/envirotest.git"));
        assertTrue(verifier.gitlabPath("https://github.com/Amenybn/eventpass_front.git").isEmpty());
        assertTrue(verifier.isKnownHost("https://github.com/Amenybn/eventpass_front.git"));
        assertFalse(verifier.isKnownHost("https://git.example.org/team/app.git"));
    }

    @Test
    void emptyTokenIsNotVerifiedRemotely() {
        assertEquals(GitAccessVerifier.Status.UNVERIFIED,
                new GitAccessVerifier().verifyToken("https://github.com/Amenybn/eventpass_front.git", "  "));
    }
}
