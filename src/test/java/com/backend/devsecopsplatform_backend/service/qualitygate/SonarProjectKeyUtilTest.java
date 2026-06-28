package com.backend.devsecopsplatform_backend.service.qualitygate;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

class SonarProjectKeyUtilTest {

    @Test
    void deriveSonarProjectKey_matchesPipelineSlug() {
        assertEquals(
                "github_com_Amenybn_Angular",
                SonarProjectKeyUtil.deriveSonarProjectKey("https://github.com/Amenybn/Angular")
        );
        assertEquals(
                "github_com_Amenybn_Angular",
                SonarProjectKeyUtil.deriveSonarProjectKey("https://github.com/Amenybn/Angular.git")
        );
    }

    /** Aligné sed pipeline : pas de collapse des underscores consécutifs. */
    @Test
    void deriveSonarProjectKey_preservesConsecutiveUnderscores() {
        assertEquals(
                "github_com_foo__bar_baz",
                SonarProjectKeyUtil.deriveSonarProjectKey("https://github.com/foo--bar/baz")
        );
    }

    /** Slash final → underscore final (pipeline ne trim pas). */
    @Test
    void deriveSonarProjectKey_trailingSlashBecomesTrailingUnderscore() {
        assertEquals(
                "github_com_Amenybn_Angular_",
                SonarProjectKeyUtil.deriveSonarProjectKey("https://github.com/Amenybn/Angular/")
        );
    }
}
