package com.backend.devsecopsplatform_backend.service.qualitygate;

import com.backend.devsecopsplatform_backend.service.qualitygate.dto.ScoreBreakdownItemDto;
import com.backend.devsecopsplatform_backend.service.qualitygate.dto.SecurityScoreDto;
import org.junit.jupiter.api.Test;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class SecurityScoringServiceTest {

    private final SecurityScoringService service = new SecurityScoringService();

    @Test
    void hardGate_secretsBlockImmediately() {
        HardGateInput input = HardGateInput.builder()
                .secrets(2)
                .secretsEvaluable(true)
                .ddCritical(0)
                .sonarBlockers(0)
                .defectDojoAvailable(true)
                .sonarAvailable(true)
                .build();
        var eval = service.evaluateHardGates(input);
        assertEquals(1, eval.violations().size());
        assertTrue(eval.summaryMessage().contains("2 secret"));
    }

    @Test
    void hardGate_secretsNotEvaluableIsIndeterminate() {
        HardGateInput input = HardGateInput.builder()
                .secrets(0)
                .secretsEvaluable(false)
                .defectDojoAvailable(true)
                .sonarAvailable(true)
                .build();
        var eval = service.evaluateHardGates(input);
        assertTrue(eval.indeterminate().stream().anyMatch(v -> "secrets".equals(v.getId())));
    }

    @Test
    void hardGate_defectDojoUnavailableIsIndeterminate() {
        HardGateInput input = HardGateInput.builder()
                .secrets(0)
                .secretsEvaluable(true)
                .defectDojoAvailable(false)
                .sonarAvailable(true)
                .build();
        var eval = service.evaluateHardGates(input);
        assertTrue(eval.indeterminateSources().contains("Centralisation des vulnérabilités"));
    }

    @Test
    void postureScore_usesDensityWhenNclocKnown() {
        Map<String, Integer> dd = new LinkedHashMap<>();
        dd.put("critical", 0);
        dd.put("high", 20);
        dd.put("medium", 0);
        dd.put("low", 0);

        SecurityScoreInput input = SecurityScoreInput.builder()
                .ddBySeverity(dd)
                .secrets(0)
                .ncloc(10000)
                .stages(List.of())
                .sonarAvailable(true)
                .defectDojoAvailable(true)
                .build();

        SecurityScoreDto score = service.computePostureScore(input);
        assertTrue(score.getScore() < 100, "density penalty should reduce score");
        assertTrue(score.getScore() >= 75);
        assertEquals("RECOMMENDED", score.getDerivedVerdict());
    }

    // ── Objectif B : gate DAST (ZAP) ──────────────────────────────────────────

    @Test
    void hardGate_dastNotApplicableOnScanOnlyPipeline() {
        // Garde de non-régression scan-only : dastApplicable=false doit rester silencieux,
        // même avec un compte élevé -- un pipeline scan-only ne doit jamais afficher de gate DAST.
        HardGateInput input = HardGateInput.builder()
                .secrets(0)
                .secretsEvaluable(true)
                .defectDojoAvailable(true)
                .sonarAvailable(true)
                .dastApplicable(false)
                .dastHigh(999)
                .build();
        var eval = service.evaluateHardGates(input);
        assertTrue(eval.violations().stream().noneMatch(v -> "dast".equals(v.getId())));
        assertTrue(eval.indeterminate().stream().noneMatch(v -> "dast".equals(v.getId())));
    }

    @Test
    void hardGate_dastApplicableButNotEvaluableIsIndeterminate() {
        HardGateInput input = HardGateInput.builder()
                .secrets(0)
                .secretsEvaluable(true)
                .defectDojoAvailable(true)
                .sonarAvailable(true)
                .dastApplicable(true)
                .dastEvaluable(false)
                .build();
        var eval = service.evaluateHardGates(input);
        assertTrue(eval.indeterminate().stream().anyMatch(v -> "dast".equals(v.getId())));
        assertTrue(eval.indeterminateSources().contains("DAST (ZAP)"));
    }

    @Test
    void hardGate_dastHighAboveThresholdViolates() {
        HardGateInput input = HardGateInput.builder()
                .secrets(0)
                .secretsEvaluable(true)
                .defectDojoAvailable(true)
                .sonarAvailable(true)
                .dastApplicable(true)
                .dastEvaluable(true)
                .dastHigh(6) // seuil QualityGateThresholds.DAST_HIGH = 5
                .build();
        var eval = service.evaluateHardGates(input);
        assertTrue(eval.violations().stream().anyMatch(v -> "dast".equals(v.getId())));
    }

    @Test
    void hardGate_dastHighAtThresholdDoesNotViolate() {
        HardGateInput input = HardGateInput.builder()
                .secrets(0)
                .secretsEvaluable(true)
                .defectDojoAvailable(true)
                .sonarAvailable(true)
                .dastApplicable(true)
                .dastEvaluable(true)
                .dastHigh(5) // au seuil, pas au-dessus
                .build();
        var eval = service.evaluateHardGates(input);
        assertTrue(eval.violations().stream().noneMatch(v -> "dast".equals(v.getId())));
    }

    @Test
    void postureScore_dastHasOwnBreakdownLineAndDoesNotInflateGenericHigh() {
        Map<String, Integer> dd = new LinkedHashMap<>();
        dd.put("critical", 0);
        dd.put("high", 2);
        dd.put("medium", 0);
        dd.put("low", 0);

        SecurityScoreInput withoutDast = SecurityScoreInput.builder()
                .ddBySeverity(dd)
                .ncloc(10000)
                .stages(List.of())
                .sonarAvailable(true)
                .defectDojoAvailable(true)
                .dastApplicable(false)
                .build();
        SecurityScoreDto scoreWithoutDast = service.computePostureScore(withoutDast);

        SecurityScoreInput withDast = SecurityScoreInput.builder()
                .ddBySeverity(dd)
                .ncloc(10000)
                .stages(List.of())
                .sonarAvailable(true)
                .defectDojoAvailable(true)
                .dastApplicable(true)
                .dastHigh(3)
                .build();
        SecurityScoreDto scoreWithDast = service.computePostureScore(withDast);

        assertTrue(scoreWithDast.getBreakdown().stream().anyMatch(i -> "dd_dast_high".equals(i.getId())),
                "le DAST doit avoir sa propre ligne de détail, séparée du bucket générique");
        // Garde anti double-comptage : ajouter du DAST ne doit jamais gonfler la pénalité
        // générique "high" (dd_high) -- seule une ligne dd_dast_high distincte doit apparaître.
        assertEquals(breakdownImpact(scoreWithoutDast, "dd_high"), breakdownImpact(scoreWithDast, "dd_high"));
        assertTrue(scoreWithDast.getScore() < scoreWithoutDast.getScore(),
                "le DAST doit quand même faire baisser le score global, via sa propre ligne");
    }

    private static int breakdownImpact(SecurityScoreDto score, String id) {
        return score.getBreakdown().stream()
                .filter(i -> id.equals(i.getId()))
                .mapToInt(ScoreBreakdownItemDto::getImpact)
                .findFirst()
                .orElse(0);
    }

    // ── Objectif C : pondération CVSS ─────────────────────────────────────────

    private SecurityScoreInput criticalScoreInput(int criticalCount, Map<String, Double> avgCvss, Map<String, Integer> known) {
        Map<String, Integer> dd = new LinkedHashMap<>();
        dd.put("critical", criticalCount);
        dd.put("high", 0);
        dd.put("medium", 0);
        dd.put("low", 0);
        return SecurityScoreInput.builder()
                .ddBySeverity(dd)
                .ncloc(10000)
                .stages(List.of())
                .sonarAvailable(true)
                .defectDojoAvailable(true)
                .avgCvssBySeverity(avgCvss)
                .cvssKnownCountBySeverity(known)
                .build();
    }

    @Test
    void postureScore_noCvssDataMatchesFlatCountBehavior() {
        // Repli sûr : sans donnée CVSS, le score doit être identique au comportement historique
        // (comptage brut). 24 critical / ncloc=10000 -> densité 2.4, impact round(2.4*12)=29.
        SecurityScoreInput input = criticalScoreInput(24, Map.of(), Map.of());
        assertEquals(71, service.computePostureScore(input).getScore());
    }

    @Test
    void postureScore_highCvssAverageIncreasesPenalty() {
        SecurityScoreInput input = criticalScoreInput(24, Map.of("critical", 9.8), Map.of("critical", 24));
        // Un CVSS moyen élevé (9.8, proche du plafond 10) doit alourdir la pénalité par rapport
        // au comptage brut (71 sans CVSS, voir test précédent).
        assertEquals(70, service.computePostureScore(input).getScore());
    }

    @Test
    void postureScore_lowCvssAverageReducesPenaltyButStaysPositive() {
        SecurityScoreInput input = criticalScoreInput(24, Map.of("critical", 9.0), Map.of("critical", 24));
        SecurityScoreDto score = service.computePostureScore(input);
        // Un CVSS moyen bas pour sa catégorie (9.0, plancher du Critical) doit réduire la pénalité
        // par rapport au comptage brut (71), sans jamais l'annuler.
        assertEquals(73, score.getScore());
        assertTrue(breakdownImpact(score, "dd_critical") < 0, "la pénalité doit rester présente");
    }

    @Test
    void postureScore_mixedKnownUnknownCvssBlendsBetweenExtremes() {
        SecurityScoreInput allUnknown = criticalScoreInput(24, Map.of(), Map.of());
        SecurityScoreInput allKnownHighAvg = criticalScoreInput(24, Map.of("critical", 9.8), Map.of("critical", 24));
        SecurityScoreInput mixed = criticalScoreInput(24, Map.of("critical", 9.8), Map.of("critical", 12));

        int scoreAllUnknown = service.computePostureScore(allUnknown).getScore();
        int scoreAllKnownHighAvg = service.computePostureScore(allKnownHighAvg).getScore();
        int scoreMixed = service.computePostureScore(mixed).getScore();

        assertTrue(scoreMixed <= scoreAllUnknown,
                "un mélange avec CVSS élevé ne doit jamais donner un score meilleur que sans CVSS");
        assertTrue(scoreMixed >= scoreAllKnownHighAvg,
                "un mélange doit rester moins pénalisant que si tous les findings avaient ce CVSS élevé");
    }

    // ── Objectif D : diagnostic score-à-0 du 29/08/2026 — plafond global + conteneur ───────────
    // Garde de non-régression explicite : un projet "normal" (pas de saturation multi-buckets,
    // pas de Grype disproportionné) doit obtenir un score identique au comportement d'avant ce
    // changement -- voir postureScore_usesDensityWhenNclocKnown et les tests CVSS ci-dessus, qui
    // continuent tous de passer sans modification (aucune de leurs sommes n'atteint 70).

    @Test
    void postureScore_normalCaseUnaffectedByNewCaps() {
        // 20 high / ncloc=10000 -> impact 29 (identique à postureScore_usesDensityWhenNclocKnown) :
        // bien en dessous de 70, donc aucun plafond ne doit se déclencher, et sans findings
        // conteneur aucune ligne "container_*" ne doit apparaître.
        Map<String, Integer> dd = new LinkedHashMap<>();
        dd.put("critical", 0);
        dd.put("high", 20);
        dd.put("medium", 0);
        dd.put("low", 0);
        SecurityScoreInput input = SecurityScoreInput.builder()
                .ddBySeverity(dd)
                .ncloc(10000)
                .stages(List.of())
                .sonarAvailable(true)
                .defectDojoAvailable(true)
                .build();

        SecurityScoreDto score = service.computePostureScore(input);
        // 20 high / ncloc=10000 -> densité 2.0, impact round(min(30, 2.0*4.0)) = 8 -> score 92
        // (identique au calcul d'avant ce changement : sans dépassement de 70, severityApplied ==
        // severitySum, comportement inchangé).
        assertEquals(92, score.getScore());
        assertTrue(score.getAppliedCaps().isEmpty(), "aucun plafond ne doit se déclencher sous le seuil");
        assertTrue(score.getBreakdown().stream().noneMatch(i -> i.getId().startsWith("container_")),
                "pas de findings conteneur -> pas de ligne container_* dans le breakdown");
        assertEquals(score.getScore(), score.getRawScoreBeforeCaps(),
                "sans dépassement, rawScoreBeforeCaps doit rester égal au score final");
    }

    @Test
    void postureScore_severityGlobalCap_appliesAfterIndividualCapsButKeepsThemVisible() {
        // Reproduit le pipeline 2800542049 du diagnostic (ncloc=928, crit=13/high=132/med=117/low=25,
        // sans CVSS pour rester calculable à la main) : les 3 buckets crit/high/med saturent
        // individuellement à -30 (densité largement > seuil), somme brute = 101 (30+30+30+11),
        // au-delà du plafond global de 70.
        Map<String, Integer> dd = new LinkedHashMap<>();
        dd.put("critical", 13);
        dd.put("high", 132);
        dd.put("medium", 117);
        dd.put("low", 25);
        SecurityScoreInput input = SecurityScoreInput.builder()
                .ddBySeverity(dd)
                .ncloc(928)
                .stages(List.of())
                .sonarAvailable(true)
                .defectDojoAvailable(true)
                .securityRating("D")
                .coverageKnown(true)
                .coverage(0)
                .dastApplicable(true)
                .dastMedium(3)
                .build();

        SecurityScoreDto score = service.computePostureScore(input);

        // Chaque bucket individuel garde sa vraie valeur, plafonnée à -30 (transparence) --
        // "rognage après coup", pas d'arrêt anticipé de l'accumulation (choix validé explicitement).
        assertEquals(-30, breakdownImpact(score, "dd_critical"));
        assertEquals(-30, breakdownImpact(score, "dd_high"));
        assertEquals(-30, breakdownImpact(score, "dd_medium"));
        assertEquals(-11, breakdownImpact(score, "dd_low"));

        assertTrue(score.getAppliedCaps().contains("severity_global_cap"));
        assertTrue(score.getAppliedCaps().stream().noneMatch("container_global_cap"::equals));

        // score = 100 - 70(sévérité, plafonnée au lieu de 101) - 5(dast_medium) - 15(sonar: -10
        // rating Security D, -5 couverture < 50%) = 10 -- avant ce correctif, la même entrée
        // donnait 0 (100 - 101 - 5 - 15 = -21, clampé à 0), masquant tout écart entre ce cas et un
        // cas bien pire.
        assertEquals(10, score.getScore());
        assertEquals(-21, score.getRawScoreBeforeCaps(),
                "la vraie somme avant plafonds doit rester visible (et négative), contrairement au "
                        + "comportement historique où ce champ ne faisait que refléter le score déjà plafonné");
    }

    @Test
    void postureScore_containerTiers_absoluteNotDensityBased() {
        // Deux ncloc très différents, mêmes comptages conteneur : le palier absolu doit donner le
        // même impact dans les deux cas (contrairement à un bucket en densité, qui varierait avec
        // ncloc) -- c'est tout l'objet de la piste B (le nombre de vulnérabilités d'une image de
        // base n'a pas de lien avec la taille du code source).
        SecurityScoreInput smallApp = containerScoreInput(140, 13, 132, 0, 0);
        SecurityScoreInput largeApp = containerScoreInput(29359, 13, 132, 0, 0);

        SecurityScoreDto scoreSmall = service.computePostureScore(smallApp);
        SecurityScoreDto scoreLarge = service.computePostureScore(largeApp);

        assertEquals(breakdownImpact(scoreSmall, "container_critical"), breakdownImpact(scoreLarge, "container_critical"));
        assertEquals(breakdownImpact(scoreSmall, "container_high"), breakdownImpact(scoreLarge, "container_high"));
        assertEquals(-25, breakdownImpact(scoreSmall, "container_critical"), "13 critical -> palier [9,15] = 25");
        assertEquals(-30, breakdownImpact(scoreSmall, "container_high"), "132 high -> au-delà du palier [121,+] = 30");

        // Garde anti double-comptage : les findings conteneur ne doivent jamais apparaître dans les
        // buckets génériques dd_critical/dd_high (la soustraction se fait en amont, dans
        // QualityGateService.buildBySeverity -- ici ddBySeverity ne les inclut pas du tout, donc
        // aucune ligne dd_critical/dd_high ne doit apparaître).
        assertTrue(scoreSmall.getBreakdown().stream().noneMatch(i -> "dd_critical".equals(i.getId())));
        assertTrue(scoreSmall.getBreakdown().stream().noneMatch(i -> "dd_high".equals(i.getId())));
    }

    @Test
    void postureScore_containerGlobalCap_appliesIndependentlyFromSeverityCap() {
        // Les 4 sévérités conteneur saturent chacune leur propre palier à 30 -> somme brute 120,
        // au-delà du plafond conteneur de 70 -- alors qu'aucun finding générique n'existe (pas de
        // saturation du plafond de sévérité). Les deux plafonds doivent rester indépendants.
        SecurityScoreInput input = containerScoreInput(928, 16, 200, 200, 200);

        SecurityScoreDto score = service.computePostureScore(input);

        assertTrue(score.getAppliedCaps().contains("container_global_cap"));
        assertTrue(score.getAppliedCaps().stream().noneMatch("severity_global_cap"::equals),
                "pas de findings génériques dans ce cas -> le plafond de sévérité ne doit pas se déclencher");
        // 100 - 70 (conteneur plafonné au lieu de 30*4=120) = 30
        assertEquals(30, score.getScore());
    }

    private SecurityScoreInput containerScoreInput(int ncloc, int critical, int high, int medium, int low) {
        Map<String, Integer> dd = new LinkedHashMap<>();
        dd.put("critical", 0);
        dd.put("high", 0);
        dd.put("medium", 0);
        dd.put("low", 0);
        return SecurityScoreInput.builder()
                .ddBySeverity(dd)
                .ncloc(ncloc)
                .stages(List.of())
                .sonarAvailable(false)
                .defectDojoAvailable(true)
                .containerCritical(critical)
                .containerHigh(high)
                .containerMedium(medium)
                .containerLow(low)
                .build();
    }
}
