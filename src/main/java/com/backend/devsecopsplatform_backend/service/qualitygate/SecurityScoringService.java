package com.backend.devsecopsplatform_backend.service.qualitygate;

import com.backend.devsecopsplatform_backend.service.qualitygate.dto.HardGateViolationDto;
import com.backend.devsecopsplatform_backend.service.qualitygate.dto.QualityGateStageDto;
import com.backend.devsecopsplatform_backend.service.qualitygate.dto.ScoreBreakdownItemDto;
import com.backend.devsecopsplatform_backend.service.qualitygate.dto.SecurityScoreDto;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * Décision Quality Gate à deux niveaux :
 * 1) Hard gates déterministes (bloquants absolus)
 * 2) Score de posture informatif (densité / 1000 LOC) — seulement si hard gates OK
 */
@Service
public class SecurityScoringService {

    private static final double DENSITY_CRITICAL_FACTOR = 12.0;
    private static final double DENSITY_HIGH_FACTOR = 4.0;
    private static final double DENSITY_MEDIUM_FACTOR = 1.5;
    private static final double DENSITY_LOW_FACTOR = 0.4;
    private static final int ABS_PENALTY_CRITICAL = 8;
    private static final int ABS_PENALTY_HIGH = 3;
    private static final int ABS_PENALTY_MEDIUM = 1;
    private static final double ABS_PENALTY_LOW = 0.25;
    private static final int HOTSPOT_PENALTY_CAP = 10;
    private static final int POSTURE_WARN_THRESHOLD = 75;

    // ── Diagnostic du 29/08/2026 (30 derniers quality_gate_snapshots) ──────────────────────────
    // Constat : dans 5/5 pipelines à score 0 de l'échantillon, dd_critical + dd_high + dd_medium
    // saturaient SIMULTANÉMENT leur plafond individuel de -30 (-90 à eux seuls), avant même DAST
    // ou Sonar -- aucun plafond n'existait sur la somme. PROVISOIRE : calibré sur 30 pipelines
    // seulement, à revoir dès qu'on dispose de plus de données (voir docs/audit-quality-gate.md).
    private static final int SEVERITY_GLOBAL_CAP = 70;

    // Même réserve (provisoire, 30 pipelines) pour la dimension conteneur ci-dessous -- sans ce
    // second plafond, un pipeline à forte densité de findings Grype reproduirait exactement le
    // même mécanisme de dépassement, juste déplacé d'un bucket à l'autre.
    private static final int CONTAINER_GLOBAL_CAP = 70;

    // Paliers absolus pour le scan de conteneur (Grype) -- PAS de densité par ncloc. Diagnostic du
    // 29/08/2026 : ni le rapport Grype natif, ni l'agrégation CI, ni aucun DTO backend n'exposent
    // un total de paquets scannés dans l'image (Syft ne tourne que pour la conformité licence,
    // jamais fusionné au scan de vulnérabilités) -- une normalisation par "nombre de dépendances"
    // n'est donc pas possible aujourd'hui. Le nombre de vulnérabilités d'une image de base
    // (paquets OS/runtime) n'a de toute façon structurellement aucun lien avec ncloc : deux
    // pipelines de la même appli avec ncloc=140 et ncloc=928 montraient des comptages Grype du
    // même ordre de grandeur dans l'échantillon.
    // Seuils calibrés sur les comptages réels (dimension DefectDojo, après import) observés sur
    // les pipelines du flux déploiement de l'échantillon :
    //   critical : 0, 7, 13, 13, 13, 13
    //   high     : 0, 44, 113, 116, 132, 144
    //   medium   : 0 (majorité des cas), un cas à 117
    //   low      : 0 (majorité des cas), un cas à 25
    // Échantillon volontairement restreint (30 pipelines, ~5 exploitables par sévérité hors
    // doublons) -- seuils à recalibrer avec plus de données, voir docs/audit-quality-gate.md.
    private static final int[] CONTAINER_CRIT_THRESHOLDS = {3, 8, 15};
    private static final int[] CONTAINER_CRIT_IMPACTS = {8, 16, 25, 30};
    private static final int[] CONTAINER_HIGH_THRESHOLDS = {15, 50, 120};
    private static final int[] CONTAINER_HIGH_IMPACTS = {8, 16, 24, 30};
    private static final int[] CONTAINER_MEDIUM_THRESHOLDS = {10, 40, 90};
    private static final int[] CONTAINER_MEDIUM_IMPACTS = {6, 14, 22, 30};
    private static final int[] CONTAINER_LOW_THRESHOLDS = {8, 20};
    private static final int[] CONTAINER_LOW_IMPACTS = {6, 14, 30};

    public record HardGateEvaluation(
            List<HardGateViolationDto> violations,
            List<HardGateViolationDto> indeterminate,
            List<String> indeterminateSources,
            String summaryMessage
    ) {}

    /** Hard gates évalués AVANT tout score — tolérance zéro sur les risques graves. */
    public HardGateEvaluation evaluateHardGates(HardGateInput input) {
        if (input == null) {
            return new HardGateEvaluation(List.of(), List.of(), List.of("Données"), null);
        }

        List<HardGateViolationDto> violations = new ArrayList<>();
        List<HardGateViolationDto> indeterminate = new ArrayList<>();
        List<String> indeterminateSources = new ArrayList<>();

        if (!input.isSecretsEvaluable()) {
            indeterminate.add(violation("secrets", "Secrets exposés (Gitleaks)",
                    "Scan secrets non exécuté — état inconnu", "INDETERMINATE"));
        } else if (input.getSecrets() > 0) {
            violations.add(violation("secrets", "Secrets exposés (Gitleaks)",
                    input.getSecrets() + " secret(s) exposé(s)", "VIOLATED"));
        }

        if (!input.isDefectDojoAvailable()) {
            indeterminateSources.add("Centralisation des vulnérabilités");
            indeterminate.add(violation("dd_critical", "Vulnérabilités critiques",
                    "Centralisation des vulnérabilités indisponible — état inconnu", "INDETERMINATE"));
        } else {
            int combinedCritical = input.getDdCritical();
            if (input.isSonarAvailable()) {
                combinedCritical += Math.max(0, input.getSonarCritical());
            }
            if (combinedCritical > 0) {
                String detail = combinedCritical + " vulnérabilité(s) critique(s)";
                if (input.isSonarAvailable() && input.getSonarCritical() > 0 && input.getDdCritical() > 0) {
                    detail += " (centralisation " + input.getDdCritical() + " + SonarQube "
                            + input.getSonarCritical() + ")";
                } else if (input.isSonarAvailable() && input.getSonarCritical() > 0) {
                    detail += " (SonarQube " + input.getSonarCritical() + ")";
                }
                violations.add(violation("dd_critical", "Vulnérabilités critiques",
                        detail, "VIOLATED"));
            }
        }

        if (!input.isSonarAvailable()) {
            if (!indeterminateSources.contains("SonarQube")) {
                indeterminateSources.add("SonarQube");
            }
            indeterminate.add(violation("sonar_blocker", "Issues Blocker (SonarQube)",
                    "SonarQube indisponible — état inconnu", "INDETERMINATE"));
            indeterminate.add(violation("sonar_qg", "Quality Gate SonarQube",
                    "SonarQube indisponible — état inconnu", "INDETERMINATE"));
        } else {
            if (input.getSonarBlockers() > 0) {
                violations.add(violation("sonar_blocker", "Issues Blocker (SonarQube)",
                        input.getSonarBlockers() + " issue(s) Blocker", "VIOLATED"));
            }
            if ("ERROR".equalsIgnoreCase(stringVal(input.getSonarQgStatus()))) {
                violations.add(violation("sonar_qg", "Quality Gate SonarQube",
                        "Quality Gate SonarQube en ERROR", "VIOLATED"));
            }
        }

        // DAST (ZAP) ne s'applique jamais aux pipelines scan-only (ZAP n'y tourne pas) : le gate
        // reste silencieusement absent dans ce cas, comportement identique à avant ce changement.
        // Bloquant (VIOLATED), avec le seuil de tolérance déjà prévu pour le DAST (pas zéro-tolérance
        // comme les autres gates, pour absorber le bruit propre à une analyse dynamique).
        if (input.isDastApplicable()) {
            if (!input.isDastEvaluable()) {
                indeterminateSources.add("DAST (ZAP)");
                indeterminate.add(violation("dast", "Vulnérabilités élevées (DAST / ZAP)",
                        "Scan DAST non exécuté ou incomplet — état inconnu", "INDETERMINATE"));
            } else if (input.getDastHigh() > QualityGateThresholds.DAST_HIGH) {
                violations.add(violation("dast", "Vulnérabilités élevées (DAST / ZAP)",
                        input.getDastHigh() + " finding(s) élevé(s) ZAP (seuil " + QualityGateThresholds.DAST_HIGH + ")",
                        "VIOLATED"));
            }
        }

        String summary = buildHardGateSummary(violations);
        return new HardGateEvaluation(violations, indeterminate, indeterminateSources, summary);
    }

    /**
     * Score de posture informatif — uniquement si tous les hard gates passent.
     * Utilise la densité (findings / 1000 LOC) quand ncloc est connu.
     */
    public SecurityScoreDto computePostureScore(SecurityScoreInput input) {
        if (input == null) {
            return emptyScore();
        }

        List<ScoreBreakdownItemDto> breakdown = new ArrayList<>();
        List<String> appliedCaps = new ArrayList<>();
        Map<String, Integer> dd = input.getDdBySeverity() != null ? input.getDdBySeverity() : Map.of();

        int crit = dd.getOrDefault("critical", 0);
        int high = dd.getOrDefault("high", 0);
        int med = dd.getOrDefault("medium", 0);
        int low = dd.getOrDefault("low", 0);
        int ncloc = Math.max(0, input.getNcloc());
        boolean useDensity = ncloc >= 100;

        int score = 100;
        CvssWeighting critW = cvssWeighting("critical", crit, input);
        int critImpact = severityPenalty(breakdown, "critical", crit, critW.weightedCount(), critW.note(),
                ncloc, useDensity, DENSITY_CRITICAL_FACTOR, ABS_PENALTY_CRITICAL);
        CvssWeighting highW = cvssWeighting("high", high, input);
        int highImpact = severityPenalty(breakdown, "high", high, highW.weightedCount(), highW.note(),
                ncloc, useDensity, DENSITY_HIGH_FACTOR, ABS_PENALTY_HIGH);
        CvssWeighting medW = cvssWeighting("medium", med, input);
        int medImpact = severityPenalty(breakdown, "medium", med, medW.weightedCount(), medW.note(),
                ncloc, useDensity, DENSITY_MEDIUM_FACTOR, ABS_PENALTY_MEDIUM);
        CvssWeighting lowW = cvssWeighting("low", low, input);
        int lowImpact = severityPenalty(breakdown, "low", low, lowW.weightedCount(), lowW.note(),
                ncloc, useDensity, DENSITY_LOW_FACTOR, ABS_PENALTY_LOW);

        // Plafond global sur la somme des 4 buckets de sévérité -- appliqué APRÈS les plafonds
        // individuels de -30 (rognage de la somme finale), pas d'arrêt anticipé de l'accumulation :
        // chaque bucket reste calculé et affiché avec sa vraie valeur individuelle (transparence),
        // seule la part appliquée au score est plafonnée. Choix délibéré (plus simple, plus
        // prévisible, n'exige pas de choisir un ordre d'évaluation des buckets) -- voir diagnostic
        // du 29/08/2026. Sans dépassement (cas normal), ce plafond est un no-op strict : score
        // identique au comportement d'avant ce changement.
        int severitySum = critImpact + highImpact + medImpact + lowImpact;
        int severityApplied = applyGlobalCap(severitySum, SEVERITY_GLOBAL_CAP, "severity_global_cap", appliedCaps);
        score -= severityApplied;

        // Conteneur (Grype) : dimension à part, paliers absolus (PAS de densité par ncloc), jamais
        // fondue dans crit/high/med/low ci-dessus -- voir QualityGateService.buildBySeverity
        // (soustraction symétrique à celle déjà faite pour DAST) et les constantes CONTAINER_*
        // ci-dessus pour la justification des seuils. Même plafond global que les buckets de
        // sévérité, même raison : éviter de reproduire le même mécanisme de dépassement ici.
        int containerImpact = 0;
        containerImpact += containerTierPenalty(breakdown, "critical", input.getContainerCritical(),
                CONTAINER_CRIT_THRESHOLDS, CONTAINER_CRIT_IMPACTS);
        containerImpact += containerTierPenalty(breakdown, "high", input.getContainerHigh(),
                CONTAINER_HIGH_THRESHOLDS, CONTAINER_HIGH_IMPACTS);
        containerImpact += containerTierPenalty(breakdown, "medium", input.getContainerMedium(),
                CONTAINER_MEDIUM_THRESHOLDS, CONTAINER_MEDIUM_IMPACTS);
        containerImpact += containerTierPenalty(breakdown, "low", input.getContainerLow(),
                CONTAINER_LOW_THRESHOLDS, CONTAINER_LOW_IMPACTS);
        int containerApplied = applyGlobalCap(containerImpact, CONTAINER_GLOBAL_CAP, "container_global_cap", appliedCaps);
        score -= containerApplied;

        // DAST (ZAP) : dimension à part, jamais fondue dans crit/high/med/low ci-dessus (voir
        // QualityGateService.buildBySeverity) -- ligne de détail dédiée, visible séparément.
        int dastImpact = 0;
        if (input.isDastApplicable()) {
            dastImpact += severityPenalty(breakdown, "dast_high", input.getDastHigh(),
                    ncloc, useDensity, DENSITY_HIGH_FACTOR, ABS_PENALTY_HIGH);
            dastImpact += severityPenalty(breakdown, "dast_medium", input.getDastMedium(),
                    ncloc, useDensity, DENSITY_MEDIUM_FACTOR, ABS_PENALTY_MEDIUM);
        }
        score -= dastImpact;

        int sonarImpact = 0;
        if (input.isSonarAvailable()) {
            int secRating = ratingPenalty("Security", input.getSecurityRating(), breakdown);
            int relRating = ratingPenalty("Reliability", input.getReliabilityRating(), breakdown);
            sonarImpact += secRating + relRating;
            if (input.isCoverageKnown() && input.getCoverage() < 50) {
                sonarImpact += 5;
                breakdown.add(item("sonar_coverage", "SONAR_QUALITY",
                        "Couverture de tests < 50 % (" + formatCoverage(input.getCoverage()) + ")", -5, null,
                        "Informationnel si aucun test configuré"));
            }
            if (input.getSecurityHotspots() > 0) {
                int hsImpact = Math.min(HOTSPOT_PENALTY_CAP,
                        (int) Math.round(input.getSecurityHotspots() * 0.5));
                if (hsImpact > 0) {
                    sonarImpact += hsImpact;
                    breakdown.add(item("sonar_hotspots", "SONAR_QUALITY",
                            input.getSecurityHotspots() + " security hotspot(s) à revoir", -hsImpact, null, null));
                }
            }
            score -= sonarImpact;
        }

        // Vraie somme avant plafonds (contrairement au comportement historique où ce champ ne
        // faisait que refléter le score déjà plafonné) -- calculée à partir des sommes non
        // plafonnées de chaque dimension, avant le clamp final [0, 100]. Volontairement non
        // clampée : une valeur négative est le signal utile (diagnostic du 29/08/2026).
        int rawScoreBeforeCaps = 100 - severitySum - containerImpact - dastImpact - sonarImpact;

        score = Math.max(0, Math.min(100, score));
        String grade = scoreToGrade(score);
        String derivedVerdict = derivePostureVerdict(score, input.getStages());

        return SecurityScoreDto.builder()
                .score(score)
                .grade(grade)
                .derivedVerdict(derivedVerdict)
                .breakdown(breakdown)
                .rawScoreBeforeCaps(rawScoreBeforeCaps)
                .appliedCaps(appliedCaps)
                .build();
    }

    /**
     * Rogne la somme d'un groupe de buckets déjà individuellement calculés/plafonnés -- rognage
     * de la somme finale (pas d'arrêt anticipé de l'accumulation). N'enregistre l'id du plafond
     * dans {@code appliedCaps} que s'il a réellement fallu rogner (no-op sinon, comportement
     * historique préservé à l'identique).
     */
    private static int applyGlobalCap(int sum, int cap, String capId, List<String> appliedCaps) {
        if (sum > cap) {
            appliedCaps.add(capId);
            return cap;
        }
        return sum;
    }

    /** Recherche le palier applicable (comptage brut -> impact), 0 si count &lt;= 0. */
    private static int tierImpact(int count, int[] thresholds, int[] impacts) {
        if (count <= 0) return 0;
        for (int i = 0; i < thresholds.length; i++) {
            if (count <= thresholds[i]) {
                return impacts[i];
            }
        }
        return impacts[impacts.length - 1];
    }

    private int containerTierPenalty(
            List<ScoreBreakdownItemDto> breakdown,
            String severityKey,
            int count,
            int[] thresholds,
            int[] impacts
    ) {
        int impact = tierImpact(count, thresholds, impacts);
        if (impact > 0) {
            breakdown.add(item("container_" + severityKey, "DEFECTDOJO",
                    count + " " + severityKey + "(s) conteneur (Grype) — palier absolu, indépendant de ncloc",
                    -impact, null,
                    "Palier provisoire (échantillon 30 pipelines, 29/08/2026) — voir SecurityScoringService"));
        }
        return impact;
    }

    /** @deprecated Utiliser {@link #computePostureScore} — conservé pour compatibilité tests. */
    @Deprecated
    public SecurityScoreDto compute(SecurityScoreInput input) {
        HardGateInput hg = HardGateInput.builder()
                .secrets(input != null ? input.getSecrets() : 0)
                .ddCritical(input != null && input.getDdBySeverity() != null
                        ? input.getDdBySeverity().getOrDefault("critical", 0) : 0)
                .sonarBlockers(input != null ? input.getSonarBlockers() : 0)
                .sonarQgStatus(input != null ? input.getSonarQgStatus() : null)
                .defectDojoAvailable(input != null && input.isDefectDojoAvailable())
                .sonarAvailable(input != null && input.isSonarAvailable())
                .build();
        HardGateEvaluation gates = evaluateHardGates(hg);
        if (!gates.violations().isEmpty() || !gates.indeterminateSources().isEmpty()) {
            return SecurityScoreDto.builder()
                    .score(0)
                    .grade("E")
                    .derivedVerdict("NOT_RECOMMENDED")
                    .breakdown(List.of())
                    .rawScoreBeforeCaps(0)
                    .appliedCaps(List.of())
                    .build();
        }
        return computePostureScore(input);
    }

    public static String ratingToLetter(Object ratingValue) {
        if (ratingValue == null) return null;
        String s = String.valueOf(ratingValue).trim().toUpperCase(Locale.ROOT);
        if (s.length() == 1 && s.charAt(0) >= 'A' && s.charAt(0) <= 'E') {
            return s;
        }
        try {
            int n = (int) Math.round(Double.parseDouble(s));
            return switch (n) {
                case 1 -> "A";
                case 2 -> "B";
                case 3 -> "C";
                case 4 -> "D";
                case 5 -> "E";
                default -> null;
            };
        } catch (Exception e) {
            return null;
        }
    }

    public static int ratingNumeric(Object ratingValue) {
        if (ratingValue == null) return 0;
        String letter = ratingToLetter(ratingValue);
        if (letter != null) {
            return switch (letter) {
                case "A" -> 1;
                case "B" -> 2;
                case "C" -> 3;
                case "D" -> 4;
                case "E" -> 5;
                default -> 0;
            };
        }
        return 0;
    }

    /** Compte brut (comportement historique, non pondéré par CVSS) — utilisé par le DAST. */
    private int severityPenalty(
            List<ScoreBreakdownItemDto> breakdown,
            String severityKey,
            int count,
            int ncloc,
            boolean useDensity,
            double densityFactor,
            double absFactor
    ) {
        return severityPenalty(breakdown, severityKey, count, count, null, ncloc, useDensity, densityFactor, absFactor);
    }

    /**
     * @param rawCount      compte brut, affiché tel quel dans le libellé (jamais de décimale visible)
     * @param weightedCount compte utilisé pour le calcul — identique à rawCount si pas de CVSS connu
     *                      (repli sûr, comportement inchangé), sinon pondéré par {@link #cvssWeighting}
     * @param cvssNote      suffixe optionnel affiché dans le libellé quand la pondération CVSS
     *                      s'écarte notablement de 1.0 (null sinon)
     */
    private int severityPenalty(
            List<ScoreBreakdownItemDto> breakdown,
            String severityKey,
            int rawCount,
            double weightedCount,
            String cvssNote,
            int ncloc,
            boolean useDensity,
            double densityFactor,
            double absFactor
    ) {
        if (rawCount <= 0) return 0;
        int impact;
        String label;
        if (useDensity) {
            double density = weightedCount * 1000.0 / ncloc;
            impact = (int) Math.round(Math.min(30, density * densityFactor));
            label = rawCount + " " + severityKey + "(s) — densité "
                    + String.format(Locale.ROOT, "%.2f", density) + " / 1000 LOC";
        } else {
            impact = (int) Math.round(weightedCount * absFactor);
            label = rawCount + " " + severityKey + "(s) (DefectDojo, comptage absolu — ncloc inconnu)";
        }
        if (cvssNote != null) {
            label += " " + cvssNote;
        }
        if (impact > 0) {
            breakdown.add(item("dd_" + severityKey, "DEFECTDOJO", label, -impact, null,
                    useDensity ? "Pénalité basée sur la densité (ncloc=" + ncloc + ")" : null));
        }
        return impact;
    }

    private record CvssWeighting(double weightedCount, String note) {}

    /**
     * Pondère un compte de findings par le CVSS moyen observé dans son bucket de sévérité, en
     * modulant (±50 % max) autour du point médian CVSS v3.1 standard de cette sévérité. Repli sûr :
     * sans donnée CVSS pour ce bucket, retourne le compte brut inchangé (score identique à avant
     * ce changement).
     */
    private CvssWeighting cvssWeighting(String severityKey, int rawCount, SecurityScoreInput input) {
        if (rawCount <= 0) {
            return new CvssWeighting(0, null);
        }
        Map<String, Double> avgMap = input.getAvgCvssBySeverity();
        Map<String, Integer> knownMap = input.getCvssKnownCountBySeverity();
        Double avg = avgMap != null ? avgMap.get(severityKey) : null;
        Integer known = knownMap != null ? knownMap.get(severityKey) : null;
        if (avg == null || known == null || known <= 0) {
            return new CvssWeighting(rawCount, null);
        }
        double midpoint = switch (severityKey) {
            case "critical" -> 9.5;
            case "high" -> 8.0;
            case "medium" -> 5.5;
            case "low" -> 2.0;
            default -> 1.0;
        };
        double weight = Math.max(0.5, Math.min(1.5, avg / midpoint));
        int unknown = Math.max(0, rawCount - known);
        double weightedCount = (known * weight) + unknown;
        String note = Math.abs(weight - 1.0) >= 0.05
                ? "(CVSS moy. " + String.format(Locale.ROOT, "%.1f", avg) + ", pondéré ×"
                        + String.format(Locale.ROOT, "%.2f", weight) + ")"
                : null;
        return new CvssWeighting(weightedCount, note);
    }

    private int ratingPenalty(String dimension, String letter, List<ScoreBreakdownItemDto> breakdown) {
        if (letter == null || letter.isBlank()) return 0;
        int impact = switch (letter.toUpperCase(Locale.ROOT)) {
            case "D" -> "Security".equals(dimension) ? 10 : 5;
            case "E" -> "Security".equals(dimension) ? 15 : 8;
            default -> 0;
        };
        if (impact > 0) {
            breakdown.add(item("sonar_rating_" + dimension.toLowerCase(Locale.ROOT), "SONAR_QUALITY",
                    "Rating " + dimension + " " + letter + " (SonarQube)", -impact, null, null));
        }
        return impact;
    }

    private static String derivePostureVerdict(int score, List<QualityGateStageDto> stages) {
        boolean warnStage = stages != null && stages.stream()
                .anyMatch(s -> "WARN".equals(s.getStatus()));
        if (score < POSTURE_WARN_THRESHOLD || warnStage) {
            return "WITH_WARNINGS";
        }
        return "RECOMMENDED";
    }

    private static String buildHardGateSummary(List<HardGateViolationDto> violations) {
        if (violations.isEmpty()) {
            return null;
        }
        List<String> parts = violations.stream()
                .map(HardGateViolationDto::getMessage)
                .toList();
        return "Vous devez d'abord résoudre : " + String.join(", ", parts);
    }

    private static HardGateViolationDto violation(String id, String label, String message, String status) {
        return HardGateViolationDto.builder()
                .id(id)
                .label(label)
                .message(message)
                .status(status)
                .build();
    }

    private static ScoreBreakdownItemDto item(
            String id, String category, String label, int impact, Integer cap, String detail
    ) {
        return ScoreBreakdownItemDto.builder()
                .id(id)
                .category(category)
                .label(label)
                .impact(impact)
                .capScore(cap)
                .detail(detail)
                .build();
    }

    private static String stringVal(Object o) {
        return o == null ? "" : String.valueOf(o);
    }

    private static String formatCoverage(double coverage) {
        if (coverage <= 0) return "0 %";
        return String.format(Locale.ROOT, "%.1f %%", coverage);
    }

    public static String scoreToGrade(int score) {
        if (score >= 90) return "A";
        if (score >= 75) return "B";
        if (score >= 60) return "C";
        if (score >= 40) return "D";
        return "E";
    }

    /**
     * Même logique que {@code QualityGateService.resolveDeterministicVerdict} —
     * exposée pour l'agrégation lot (Chantier 4) sans coupler au controller QG.
     */
    public String resolveDeterministicVerdict(HardGateEvaluation hardGates, SecurityScoreDto postureScore) {
        if (hardGates != null && !hardGates.violations().isEmpty()) {
            return "NOT_RECOMMENDED";
        }
        if (hardGates != null && (!hardGates.indeterminateSources().isEmpty()
                || (hardGates.indeterminate() != null && !hardGates.indeterminate().isEmpty()))) {
            return "INDETERMINE";
        }
        if (postureScore != null && postureScore.getDerivedVerdict() != null) {
            return postureScore.getDerivedVerdict();
        }
        return "WITH_WARNINGS";
    }

    private static SecurityScoreDto emptyScore() {
        return SecurityScoreDto.builder()
                .score(100)
                .grade("A")
                .derivedVerdict("RECOMMENDED")
                .breakdown(List.of())
                .rawScoreBeforeCaps(100)
                .appliedCaps(List.of())
                .build();
    }
}
