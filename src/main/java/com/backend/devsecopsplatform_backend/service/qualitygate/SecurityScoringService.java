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

        if (input.getSecrets() > 0) {
            violations.add(violation("secrets", "Secrets exposés (Gitleaks)",
                    input.getSecrets() + " secret(s) exposé(s)", "VIOLATED"));
        }

        if (!input.isDefectDojoAvailable()) {
            indeterminateSources.add("Centralisation des vulnérabilités");
            indeterminate.add(violation("dd_critical", "Vulnérabilités critiques (DefectDojo)",
                    "Centralisation des vulnérabilités indisponible — état inconnu", "INDETERMINATE"));
        } else if (input.getDdCritical() > 0) {
            violations.add(violation("dd_critical", "Vulnérabilités critiques (DefectDojo)",
                    input.getDdCritical() + " vulnérabilité(s) critique(s)", "VIOLATED"));
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
        Map<String, Integer> dd = input.getDdBySeverity() != null ? input.getDdBySeverity() : Map.of();

        int crit = dd.getOrDefault("critical", 0);
        int high = dd.getOrDefault("high", 0);
        int med = dd.getOrDefault("medium", 0);
        int low = dd.getOrDefault("low", 0);
        int ncloc = Math.max(0, input.getNcloc());
        boolean useDensity = ncloc >= 100;

        int score = 100;
        score -= severityPenalty(breakdown, "critical", crit, ncloc, useDensity, DENSITY_CRITICAL_FACTOR, ABS_PENALTY_CRITICAL);
        score -= severityPenalty(breakdown, "high", high, ncloc, useDensity, DENSITY_HIGH_FACTOR, ABS_PENALTY_HIGH);
        score -= severityPenalty(breakdown, "medium", med, ncloc, useDensity, DENSITY_MEDIUM_FACTOR, ABS_PENALTY_MEDIUM);
        score -= severityPenalty(breakdown, "low", low, ncloc, useDensity, DENSITY_LOW_FACTOR, ABS_PENALTY_LOW);

        if (input.isSonarAvailable()) {
            score -= ratingPenalty("Security", input.getSecurityRating(), breakdown);
            score -= ratingPenalty("Reliability", input.getReliabilityRating(), breakdown);
            if (input.isCoverageKnown() && input.getCoverage() < 50) {
                score -= 5;
                breakdown.add(item("sonar_coverage", "SONAR_QUALITY",
                        "Couverture de tests < 50 % (" + formatCoverage(input.getCoverage()) + ")", -5, null,
                        "Informationnel si aucun test configuré"));
            }
            if (input.getSecurityHotspots() > 0) {
                int hsImpact = Math.min(HOTSPOT_PENALTY_CAP,
                        (int) Math.round(input.getSecurityHotspots() * 0.5));
                if (hsImpact > 0) {
                    score -= hsImpact;
                    breakdown.add(item("sonar_hotspots", "SONAR_QUALITY",
                            input.getSecurityHotspots() + " security hotspot(s) à revoir", -hsImpact, null, null));
                }
            }
        }

        score = Math.max(0, Math.min(100, score));
        String grade = scoreToGrade(score);
        String derivedVerdict = derivePostureVerdict(score, input.getStages());

        return SecurityScoreDto.builder()
                .score(score)
                .grade(grade)
                .derivedVerdict(derivedVerdict)
                .breakdown(breakdown)
                .rawScoreBeforeCaps(score)
                .appliedCaps(List.of())
                .build();
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

    private int severityPenalty(
            List<ScoreBreakdownItemDto> breakdown,
            String severityKey,
            int count,
            int ncloc,
            boolean useDensity,
            double densityFactor,
            double absFactor
    ) {
        if (count <= 0) return 0;
        int impact;
        String label;
        if (useDensity) {
            double density = count * 1000.0 / ncloc;
            impact = (int) Math.round(Math.min(30, density * densityFactor));
            label = count + " " + severityKey + "(s) — densité "
                    + String.format(Locale.ROOT, "%.2f", density) + " / 1000 LOC";
        } else {
            impact = severityKey.equals("low")
                    ? (int) Math.round(count * absFactor)
                    : (int) Math.round(count * absFactor);
            label = count + " " + severityKey + "(s) (DefectDojo, comptage absolu — ncloc inconnu)";
        }
        if (impact > 0) {
            breakdown.add(item("dd_" + severityKey, "DEFECTDOJO", label, -impact, null,
                    useDensity ? "Pénalité basée sur la densité (ncloc=" + ncloc + ")" : null));
        }
        return impact;
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

    private static String scoreToGrade(int score) {
        if (score >= 90) return "A";
        if (score >= 75) return "B";
        if (score >= 60) return "C";
        if (score >= 40) return "D";
        return "E";
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
