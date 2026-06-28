package com.backend.devsecopsplatform_backend.service.qualitygate;

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
 * Score de posture 0–100. Les pénalités de sévérité proviennent uniquement de DefectDojo
 * (pas de double comptage avec SonarQube). SonarQube contribue via ratings, QG et hotspots.
 */
@Service
public class SecurityScoringService {

    private static final int PENALTY_CRITICAL = 8;
    private static final int PENALTY_HIGH = 3;
    private static final int PENALTY_MEDIUM = 1;
    private static final double PENALTY_LOW = 0.25;
    private static final int CAP_SECRETS = 40;
    private static final int CAP_CONTAINER = 50;
    private static final int CAP_SONAR_QG = 60;
    private static final int HOTSPOT_PENALTY_CAP = 10;

    public SecurityScoreDto compute(SecurityScoreInput input) {
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

        int score = 100;
        if (crit > 0) {
            int impact = crit * PENALTY_CRITICAL;
            score -= impact;
            breakdown.add(item("dd_critical", "DEFECTDOJO",
                    crit + " vulnérabilité(s) critique(s) (DefectDojo)", -impact, null, null));
        }
        if (high > 0) {
            int impact = high * PENALTY_HIGH;
            score -= impact;
            breakdown.add(item("dd_high", "DEFECTDOJO",
                    high + " vulnérabilité(s) élevée(s) (DefectDojo)", -impact, null, null));
        }
        if (med > 0) {
            int impact = med * PENALTY_MEDIUM;
            score -= impact;
            breakdown.add(item("dd_medium", "DEFECTDOJO",
                    med + " vulnérabilité(s) moyenne(s) (DefectDojo)", -impact, null, null));
        }
        if (low > 0) {
            int impact = (int) Math.round(low * PENALTY_LOW);
            if (impact > 0) {
                score -= impact;
                breakdown.add(item("dd_low", "DEFECTDOJO",
                        low + " vulnérabilité(s) faible(s) (DefectDojo)", -impact, null, null));
            }
        }

        int rawBeforeCaps = Math.max(0, Math.min(100, score));

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

        // Plafonds bloquants appliqués en dernier (score final ≤ plafond)
        if (input.getSecrets() > 0) {
            appliedCaps.add("cap_secrets");
            breakdown.add(item("cap_secrets", "BLOCKING_CAP",
                    input.getSecrets() + " secret(s) exposé(s)", 0, CAP_SECRETS,
                    "Score final plafonné à " + CAP_SECRETS));
            score = applyCap(score, CAP_SECRETS);
        }

        int containerThreshold = input.getContainerCriticalThreshold();
        if (input.getContainerCritical() > containerThreshold) {
            appliedCaps.add("cap_container");
            breakdown.add(item("cap_container", "BLOCKING_CAP",
                    "Container critical " + input.getContainerCritical()
                            + " > seuil CI " + containerThreshold, 0, CAP_CONTAINER,
                    "Score final plafonné à " + CAP_CONTAINER));
            score = applyCap(score, CAP_CONTAINER);
        }

        if (input.isSonarAvailable() && "ERROR".equalsIgnoreCase(stringVal(input.getSonarQgStatus()))) {
            appliedCaps.add("cap_sonar_qg");
            breakdown.add(item("cap_sonar_qg", "BLOCKING_CAP",
                    "Quality Gate SonarQube en ERROR", 0, CAP_SONAR_QG,
                    "Score final plafonné à " + CAP_SONAR_QG));
            score = applyCap(score, CAP_SONAR_QG);
        }

        score = Math.max(0, Math.min(100, score));
        String grade = scoreToGrade(score);
        String derivedVerdict = deriveVerdict(score, appliedCaps, input.getStages());

        return SecurityScoreDto.builder()
                .score(score)
                .grade(grade)
                .derivedVerdict(derivedVerdict)
                .breakdown(breakdown)
                .rawScoreBeforeCaps(rawBeforeCaps)
                .appliedCaps(appliedCaps)
                .build();
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

    private static int applyCap(int score, int cap) {
        return Math.min(score, cap);
    }

    private static String scoreToGrade(int score) {
        if (score >= 90) return "A";
        if (score >= 75) return "B";
        if (score >= 60) return "C";
        if (score >= 40) return "D";
        return "E";
    }

    private static String deriveVerdict(int score, List<String> appliedCaps, List<QualityGateStageDto> stages) {
        boolean blockingStage = stages != null && stages.stream()
                .anyMatch(s -> s.isBlocking() && "FAIL".equals(s.getStatus()));
        if (!appliedCaps.isEmpty() || blockingStage || score < 40) {
            return "NOT_RECOMMENDED";
        }
        boolean warnStage = stages != null && stages.stream()
                .anyMatch(s -> "WARN".equals(s.getStatus()));
        if (score < 75 || warnStage) {
            return "WITH_WARNINGS";
        }
        return "RECOMMENDED";
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
