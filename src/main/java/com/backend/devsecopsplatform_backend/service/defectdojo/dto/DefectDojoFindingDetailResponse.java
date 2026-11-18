package com.backend.devsecopsplatform_backend.service.defectdojo.dto;

import lombok.Builder;
import lombok.Data;

import java.util.List;
import java.util.Map;
import java.util.UUID;

@Data
@Builder
public class DefectDojoFindingDetailResponse {

    private int id;
    private String title;
    /** Texte lisible du scanner (métadonnées techniques extraites dans {@link #scannerFields}). */
    private String description;
    /** Métadonnées techniques du scanner (libellé français → valeur brute) : PURL, source, méthode… */
    private Map<String, String> scannerFields;
    private String severity;
    private String status;
    private boolean active;
    private boolean verified;
    private boolean mitigated;
    private boolean falsePositive;
    private boolean outOfScope;
    private boolean riskAccepted;

    private String cwe;
    private String cve;
    private Double cvssScore;
    private String filePath;
    private Integer line;
    private Integer lineEnd;
    private String componentName;
    private String scanType;
    private String testTitle;
    private String toolName;

    private String mitigation;
    private String impact;
    private String references;
    private String created;
    private String mitigatedDate;

    private String branch;
    private String engagementName;
    private String productName;

    private String codeSnippet;
    private String codeContextSource;
    /** Message UI : chemin conteneur, fallback Dockerfile, etc. */
    private String codeContextHint;
    /** Fichier du dépôt dont provient {@link #codeSnippet} (ex. main.py déduit du Dockerfile pour un finding DAST). */
    private String codeFilePath;

    private UUID applicationId;

    // ── Analyse dynamique (OWASP ZAP) ────────────────────────────────────────────────────────

    /** Identifiant de la règle chez l'outil (ZAP : pluginid, ex. 10035 pour HSTS). */
    private String toolRuleId;
    /** true = finding DAST : ZAP a testé l'application déployée (réponses HTTP), pas le code source. */
    private boolean dynamicFinding;
    /** URL(s) testées par ZAP pour ce finding (endpoints DefectDojo). */
    private List<String> analyzedUrls;
    /** Contrôle des en-têtes fait par la plateforme sur la 1re URL, au moment de l'analyse. */
    private LiveHttpCheck liveCheck;
    /** Couches réellement traversées par la réponse (Cloudflare, Ingress Traefik généré par EnviroTest, conteneur). */
    private List<String> exposureChain;

    @Data
    @Builder
    public static class LiveHttpCheck {
        private String url;
        private Integer status;
        /** Date ISO du contrôle (peut être postérieur au scan ZAP). */
        private String checkedAt;
        /** En-têtes de sécurité utiles (noms en minuscules) ; valeurs des cookies masquées. */
        private Map<String, String> headers;
        /** En-têtes de sécurité attendus mais absents de la réponse. */
        private List<String> missingHeaders;
        /** Origine envoyée pour le test CORS (null si pas de test CORS). */
        private String corsTestOrigin;
        /** Message si le contrôle n'a pas pu être fait ou n'est pas exploitable (environnement arrêté…). */
        private String error;
    }
}
