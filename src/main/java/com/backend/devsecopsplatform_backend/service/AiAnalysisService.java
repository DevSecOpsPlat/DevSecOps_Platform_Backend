package com.backend.devsecopsplatform_backend.service;

import com.backend.devsecopsplatform_backend.controller.ai.AnalyzeArtifactResponse;
import com.backend.devsecopsplatform_backend.controller.ai.VulnerabilityItem;
import com.backend.devsecopsplatform_backend.controller.finding.FindingAiRemediationResponse;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.*;
import org.springframework.stereotype.Service;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestTemplate;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Service d'analyse des artifacts par IA. Plusieurs fournisseurs supportés (sans carte bancaire) :
 * - groq : gratuit, clé sur console.groq.com (recommandé)
 * - huggingface : gratuit, token sur huggingface.co/settings/tokens
 * - ollama : local, pas de clé (ollama run llama2)
 * - gemini : Google (quota souvent limité en free tier)
 */
@Service
@Slf4j
@RequiredArgsConstructor
public class AiAnalysisService {

    private static final String GEMINI_BASE_URL = "https://generativelanguage.googleapis.com/v1beta/models/";
    private static final String GROQ_URL = "https://api.groq.com/openai/v1/chat/completions";
    private static final String HUGGINGFACE_INFERENCE_URL = "https://api-inference.huggingface.co/models/";
    private static final String OLLAMA_DEFAULT_URL = "http://localhost:11434";
    /** Limite de caractères pour réduire la consommation de tokens. */
    private static final int MAX_ARTIFACT_LENGTH = 120_000;
    /** Contexte finding + evidence (hors snippet de code utilisateur). */
    private static final int MAX_FINDING_CONTEXT_CHARS = 16_000;
    /** Snippet de code optionnel (collé par l'utilisateur ou futur fetch GitLab). */
    private static final int MAX_CODE_SNIPPET_CHARS = 32_000;
    private static final int DEFAULT_RETRY_DELAY_SECONDS = 45;
    private static final int MAX_CHAT_TURNS = 24;
    private static final int MAX_CHAT_MESSAGE_CHARS = 10_000;

    private final ObjectMapper objectMapper;

    public record ChatTurn(String role, String content) {}

    /** gemini | groq | huggingface | ollama */
    @Value("${ai.provider:groq}")
    private String aiProvider;

    @Value("${ai.enabled:true}")
    private boolean aiEnabled;

    // Gemini
    @Value("${ai.gemini.api-key:}")
    private String geminiApiKey;
    @Value("${ai.gemini.model:gemini-2.0-flash}")
    private String geminiModel;

    // Groq (gratuit, sans carte - console.groq.com)
    @Value("${ai.groq.api-key:}")
    private String groqApiKey;
    @Value("${ai.groq.model:llama-3.3-70b-versatile}")
    private String groqModel;

    // Hugging Face (gratuit - huggingface.co/settings/tokens)
    @Value("${ai.huggingface.token:}")
    private String huggingfaceToken;
    @Value("${ai.huggingface.model:HuggingFaceH4/zephyr-7b-beta}")
    private String huggingfaceModel;

    // Ollama (local, pas de clé)
    @Value("${ai.ollama.url:http://localhost:11434}")
    private String ollamaUrl;
    @Value("${ai.ollama.model:llama2}")
    private String ollamaModel;
    /** Température Ollama pour modèles autres que DeepSeek (DeepSeek utilise 0.1 dans le code). */
    @Value("${ai.ollama.temperature:0.2}")
    private double ollamaTemperature;
    /** Tokens max générés par Ollama (remédiation JSON longue) ; défaut élevé pour éviter un JSON coupé au milieu. */
    @Value("${ai.ollama.num-predict:8192}")
    private int ollamaNumPredict;

    /**
     * Analyse le contenu d'un artifact (JSON ou texte) et renvoie les vulnérabilités
     * détectées avec description, où les trouver et comment les corriger.
     *
     * @param artifactContent Contenu brut de l'artifact (rapport de scan).
     * @param artifactSource  Optionnel : type (trivy, sonarqube, etc.) pour aider l'IA.
     * @return Résumé + liste de vulnérabilités avec remédiation.
     */
    public AnalyzeArtifactResponse analyzeArtifact(String artifactContent, String artifactSource) {
        if (!aiEnabled) {
            return errorResponse("Analyse IA désactivée (ai.enabled=true pour activer).");
        }
        String provider = (aiProvider != null) ? aiProvider.strip().toLowerCase() : "groq";
        if (!isProviderConfigured(provider)) {
            return errorResponse("Provider '" + provider + "' non configuré. " + getConfigHint(provider));
        }

        String content = artifactContent;
        if (content.length() > MAX_ARTIFACT_LENGTH) {
            log.info("Artifact tronqué de {} à {} caractères", content.length(), MAX_ARTIFACT_LENGTH);
            content = content.substring(0, MAX_ARTIFACT_LENGTH) + "\n\n[... contenu tronqué ...]";
        }

        String sourceHint = (artifactSource != null && !artifactSource.isBlank())
                ? " (format probable: " + artifactSource + ")"
                : "";
        String prompt = buildPrompt(content, sourceHint);

        try {
            String jsonResponse = callAiProviderWithFallback(provider, prompt);
            return parseGeminiResponse(jsonResponse);
        } catch (Exception e) {
            log.error("Erreur analyse IA ({}): {}", provider, e.getMessage());
            String userMessage = buildUserFriendlyErrorMessage(e, provider);
            return AnalyzeArtifactResponse.builder()
                    .summary(userMessage)
                    .vulnerabilities(List.of())
                    .build();
        }
    }

    /**
     * Remédiation ciblée pour un finding (pas le rapport complet du pipeline) : limite tokens/quota.
     * Pour éviter les plafonds Groq/Gemini : {@code ai.provider=ollama} (Ollama local, pas de quota cloud).
     */
    public FindingAiRemediationResponse analyzeFindingRemediation(String findingContextBlock, String optionalCodeSnippet) {
        if (!aiEnabled) {
            return FindingAiRemediationResponse.builder()
                    .problemSummary("Analyse IA désactivée (ai.enabled=true).")
                    .build();
        }
        String provider = (aiProvider != null) ? aiProvider.strip().toLowerCase() : "groq";
        if (!isProviderConfigured(provider)) {
            return FindingAiRemediationResponse.builder()
                    .problemSummary("Provider '" + provider + "' non configuré. " + getConfigHint(provider))
                    .build();
        }

        String ctx = findingContextBlock != null ? findingContextBlock : "";
        if (ctx.length() > MAX_FINDING_CONTEXT_CHARS) {
            ctx = ctx.substring(0, MAX_FINDING_CONTEXT_CHARS) + "\n\n[... contexte tronqué ...]";
        }
        String snippet = optionalCodeSnippet != null ? optionalCodeSnippet : "";
        if (snippet.length() > MAX_CODE_SNIPPET_CHARS) {
            snippet = snippet.substring(0, MAX_CODE_SNIPPET_CHARS) + "\n\n[... snippet tronqué ...]";
        }

        String prompt = buildFindingRemediationPrompt(ctx, snippet, isLikelySecretOrCredentialFinding(ctx));
        try {
            String jsonResponse = callAiProviderWithFallback(provider, prompt);
            return parseFindingRemediationResponse(jsonResponse);
        } catch (Exception e) {
            log.error("Erreur remédiation finding IA ({}): {}", provider, e.getMessage());
            return FindingAiRemediationResponse.builder()
                    .problemSummary(buildUserFriendlyErrorMessage(e, provider))
                    .build();
        }
    }

    private String remediationSecretRulesAppendix(boolean secretOrCredentialFinding) {
        return secretOrCredentialFinding ? """

                RÈGLES OBLIGATOIRES — Secrets / clés / tokens / mots de passe / identifiants (ce finding en relève probablement) :
                - Ne JAMAIS proposer de coller une nouvelle clé, token, ClientId, UserPoolId ou secret en dur dans le code source (ni valeur fictive « nouvelle-clé »).
                - La bonne pratique : EXTERNALISER (variables d'environnement, coffre secrets, pas dans Git).

                Contexte plateforme (important pour remediationSteps) :
                - Le scan a souvent été lancé depuis un pipeline hébergé sur GitLab dans ce projet plateforme. La mention « GitLab » est un EXEMPLE de CI (variables Settings → CI/CD → Variables, masked/protected), pas une obligation : beaucoup de développeurs utilisent GitHub Actions Secrets, ou ne passent pas par GitLab pour leur app React/AWS.
                - Les remediationSteps doivent être UNIVERSELLES et ADAPTATIVES : proposer PLUSIEURS options selon le cas — (1) React local : fichier .env / .env.local dans .gitignore, préfixes VITE_ (Vite), REACT_APP_ (CRA), import.meta.env / process.env ; (2) déploiement AWS : variables d'environnement dans Amplify Console, Elastic Beanstalk, Lambda configuration, ECS task definition, ou AWS Systems Manager Parameter Store / Secrets Manager ; (3) CI : GitHub Actions secrets, GitLab CI variables, ou autre ; (4) ne pas imposer GitLab si le contexte évoque React+AWS sans GitLab.
                - Toujours dire clairement : « garder la valeur hors du dépôt » (fichier env non commité, console AWS, ou secrets CI), puis « lire la valeur dans le code via variable d'environnement », puis rebuild/redeploy si besoin.

                - Dans suggestedPatch et fullFileRewrite : UNIQUEMENT des placeholders (import.meta.env.VITE_*, process.env.* pour Node/build) — jamais de littéral secret.
                - Pour Cognito dans une SPA React : rappeler que les identifiants « publics » côté client restent à préférer via env injectée au build, pas en dur dans cognitoConfig.js versionné.

                - Si l'utilisateur doit conserver l'accès au service : garder la valeur dans le gestionnaire adapté (pas dans Git), pas « supprimer sans remplacement ».

                """ : """

                Si le finding concerne des identifiants sensibles (même ambigu) : privilégier variables d'environnement, .env non versionné (React/Vite), secrets CI ou AWS selon le déploiement — pas de valeurs en dur dans le dépôt.

                """;
    }

    /** Prompt court pour DeepSeek-Coder (Ollama) ; mêmes règles secrets que le prompt long. */
    private boolean useDeepSeekStyleRemediationPrompt() {
        String p = aiProvider != null ? aiProvider.strip().toLowerCase(Locale.ROOT) : "";
        return "ollama".equals(p)
                && ollamaModel != null
                && ollamaModel.toLowerCase(Locale.ROOT).contains("deepseek");
    }

    /** Contraintes métier : l'utilisateur voit le finding dans l'app, sans accès édition pipeline. */
    private static final String REMEDIATION_PLATFORM_AUDIENCE = """
            Contexte plateforme (à respecter strictement) :
            L'utilisateur lit ce finding dans une application DevSecOps : il voit les problèmes détectés sur son projet. En général il N'A PAS accès pour modifier les pipelines CI/CD (GitLab CI, GitHub Actions, .gitlab-ci.yml, jobs, runners) depuis cet écran. Il peut corriger le dépôt en local / IDE, pousser ses changements, et surtout relancer une analyse depuis cette plateforme.
            INTERDIT sauf preuve explicite dans le contexte : « configure ton pipeline », « ajoute Semgrep dans le CI », « modifie le workflow GitHub Actions », « étape dans le pipeline » pour ce type de finding.
            Ne dis JAMAIS de mettre l'attribut HTML integrity (SRI) ou crossorigin dans des « variables d'environnement » : ce sont des attributs dans le HTML ou les templates du dépôt, pas des env vars serveur.
            À privilégier : fichier à ouvrir, modification concrète du code ou du markup, commandes sur la machine du développeur (openssl, npm, git, build local), puis commit/push et « relancer l'analyse / le scan depuis le tableau de bord de l'application ».
            Stack du projet testé : le contexte finding commence par « TECHNOLOGIES_DEDUITES » (nom/description du projet sur la plateforme, dépôt GitHub/GitLab, chemins type package.json ou pom.xml, chemin d'artefact, extrait de code). Utilise ces indices pour proposer des commandes et exemples adaptés (npm/yarn/pnpm vs mvn/gradle vs pip, Angular/React, etc.). Si un indice contredit filePath ou packageName du finding, privilégie les faits du finding.
            """;

    private String buildFindingRemediationPrompt(String findingContext, String codeSnippet, boolean secretOrCredentialFinding) {
        String secretRules = remediationSecretRulesAppendix(secretOrCredentialFinding);

        if (useDeepSeekStyleRemediationPrompt()) {
            String snippetSection = codeSnippet.isBlank()
                    ? "(Aucun extrait de code — base-toi sur le contexte du scanner.)"
                    : "\nCode concerné :\n```\n%s\n```\n".formatted(codeSnippet);
            return """
                    Tu es un expert en sécurité. Analyse ce problème et donne une solution précise.

                    %s

                    %s

                    Contexte du problème :
                    %s
                    %s

                    Exigences de détail (obligatoire) :
                    - remediationSteps : 4 à 8 étapes courtes et actionnables (une chaîne = une étape). Pas de généralités vagues du type « ajouter integrity » sans dire COMMENT (outil, commande, syntaxe).
                    - Pour SRI / CDN / scripts ou CSS externes : inclure au moins une commande concrète pour calculer le hash (ex. openssl) ET un exemple de balise ou ligne complète (integrity="sha384-..." ou sha256-..., crossorigin="anonymous" si pertinent).
                    - suggestedPatch : fragment réellement copiable (HTML, diff, config) quand une correction locale existe ; ne pas laisser vide si un extrait de code suffit.
                    - verificationCommands : commandes sur poste développeur (openssl, npm, grep, build local) ; PAS « lancer semgrep en CI ». verificationHints : peut inclure « relancer l'analyse depuis la plateforme » après correction.

                    Réponds UNIQUEMENT avec un JSON valide UTF-8, sans texte avant ou après, sans markdown, exactement aux clés :
                    {"problemSummary":"...","impact":"...","location":"...","remediationSteps":["..."],"suggestedPatch":"...","fullFileRewrite":"","verificationHints":["..."],"verificationCommands":["..."]}
                    (verificationCommands = commandes shell sur machine locale si pertinent ; sinon [].)
                    """.formatted(REMEDIATION_PLATFORM_AUDIENCE, secretRules, findingContext, snippetSection);
        }

        String snippetSection = codeSnippet.isBlank()
                ? "(Aucun extrait de code fourni — base-toi sur le contexte du scanner et propose une correction type : dépendance, config, ou pattern de code.)"
                : """
                Extrait de code fourni par l'utilisateur (peut être partiel) :
                ```
                %s
                ```
                """.formatted(codeSnippet);

        return """
                Tu es un expert sécurité applicative et développement DevSecOps. On te donne UN finding de scanner (SAST/SCA/secrets/etc.), pas tout le projet.

                %s

                %s

                Tâche :
                1) Expliquer clairement le problème et l'impact (ce qu'un attaquant pourrait faire).
                2) Préciser où ça se situe (fichier/ligne si présents, sinon package/CVE).
                3) Donner des étapes de remédiation que l'utilisateur peut faire sans accès pipeline : édition des fichiers du dépôt, commandes en local. Pour les findings SECRETS uniquement : rappeler variables d'environnement / secrets manager / fichiers .env non commités — pas pour SRI/HTML.
                4) Proposer une correction sous forme de patch : pour SCA = commande de mise à jour locale ; pour code/markup = extrait corrigé ; pour secrets = placeholders + où stocker la valeur (hors dépôt).
                5) fullFileRewrite : seulement si tu peux montrer le fichier ENTIER sans aucun secret littéral (sinon laisser vide et utiliser suggestedPatch).
                6) verificationHints : inclure quand c'est pertinent « après correction, relancer l'analyse depuis le tableau de bord de l'application » plutôt que supposer un accès CI. Revue de code / tests locaux possibles.
                7) verificationCommands : commandes sur la machine du développeur (npm, mvn, openssl, grep, build…). Ne pas imposer Semgrep/pipeline CI comme seule voie.

                Exigences de détail (obligatoire — le développeur doit pouvoir corriger sans deviner) :
                - remediationSteps : tableau de 4 à 8 chaînes ; chaque chaîne = UNE étape précise (quoi modifier, avec quel outil ou quelle syntaxe). Interdit : une seule phrase vague du type « inclure le hash en base64 dans integrity » sans expliquer comment obtenir le hash et comment rédiger l'attribut. Interdit : « mettre integrity dans les variables d'environnement ».
                - Exemples concrets : au moins une commande OU un fragment de code/HTML/config réel dans suggestedPatch ou réparti dans les étapes (ex. SRI : `openssl dgst -sha384 -binary fichier.css | openssl enc -base64` ou équivalent + ligne `<link rel="stylesheet" href="..." integrity="sha384-..." crossorigin="anonymous">`).
                - suggestedPatch : si le finding concerne du code ou du markup, fournir un extrait corrigé copiable (même court) plutôt que de le laisser vide.
                - verificationCommands : au moins une entrée lorsque le contexte permet une vérif en terminal local (openssl, npm audit, etc.).

                Réponds UNIQUEMENT avec un JSON valide UTF-8, sans markdown ni texte hors JSON, exactement de la forme :
                {"problemSummary":"...","impact":"...","location":"...","remediationSteps":["..."],"suggestedPatch":"...","fullFileRewrite":"","verificationHints":["..."],"verificationCommands":["..."]}

                Contexte du finding (métadonnées + extrait evidence éventuel) :
                %s

                %s
                """.formatted(REMEDIATION_PLATFORM_AUDIENCE, secretRules, findingContext, snippetSection);
    }

    /**
     * Heuristique pour activer les règles « secrets → variables CI/env » (évite que le modèle propose une nouvelle clé en dur).
     */
    static boolean isLikelySecretOrCredentialFinding(String findingContext) {
        if (findingContext == null || findingContext.isBlank()) {
            return false;
        }
        String c = findingContext.toLowerCase(Locale.ROOT);
        if (c.contains("scantype: secrets")) {
            return true;
        }
        if (c.contains("toolname: gitleaks") || c.contains("toolname: trufflehog")) {
            return true;
        }
        if (c.contains("generic api key")
                || (c.contains("hardcoded") && c.contains("secret"))
                || c.contains("hardcoded credential")
                || c.contains("secret detected")) {
            return true;
        }
        if (c.contains("toolname: semgrep") && (c.contains("secret") || c.contains("credential") || c.contains("password") || c.contains("api key"))) {
            return true;
        }
        if (c.contains("trivy") && c.contains("secret")) {
            return true;
        }
        // Cognito / AWS clients souvent flaggés comme clés génériques
        if (c.contains("cognito") && (c.contains("clientid") || c.contains("client_id") || c.contains("userpool"))) {
            return true;
        }
        return false;
    }

    private FindingAiRemediationResponse parseFindingRemediationResponse(String jsonText) {
        String toParse = extractJsonFromResponse(jsonText);
        try {
            JsonNode root = objectMapper.readTree(toParse);
            List<String> steps = new ArrayList<>();
            JsonNode arr = root.path("remediationSteps");
            if (arr.isArray()) {
                for (JsonNode s : arr) {
                    if (s.isTextual()) steps.add(s.asText());
                }
            }
            List<String> hints = new ArrayList<>();
            JsonNode h = root.path("verificationHints");
            if (h.isArray()) {
                for (JsonNode x : h) {
                    if (x.isTextual()) hints.add(x.asText());
                }
            }
            List<String> verifyCmds = new ArrayList<>();
            JsonNode vc = root.path("verificationCommands");
            if (vc.isArray()) {
                for (JsonNode x : vc) {
                    if (x.isTextual()) verifyCmds.add(x.asText());
                }
            }
            return FindingAiRemediationResponse.builder()
                    .problemSummary(root.path("problemSummary").asText(""))
                    .impact(root.path("impact").asText(""))
                    .location(root.path("location").asText(""))
                    .remediationSteps(steps)
                    .suggestedPatch(root.path("suggestedPatch").asText(""))
                    .fullFileRewrite(root.path("fullFileRewrite").asText(""))
                    .verificationHints(hints)
                    .verificationCommands(verifyCmds)
                    .build();
        } catch (Exception e) {
            log.warn("Parse remédiation finding IA: {}", e.getMessage());
            return FindingAiRemediationResponse.builder()
                    .rawModelOutput(toParse.length() > 8000 ? toParse.substring(0, 8000) + "..." : toParse)
                    .problemSummary("Réponse IA non-JSON ; voir rawModelOutput.")
                    .build();
        }
    }

    /**
     * Chat pédagogique sur un finding (historique user/assistant). Réponses en texte libre (pas de JSON).
     */
    public String chatAboutFinding(String findingContextBlock, String remediationSummary, String optionalCodeSnippet, List<ChatTurn> turns) {
        if (!aiEnabled) {
            return "Analyse IA désactivée (ai.enabled=true).";
        }
        String provider = (aiProvider != null) ? aiProvider.strip().toLowerCase() : "groq";
        if (!isProviderConfigured(provider)) {
            return "Provider '" + provider + "' non configuré. " + getConfigHint(provider);
        }
        if (turns == null || turns.isEmpty()) {
            return "Envoie au moins un message utilisateur.";
        }

        String fc = findingContextBlock != null ? findingContextBlock : "";
        if (fc.length() > MAX_FINDING_CONTEXT_CHARS) {
            fc = fc.substring(0, MAX_FINDING_CONTEXT_CHARS) + "\n[...tronqué]";
        }
        String remBlock = "";
        if (remediationSummary != null && !remediationSummary.isBlank()) {
            String r = remediationSummary.length() > 4000 ? remediationSummary.substring(0, 4000) + "..." : remediationSummary;
            remBlock = "\n\nRésumé de la remédiation IA déjà affichée (si l'utilisateur l'a générée) :\n" + r;
        }
        String snippet = optionalCodeSnippet != null ? optionalCodeSnippet.strip() : "";
        if (snippet.length() > MAX_CODE_SNIPPET_CHARS) {
            snippet = snippet.substring(0, MAX_CODE_SNIPPET_CHARS) + "\n\n[...extrait tronqué]";
        }
        String snippetBlock = "";
        if (!snippet.isBlank()) {
            snippetBlock = """

                    Extrait réel du dépôt lié au finding (positions de lignes possibles dans la marge) — à utiliser pour répondre précisément aux questions « que fait cette ligne », « comment corriger ici » :
                    ```
                    %s
                    ```
                    """.formatted(snippet);
        }
        String system = buildFindingChatSystemPrompt(fc, remBlock, snippetBlock);
        List<java.util.Map<String, String>> messages = buildChatMessagesForApi(system, turns);

        try {
            return callFindingChatWithFallback(provider, messages, system, turns);
        } catch (Exception e) {
            log.error("Erreur chat finding IA ({}): {}", provider, e.getMessage());
            return buildUserFriendlyErrorMessage(e, provider);
        }
    }

    private String buildFindingChatSystemPrompt(String findingContext, String remediationBlock, String codeSnippetSection) {
        boolean secretCtx = isLikelySecretOrCredentialFinding(findingContext);
        String secretChat = secretCtx ? """

                IMPORTANT — Secrets / clés / Cognito / API / React / AWS :
                - Ne dis JAMAIS de remplacer une clé par une autre valeur en dur dans le code.
                - L'accès Cognito se maintient en gardant les valeurs dans des variables d'environnement (build ou runtime), GitHub Actions Secrets ou GitLab CI variables selon son workflow — pas besoin d'utiliser GitLab si lui utilise uniquement GitHub + AWS.
                - « Si je supprime je n'accède plus » : on DÉPLACE la valeur hors du dépôt (fichier .env ignoré, console AWS, secrets CI), l'app lit import.meta.env / process.env selon React/Vite.
                - Rapport JSON du scan (artifacts CI) ≠ fichier source à ouvrir dans son IDE.
                - Concis et pédagogique.

                """ : "";

        return """
                Tu es un assistant pédagogique sécurité / DevSecOps. Tu aides un développeur qui consulte un finding dans une application (tableau de bord sécurité) : il voit les résultats de scan sur son projet. N'invente pas de CVE ni de chemins absents du contexte.

                Contexte utilisateur : en général il n'a pas accès pour modifier les pipelines CI/CD depuis cet écran ; il peut éditer son code en local, pousser, et relancer une analyse depuis l'application. Ne lui impose pas « modifie ton pipeline GitLab », « ajoute une étape Semgrep au CI » ou des hypothèses d'accès qu'il n'a peut-être pas. Pour SRI (integrity sur link/script), ne dis pas de passer par des variables d'environnement : c'est dans le HTML ou les templates du dépôt.
                Le bloc « TECHNOLOGIES_DEDUITES » en tête du contexte résume la stack probable du projet testé : tiens-en compte pour les commandes et exemples (npm vs mvn vs pip…).

                Contexte du finding (métadonnées + evidence tronquée) :
                %s
                %s
                %s
                %s

                Règles générales :
                - Réponds en français, clair et structuré si utile.
                - Tu peux t'appuyer sur l'extrait de code fourni quand il est présent pour expliquer ligne par ligne ou proposer une correction localisée.
                - Explique la différence entre un « fichier dans le dépôt source » et un « rapport JSON produit par le job CI » (ex. reports/.../npm-audit.json).
                - Pour SCA/npm audit : une alerte porte souvent sur un PACKAGE (ex. aws-sdk dans node_modules), pas sur un fichier source nommé comme le titre du finding.
                - Si l'utilisateur dit qu'il ne trouve pas un « fichier », précise que le titre peut être la vulnérabilité / le module, pas un chemin disque dans son repo.
                - Pour clés, tokens, Cognito ClientId, etc. : priorité aux variables de configuration / secrets managers, pas aux littéraux dans le code.
                - Formate toujours tes réponses en Markdown lisible : titres courts avec ## si plusieurs parties, listes à puces ou numérotées, paragraphes séparés par une ligne vide.
                - Pour toute commande shell (openssl, npm, git, curl, docker, etc.) ou sortie terminal : mets-la dans un bloc de code avec le langage bash, par exemple trois backticks puis bash puis la commande puis trois backticks — ne colle pas les commandes dans le corps du texte sans bloc.
                - Réponses concises ; ne pas répéter tout le contexte à chaque tour.
                """.formatted(findingContext, remediationBlock, codeSnippetSection, secretChat);
    }

    private List<java.util.Map<String, String>> buildChatMessagesForApi(String systemContent, List<ChatTurn> turns) {
        List<ChatTurn> slice = turns.size() > MAX_CHAT_TURNS
                ? turns.subList(turns.size() - MAX_CHAT_TURNS, turns.size())
                : turns;
        List<java.util.Map<String, String>> out = new ArrayList<>();
        out.add(java.util.Map.of("role", "system", "content", truncate(systemContent, MAX_CHAT_MESSAGE_CHARS)));
        for (ChatTurn t : slice) {
            String r = t.role() != null ? t.role().strip().toLowerCase() : "";
            if (!"user".equals(r) && !"assistant".equals(r)) {
                continue;
            }
            String c = t.content() != null ? truncate(t.content(), MAX_CHAT_MESSAGE_CHARS) : "";
            if (c.isBlank()) continue;
            out.add(java.util.Map.of("role", r, "content", c));
        }
        return out;
    }

    private static String truncate(String s, int max) {
        if (s == null) return "";
        return s.length() <= max ? s : s.substring(0, max) + "\n[...tronqué]";
    }

    private String callGroqChat(List<java.util.Map<String, String>> messages) {
        var body = new java.util.LinkedHashMap<String, Object>();
        body.put("model", groqModel);
        List<java.util.Map<String, String>> msgList = new ArrayList<>();
        for (java.util.Map<String, String> m : messages) {
            msgList.add(new java.util.LinkedHashMap<>(m));
        }
        body.put("messages", msgList);
        body.put("temperature", 0.35);
        body.put("max_tokens", 4096);

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        headers.setBearerAuth(groqApiKey);
        HttpEntity<Object> entity = new HttpEntity<>(body, headers);
        RestTemplate rest = new RestTemplate();
        ResponseEntity<JsonNode> response = rest.exchange(GROQ_URL, HttpMethod.POST, entity, JsonNode.class);
        if (response.getBody() == null) throw new RuntimeException("Réponse Groq vide");
        String text = response.getBody().path("choices").path(0).path("message").path("content").asText(null);
        if (text == null || text.isBlank()) throw new RuntimeException("Groq n'a pas renvoyé de contenu");
        return text.strip();
    }

    /** Détecte un quota/ratelimit Groq (HTTP 429). */
    private static boolean isGroqQuotaExceeded(Throwable e) {
        if (e instanceof HttpClientErrorException he) {
            return he.getStatusCode() == HttpStatus.TOO_MANY_REQUESTS;
        }
        return false;
    }

    /** Remédiation/artifact : Groq 429 → fallback Ollama pour cet appel. */
    private String callAiProviderWithFallback(String provider, String prompt) throws Exception {
        if (!"groq".equals(provider)) {
            return callAiProvider(provider, prompt);
        }
        try {
            return callGroq(prompt);
        } catch (Exception e) {
            if (isGroqQuotaExceeded(e)) {
                log.warn("Quota Groq dépassé (429) → fallback Ollama (model={})", ollamaModel);
                return callOllama(prompt);
            }
            throw e;
        }
    }

    /** Chat : Groq 429 → fallback Ollama pour cet appel. */
    private String callFindingChatWithFallback(
            String provider,
            List<java.util.Map<String, String>> messages,
            String system,
            List<ChatTurn> turns
    ) throws Exception {
        if (!"groq".equals(provider)) {
            return switch (provider) {
                case "ollama" -> callOllamaChat(messages);
                case "gemini" -> callGeminiFindingChatPlain(system, turns);
                case "huggingface" -> callHuggingFaceFindingChatPlain(system, turns);
                default -> throw new IllegalStateException("Provider inconnu: " + provider);
            };
        }
        try {
            return callGroqChat(messages);
        } catch (Exception e) {
            if (isGroqQuotaExceeded(e)) {
                log.warn("Quota Groq chat dépassé (429) → fallback Ollama (model={})", ollamaModel);
                return callOllamaChat(messages);
            }
            throw e;
        }
    }

    private String callOllamaChat(List<java.util.Map<String, String>> messages) {
        String url = ollamaUrl.replaceAll("/+$", "") + "/api/chat";
        var body = new java.util.LinkedHashMap<String, Object>();
        body.put("model", ollamaModel);
        List<java.util.Map<String, String>> msgList = new ArrayList<>();
        for (java.util.Map<String, String> m : messages) {
            msgList.add(new java.util.LinkedHashMap<>(m));
        }
        body.put("messages", msgList);
        body.put("stream", false);
        addOllamaGenerationOptions(body);

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        HttpEntity<Object> entity = new HttpEntity<>(body, headers);
        RestTemplate rest = new RestTemplate();
        try {
            ResponseEntity<JsonNode> response = rest.exchange(url, HttpMethod.POST, entity, JsonNode.class);
            if (response.getBody() == null) throw new RuntimeException("Réponse Ollama vide");
            String text = response.getBody().path("message").path("content").asText(null);
            if (text == null || text.isBlank()) throw new RuntimeException("Ollama n'a pas renvoyé de contenu");
            return cleanDeepSeekResponse(text).strip();
        } catch (org.springframework.web.client.ResourceAccessException e) {
            throw new RuntimeException("Ollama inaccessible à " + ollamaUrl + ". Vérifie le service et ai.ollama.model.", e);
        }
    }

    private String callGeminiFindingChatPlain(String system, List<ChatTurn> turns) {
        StringBuilder sb = new StringBuilder();
        sb.append(system).append("\n\n--- Conversation ---\n");
        for (ChatTurn t : turns) {
            sb.append(t.role()).append(": ").append(t.content()).append("\n");
        }
        sb.append("\nRéponds maintenant au dernier message utilisateur de façon utile.");
        return callGeminiPlainText(sb.toString());
    }

    private String callHuggingFaceFindingChatPlain(String system, List<ChatTurn> turns) {
        StringBuilder sb = new StringBuilder();
        sb.append(system).append("\n\n");
        for (ChatTurn t : turns) {
            sb.append(t.role()).append(": ").append(t.content()).append("\n");
        }
        return callHuggingFacePlain(sb.toString());
    }

    /** Gemini sans forcer le JSON (réponse texte). */
    private String callGeminiPlainText(String prompt) {
        String url = GEMINI_BASE_URL + geminiModel + ":generateContent?key=" + geminiApiKey;
        var body = new java.util.LinkedHashMap<String, Object>();
        body.put("contents", List.of(
                java.util.Map.of("parts", List.of(java.util.Map.of("text", prompt)))
        ));
        body.put("generationConfig", java.util.Map.of(
                "temperature", 0.35,
                "maxOutputTokens", 4096
        ));
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        HttpEntity<Object> entity = new HttpEntity<>(body, headers);
        RestTemplate rest = new RestTemplate();
        ResponseEntity<JsonNode> response = rest.exchange(url, HttpMethod.POST, entity, JsonNode.class);
        if (response.getBody() == null) throw new RuntimeException("Réponse Gemini vide");
        JsonNode candidates = response.getBody().path("candidates");
        if (candidates.isEmpty()) throw new RuntimeException("Gemini sans candidat");
        JsonNode parts = candidates.path(0).path("content").path("parts");
        if (parts.isEmpty() || !parts.get(0).has("text")) {
            throw new RuntimeException("Gemini sans texte");
        }
        return parts.get(0).path("text").asText("").strip();
    }

    private String callHuggingFacePlain(String prompt) {
        String url = HUGGINGFACE_INFERENCE_URL + huggingfaceModel;
        var body = new java.util.LinkedHashMap<String, Object>();
        body.put("inputs", truncate(prompt, 12000));
        body.put("parameters", java.util.Map.of(
                "max_new_tokens", 2048,
                "return_full_text", false
        ));
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        headers.setBearerAuth(huggingfaceToken);
        HttpEntity<Object> entity = new HttpEntity<>(body, headers);
        RestTemplate rest = new RestTemplate();
        ResponseEntity<JsonNode> response = rest.exchange(url, HttpMethod.POST, entity, JsonNode.class);
        if (response.getBody() == null) throw new RuntimeException("Réponse Hugging Face vide");
        JsonNode resBody = response.getBody();
        String text = null;
        if (resBody.isArray() && resBody.size() > 0) {
            text = resBody.path(0).path("generated_text").asText(null);
        } else if (resBody.has("generated_text")) {
            text = resBody.path("generated_text").asText(null);
        }
        if (text == null) throw new RuntimeException("Hugging Face sans texte");
        return text.strip();
    }

    private AnalyzeArtifactResponse errorResponse(String summary) {
        return AnalyzeArtifactResponse.builder().summary(summary).vulnerabilities(List.of()).build();
    }

    private boolean isProviderConfigured(String provider) {
        return switch (provider) {
            case "gemini" -> geminiApiKey != null && !geminiApiKey.isBlank();
            case "groq" -> groqApiKey != null && !groqApiKey.isBlank();
            case "huggingface" -> huggingfaceToken != null && !huggingfaceToken.isBlank();
            case "ollama" -> true; // pas de clé
            default -> false;
        };
    }

    private String getConfigHint(String provider) {
        return switch (provider) {
            case "gemini" -> "Définissez ai.gemini.api-key. Ou utilisez ai.provider=groq avec ai.groq.api-key (gratuit, console.groq.com).";
            case "groq" -> "Définissez ai.groq.api-key. Clé gratuite sur https://console.groq.com (pas de carte requise).";
            case "huggingface" -> "Définissez ai.huggingface.token sur https://huggingface.co/settings/tokens.";
            case "ollama" -> "Lancez Ollama localement : ollama run llama2. Ou utilisez ai.provider=groq.";
            default -> "Choisissez ai.provider=groq, huggingface, ollama ou gemini et configurez la clé correspondante.";
        };
    }

    private String callAiProvider(String provider, String prompt) throws Exception {
        return switch (provider) {
            case "gemini" -> callGeminiWithRetry(prompt);
            case "groq" -> callGroq(prompt);
            case "huggingface" -> callHuggingFace(prompt);
            case "ollama" -> callOllama(prompt);
            default -> throw new IllegalStateException("Provider inconnu: " + provider);
        };
    }

    private String buildPrompt(String artifactContent, String sourceHint) {
        return """
            Tu es un expert en sécurité applicative. Analyse ce rapport d'artifact de pipeline de sécurité%s.
            Identifie toutes les vulnérabilités ou problèmes de sécurité (CVE, faiblesses, dépendances vulnérables, etc.).
            Pour chaque élément, fournis :
            1) Un titre court
            2) La sévérité (CRITICAL, HIGH, MEDIUM, LOW, INFO)
            3) L'emplacement (fichier, dépendance, ligne, composant - où le trouver)
            4) Une description du risque
            5) Comment corriger / remédiation concrète

            Réponds UNIQUEMENT avec un JSON valide, sans markdown ni texte autour, de la forme :
            {"summary": "résumé en une phrase du rapport (nombre de vulnérabilités, état)", "vulnerabilities": [{"title": "...", "severity": "...", "location": "...", "description": "...", "remediation": "..."}]}

            Contenu de l'artifact :
            %s
            """.formatted(sourceHint, artifactContent);
    }

    /**
     * Appelle l'API Gemini avec un retry en cas de 429 (quota dépassé).
     */
    private String callGeminiWithRetry(String prompt) throws Exception {
        try {
            return callGemini(prompt);
        } catch (HttpClientErrorException e) {
            if (e.getStatusCode() == HttpStatus.TOO_MANY_REQUESTS) {
                int delaySec = parseRetryDelaySeconds(e.getResponseBodyAsString());
                log.warn("Quota Gemini dépassée (429). Nouvel essai dans {} secondes.", delaySec);
                Thread.sleep(delaySec * 1000L);
                return callGemini(prompt);
            }
            throw e;
        }
    }

    /** Extrait "Please retry in X.XXs" ou utilise le délai par défaut. */
    private int parseRetryDelaySeconds(String responseBody) {
        if (responseBody != null) {
            Matcher m = Pattern.compile("retry in (\\d+(?:\\.\\d+)?)\\s*s", Pattern.CASE_INSENSITIVE).matcher(responseBody);
            if (m.find()) {
                return Math.min(90, (int) Math.ceil(Double.parseDouble(m.group(1))));
            }
        }
        return DEFAULT_RETRY_DELAY_SECONDS;
    }

    private String buildUserFriendlyErrorMessage(Exception e, String provider) {
        String msg = e.getMessage() != null ? e.getMessage() : "";
        if (msg.contains("429") || msg.contains("quota") || msg.contains("RESOURCE_EXHAUSTED")) {
            return "Quota API dépassé (" + provider + "). Réessayez dans 1 à 2 minutes. Ou testez un autre provider : ai.provider=groq (gratuit, console.groq.com).";
        }
        if (msg.contains("404") || msg.contains("NOT_FOUND")) {
            return "Modèle ou ressource introuvable. Vérifiez ai." + provider + ".model ou changez de provider (ex: ai.provider=groq).";
        }
        if (msg.contains("401") || msg.contains("Unauthorized")) {
            return "Clé API invalide (" + provider + "). Vérifiez ai." + (provider.equals("groq") ? "groq.api-key" : provider + ".api-key/token") + ".";
        }
        return "Erreur lors de l'analyse IA (" + provider + "): " + (msg.length() > 200 ? msg.substring(0, 200) + "..." : msg);
    }

    private String callGemini(String prompt) {
        String url = GEMINI_BASE_URL + geminiModel + ":generateContent?key=" + geminiApiKey;

        var body = new java.util.LinkedHashMap<String, Object>();
        body.put("contents", List.of(
                java.util.Map.of("parts", List.of(java.util.Map.of("text", prompt)))
        ));
        body.put("generationConfig", java.util.Map.of(
                "temperature", 0.2,
                "maxOutputTokens", 8192,
                "responseMimeType", "application/json"
        ));

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        HttpEntity<Object> entity = new HttpEntity<>(body, headers);
        RestTemplate rest = new RestTemplate();
        ResponseEntity<JsonNode> response = rest.exchange(url, HttpMethod.POST, entity, JsonNode.class);

        if (response.getBody() == null) {
            throw new RuntimeException("Réponse Gemini vide");
        }
        JsonNode root = response.getBody();
        JsonNode candidates = root.path("candidates");
        if (candidates.isEmpty() || !candidates.get(0).has("content")) {
            JsonNode blockReason = candidates.isEmpty() ? null : candidates.get(0).path("finishReason");
            throw new RuntimeException("Gemini n'a pas renvoyé de contenu. finishReason: " + blockReason.asText("UNKNOWN"));
        }
        JsonNode parts = candidates.get(0).get("content").path("parts");
        if (parts.isEmpty() || !parts.get(0).has("text")) {
            throw new RuntimeException("Réponse Gemini sans texte");
        }
        return parts.get(0).get("text").asText();
    }

    private String callGroq(String prompt) {
        var body = new java.util.LinkedHashMap<String, Object>();
        body.put("model", groqModel);
        body.put("messages", List.of(
                java.util.Map.of("role", "user", "content", prompt)
        ));
        body.put("temperature", 0.2);
        body.put("max_tokens", 8192);

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        headers.setBearerAuth(groqApiKey);
        HttpEntity<Object> entity = new HttpEntity<>(body, headers);
        RestTemplate rest = new RestTemplate();
        ResponseEntity<JsonNode> response = rest.exchange(GROQ_URL, HttpMethod.POST, entity, JsonNode.class);
        if (response.getBody() == null) throw new RuntimeException("Réponse Groq vide");
        JsonNode choice = response.getBody().path("choices").path(0);
        String text = choice.path("message").path("content").asText(null);
        if (text == null) throw new RuntimeException("Groq n'a pas renvoyé de contenu");
        return extractJsonFromResponse(text);
    }

    /** Hugging Face Inference API - token sur huggingface.co/settings/tokens */
    private String callHuggingFace(String prompt) {
        String url = HUGGINGFACE_INFERENCE_URL + huggingfaceModel;
        var body = new java.util.LinkedHashMap<String, Object>();
        body.put("inputs", prompt);
        body.put("parameters", java.util.Map.of(
                "max_new_tokens", 4096,
                "return_full_text", false
        ));

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        headers.setBearerAuth(huggingfaceToken);
        HttpEntity<Object> entity = new HttpEntity<>(body, headers);
        RestTemplate rest = new RestTemplate();
        ResponseEntity<JsonNode> response = rest.exchange(url, HttpMethod.POST, entity, JsonNode.class);
        if (response.getBody() == null) throw new RuntimeException("Réponse Hugging Face vide");
        JsonNode resBody = response.getBody();
        String text = null;
        if (resBody.isArray() && resBody.size() > 0) {
            text = resBody.path(0).path("generated_text").asText(null);
        } else if (resBody.has("generated_text")) {
            text = resBody.path("generated_text").asText(null);
        }
        if (text == null) throw new RuntimeException("Hugging Face n'a pas renvoyé de texte");
        return extractJsonFromResponse(text);
    }

    /** Options de génération Ollama ({@code /api/generate} et {@code /api/chat}). */
    private void addOllamaGenerationOptions(java.util.LinkedHashMap<String, Object> body) {
        var opts = new java.util.LinkedHashMap<String, Object>();
        opts.put("num_predict", Math.max(512, ollamaNumPredict));
        if (ollamaModel != null && ollamaModel.toLowerCase(Locale.ROOT).contains("deepseek")) {
            opts.put("temperature", 0.1);
            opts.put("top_p", 0.95);
        } else {
            opts.put("temperature", ollamaTemperature);
        }
        body.put("options", opts);
    }

    /**
     * Retire les préambules types (Llama, DeepSeek, etc.) ; le JSON utile est extrait ensuite par
     * {@link #extractBalancedJsonObject(String)}.
     */
    private String cleanDeepSeekResponse(String text) {
        if (text == null) {
            return "";
        }
        String cleaned = text.trim();
        String[] prefixes = {
                "Here's the JSON:", "Here is the JSON:", "JSON output:",
                "The response is:", "Output:", "Result:",
                "Voici le JSON :", "Voici le JSON:", "Réponse JSON :", "Réponse JSON:",
                "Here is the response in JSON format:", "Here's the response in JSON format:",
                "Here is the JSON response:", "Here's the JSON response:",
                "Response in JSON format:", "JSON response:"
        };
        boolean changed;
        do {
            changed = false;
            for (String prefix : prefixes) {
                int plen = prefix.length();
                if (cleaned.length() >= plen && cleaned.regionMatches(true, 0, prefix, 0, plen)) {
                    cleaned = cleaned.substring(plen).trim();
                    changed = true;
                    break;
                }
            }
        } while (changed);
        return cleaned.trim();
    }

    /**
     * À partir de la première '{', extrait un objet JSON équilibré (ignore tout texte conversationnel avant).
     * Respecte les chaînes JSON pour les accolades littérales.
     */
    static String extractBalancedJsonObject(String s) {
        if (s == null || s.isEmpty()) {
            return s;
        }
        int start = s.indexOf('{');
        if (start < 0) {
            return s.trim();
        }
        int depth = 0;
        boolean inString = false;
        boolean escape = false;
        for (int i = start; i < s.length(); i++) {
            char c = s.charAt(i);
            if (escape) {
                escape = false;
                continue;
            }
            if (inString) {
                if (c == '\\') {
                    escape = true;
                } else if (c == '"') {
                    inString = false;
                }
                continue;
            }
            if (c == '"') {
                inString = true;
                continue;
            }
            if (c == '{') {
                depth++;
            } else if (c == '}') {
                depth--;
                if (depth == 0) {
                    return s.substring(start, i + 1);
                }
            }
        }
        return s.substring(start);
    }

    /** Ollama : local, pas de clé — ex. {@code ollama run deepseek-coder:6.7b-instruct} */
    private String callOllama(String prompt) {
        String url = ollamaUrl.replaceAll("/+$", "") + "/api/generate";
        var body = new java.util.LinkedHashMap<String, Object>();
        body.put("model", ollamaModel);
        body.put("prompt", prompt);
        body.put("stream", false);
        addOllamaGenerationOptions(body);

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        HttpEntity<Object> entity = new HttpEntity<>(body, headers);
        RestTemplate rest = new RestTemplate();
        try {
            ResponseEntity<JsonNode> response = rest.exchange(url, HttpMethod.POST, entity, JsonNode.class);
            if (response.getBody() == null) throw new RuntimeException("Réponse Ollama vide");
            String text = response.getBody().path("response").asText(null);
            if (text == null || text.isBlank()) throw new RuntimeException("Ollama n'a pas renvoyé de contenu");
            return extractJsonFromResponse(text);
        } catch (org.springframework.web.client.ResourceAccessException e) {
            throw new RuntimeException("Ollama inaccessible à " + ollamaUrl + ". Lancez « ollama run " + ollamaModel + " ».", e);
        }
    }

    /**
     * Extrait le JSON objet de la réponse : fences markdown, préambules, puis première paire {...} équilibrée.
     */
    private String extractJsonFromResponse(String text) {
        if (text == null) {
            return "";
        }
        String t = text.trim();
        if (t.startsWith("```json")) {
            t = t.replaceFirst("^```json\\s*", "").replaceAll("```\\s*$", "").trim();
        } else if (t.startsWith("```")) {
            t = t.replaceFirst("^```\\s*", "").replaceAll("```\\s*$", "").trim();
        }
        t = cleanDeepSeekResponse(t);
        return extractBalancedJsonObject(t).trim();
    }

    private AnalyzeArtifactResponse parseGeminiResponse(String jsonText) {
        String toParse = extractJsonFromResponse(jsonText);
        try {
            JsonNode root = objectMapper.readTree(toParse);
            String summary = root.path("summary").asText("Aucun résumé fourni.");
            JsonNode vulns = root.path("vulnerabilities");
            List<VulnerabilityItem> list = new ArrayList<>();
            if (vulns.isArray()) {
                for (JsonNode v : vulns) {
                    list.add(VulnerabilityItem.builder()
                            .title(v.path("title").asText(""))
                            .severity(v.path("severity").asText(""))
                            .location(v.path("location").asText(""))
                            .description(v.path("description").asText(""))
                            .remediation(v.path("remediation").asText(""))
                            .build());
                }
            }
            return AnalyzeArtifactResponse.builder()
                    .summary(summary)
                    .vulnerabilities(list)
                    .build();
        } catch (Exception e) {
            log.warn("Impossible de parser la réponse JSON de l'IA, retour brut: {}", e.getMessage());
            return AnalyzeArtifactResponse.builder()
                    .summary("L'IA a répondu mais le format n'a pas pu être parsé. Réponse brute: " + (toParse.length() > 500 ? toParse.substring(0, 500) + "..." : toParse))
                    .vulnerabilities(List.of())
                    .build();
        }
    }
}
