# Fix pipeline GitLab

## 1. Erreur "git: 'sh' is not a git command"
- **Cause :** l’image `alpine/git:latest` a `git` comme ENTRYPOINT.
- **Fix :** ajouter `entrypoint: [""]` au job (voir formulaire ci‑dessous).

## 2. Erreur "script config should be a string or a nested array of strings"
- **Cause :** GitLab exige que `script` soit une **liste de chaînes**. Les blocs `- |` ou une mauvaise indentation peuvent être interprétés comme une structure invalide. Éviter aussi `image: name:` + `entrypoint` dans le même objet si ça pose souci.
- **Fix :** utiliser **une seule ligne par élément** de `script` (pas de bloc `|`), et `image` + `entrypoint` au même niveau que `script`.

---

## Job `clone-repository` à utiliser (copier dans ton `.gitlab-ci.yml` sur GitLab)

```yaml
clone-repository:
  stage: clone
  image: alpine/git:latest
  entrypoint: [""]
  script:
    - echo "Clonage du repository - $GIT_REPO_URL"
    - test -n "$GIT_REPO_URL" || (echo "GIT_REPO_URL vide" && exit 1)
    - if [ -n "$GITHUB_TOKEN" ]; then echo "Repository prive"; AUTH_URL=$(echo "$GIT_REPO_URL" | sed "s|https://|https://oauth2:${GITHUB_TOKEN}@|"); else echo "Repository public"; AUTH_URL="$GIT_REPO_URL"; fi
    - git clone --depth 1 --branch "$GIT_BRANCH" "$AUTH_URL" user-repo
    - cd user-repo && ls -la && cd ..
    - echo "Repository clone"
    - if [ -f "user-repo/pom.xml" ]; then echo "BUILD_TOOL=maven" > build_tool.env; elif [ -f "user-repo/package.json" ]; then echo "BUILD_TOOL=node" > build_tool.env; else echo "BUILD_TOOL=unknown" > build_tool.env; fi
    - cat build_tool.env
  artifacts:
    paths:
      - user-repo/
      - build_tool.env
    expire_in: 2 hours
```

- **Image :** `image: alpine/git:latest` (une seule ligne, pas `image: name:`).
- **Entrypoint :** `entrypoint: [""]` au même niveau que `image` et `script`.
- **Script :** chaque élément est **une seule chaîne** (une ligne par `-`), pas de bloc `- |`. Les `if/else` sont sur une ligne avec `;`.

Mets ce bloc dans le dépôt **amanibennaceur-group/EnviroTest**, branche **master**, puis relance le pipeline depuis la plateforme.
