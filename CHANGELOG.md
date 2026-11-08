# Changelog

Toutes les modifications notables de ce projet sont documentées dans ce fichier.
Le format est basé sur [Keep a Changelog](https://keepachangelog.com/fr/1.1.0/).

## [1.0.0] - 08/11/2026

### Ajouté

- Capteur SonarQube multi-langage, langage virtuel `trksecrets`, dépôt de règles `track-secrets` et profil
  qualité « Track Secrets ».
- 22 règles : mots de passe, clés d'API, secrets, jetons de services (Slack, Stripe, SendGrid, Mailgun, Twilio, JWT, Terraform Cloud, Vault), webhooks, chaînes à forte entropie, AWS, GitHub, clés privées, `.dockercfg`, `.htpasswd`, `.npmrc`, `pip.conf`, `.pypirc`, cartes bancaires, fichiers sensibles, commentaires HTML, CORS, fonctions dangereuses, règles personnalisées.
- Extracteurs : YAML, JSON, XML, `.properties`, configuration (`.env`, `.ini`...), shell, Dockerfile, texte, HTML, langages de programmation.
- Propriétés : exclusions de clés et de valeurs, seuil d'entropie, fichiers de test, taille maximale, recouvrement avec S2068, fichier de règles personnalisées.
- Documentation : guide utilisateur, architecture et décisions, script de comparaison avec `sonar-text`.

### Localisation

- Messages d'anomalie et journaux du plugin en français.
- Titres et descriptions des 22 règles, noms et descriptions des propriétés traduits en français (`track-secrets_fr.properties` et fichiers `<clé>_fr.html`) ; l'anglais reste la langue par défaut. Un test vérifie qu'aucune règle ni propriété n'est sans traduction.
- Descriptions de `dangerous-function` et `insecure-cors` : suppression d'une section « Pourquoi » qui parlait à tort d'identifiants en clair.

### Sécurité et robustesse

- **ReDoS** : aucune expression régulière à retour arrière sur du contenu non maîtrisé. Littéraux de chaîne, schémas d'URI, lignes clé / valeur, YAML, propriétés, Dockerfile, `.pypirc` et chemins sont lus par des analyseurs linéaires (`CodeExtractor`, `KeyValueLines`, `Patterns`). Une expression YAML quadratique (11 s pour 80 000 espaces) a été supprimée ; tests de non-régression sur des lignes pathologiques ; `FileScanner` intercepte `StackOverflowError`.
- **XML** : DTD et entités externes désactivées (XXE) ; `StringReader` fermé par un `try-with-resources`.
- Les exceptions ignorées sont journalisées en `debug` ; un fichier illisible n'interrompt jamais l'analyse.
- **Règle `github-token`** alignée sur sonar-text 2.53 : jetons de 36 à 255 caractères et jetons d'installation `ghs_<id>_<JWT>`.

### Qualité du code

Revue complète des règles SonarQube : chacune est soit respectée (le code est corrigé), soit exclue du profil ou du projet, sans `@SuppressWarnings`. Synthèse et justifications dans `docs/QUALITE.md`.

- Architecture : `FileScanner` dans un package `scan` (plus de dépendance circulaire entre `engine` et `extract`), `package-info.java` par package, types imbriqués en fin de classe.
- Complexité : méthodes découpées (`Detector.isStatic`, `ExtractorRegistry.forFile`, `JsonExtractor`, `YamlExtractor`, `ShellWords`), au plus 3 `return` par méthode, flux à la place des boucles de filtrage, pas de `continue`.
- Style : `var`, constantes nommées pour les nombres magiques, lignes de 120 caractères au plus, `Locale.ROOT`, ternaires imbriqués interdits (règle 15 de `docs/ARCHITECTURE.md`).
- API : `FieldSpec.regex` scindée en `regex` / `regexIgnoreCase`, constructeurs fluides renommés, `InputFile.uri()` à la place de `relativePath()` déprécié, `Pair` immuable.

### Notes

- Portage en Java du moteur de règles de Whispers et de la règle d'entropie de Sonar Secrets (Apache 2.0, Skyscanner). Voir `NOTICE`.
- Licences : code **LGPL 3.0 ou ultérieure** (`LICENSE`, `LICENSES/GPL-3.0.txt`), documentation CC BY-SA 4.0. Motif et portée : `LICENSING.md`.
- Conformité des licences : en-tête `SPDX-License-Identifier` sur tous les fichiers sources (`LGPL-3.0-or-later AND Apache-2.0` pour les fichiers dérivés de Whispers et de Sonar Secrets, avec la mention de Skyscanner), textes de licence dans `LICENSES/` (dont `Apache-2.0.txt`), et embarqués dans le jar (`META-INF/`).
- Le `.gitignore` exclut les sauvegardes et fichiers de secrets (`token*`, `*.bak`, `.env*`, clés).
