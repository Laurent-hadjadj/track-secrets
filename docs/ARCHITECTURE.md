# Architecture et décisions

> [!NOTE] Ce document décrit l'architecture de l'extension **Track Secrets** pour SonarQube, les règles à respecter pour le faire évoluer et les choix retenus, avec leur justification.

## 1️⃣ Objectif

Détecter les secrets codés en dur (mots de passe, clés d'API, identifiants AWS, jetons, clés privées...) dans **tous les langages et formats** d'un projet analysé par SonarQube, en complément du moteur natif `sonar-text`.

> [!TIP]
> **Bonne pratique visée** : les secrets vivent dans un coffre (Vault,credstash...) et le code ne contient que des identifiants.

## 2️⃣ Vue d'ensemble

```plaintext
 fichier du projet
        │  InputFile (SonarQube)
        ▼
┌──────────────────────┐
│ TrackSecretsSensor   │  couche SonarQube : configuration, parcours des fichiers, création des issues
└──────────┬───────────┘
           │ chemin relatif + contenu
           ▼
┌──────────────────────┐
│ FileScanner          │  orchestration : règle « fichier », lignes brutes, extracteur, dédoublonnage
└───────┬──────┬───────┘
        │      │ Pair(clé, valeur, fil d'Ariane, ligne)
        │      ▼
        │  ┌───────────────────────┐
        │  │ extract.* (Extractor) │  un extracteur par type de fichier
        │  └───────────────────────┘
        ▼
┌──────────────────────┐
│ Detector             │  filtre « valeur statique » + exclusions, puis règles (SecretRule)
└──────────┬───────────┘
           ▼
     Finding(règle, clé, ligne)   ← ne contient jamais la valeur
```

### Packages

| Package | Rôle | Dépend de |
| --- | --- | --- |
| `fr.ma.moulinette.secrets` | Intégration SonarQube : plugin, langage, règles, profil, propriétés, capteur | tous les autres |
| `...secrets.engine` | Moteur : règles déclaratives, détecteur, utilitaires | JDK uniquement |
| `...secrets.extract` | Extracteurs de couples clé/valeur | `engine` (`Pair`, `Patterns`, `Strings`) |
| `...secrets.scan` | Analyse d'un fichier : `FileScanner` orchestre extracteur, détecteur et dédoublonnage | `engine`, `extract` |

### Extracteurs

| Fichiers | Extracteur | Particularités |
| --- | --- | --- |
| `.yml`, `.yaml` | `YamlExtractor` | indentation, listes, scalaires de bloc, cartes de flux, CloudFormation, paires `name`/`key` + `value` |
| `.json`, `.jsonc` | `JsonExtractor` | commentaires acceptés, lignes exactes, tolérant aux documents invalides, `auths` Docker |
| `.xml`, `.csproj`, `.wsdl`... | `XmlExtractor` | StAX sans DTD ni entités externes, attributs, texte, `name`/`value` (Spring) |
| `.properties` | `PROPERTIES` | continuation de lignes, propriétés commentées |
| `.env`, `.ini`, `.conf`, `.cfg`, `.toml`... | `CONFIG` | détecte le XML déguisé (`web.config`) |
| `.sh`, `.bash`, `.zsh` | `ShellExtractor` | découpage façon shell, identifiants `curl` |
| `Dockerfile*` | `DOCKERFILE` | `ENV` et `ARG` |
| `.npmrc`, `.pypirc`, `pip.conf`, `.htpasswd`, `.dockercfg` | extracteurs dédiés | clés synthétiques |
| `.txt`, `.md` | `PLAINTEXT` | URI contenant un mot de passe |
| `.html` | `HTML` | commentaires |
| Java, Kotlin, JS/TS, Python, Go, PHP, C#, Ruby, Terraform, SQL... | `CodeExtractor` | littéraux de chaîne et nom associé, sans arbre syntaxique |

## 3️⃣ Règles d'architecture

À respecter pour toute contribution :

1. **Le package `engine` n'importe aucune API SonarQube.** Il est testable sans serveur ni mock.
2. **Le package `extract` ne dépend que de `engine`**, jamais de la couche SonarQube. `engine` ne dépend ni de `extract` ni de `scan` : aucune dépendance circulaire entre packages.
3. **Un extracteur ne lève jamais d'exception vers l'appelant.** Un fichier mal formé produit les paires lues jusqu'à l'erreur. `FileScanner` protège en plus l'analyse globale.
4. **Aucune valeur de secret n'est écrite** dans un message d'anomalie, un journal ou un `Finding`. Seul le nom de la clé peut apparaître.
5. **Toute clé de règle est déclarée dans `RuleCatalog`** et possède ses métadonnées (`src/main/resources/org/sonar/l10n/trksecrets/rules/trksecrets/<clé>.json` et `.html`). `PluginTest` échoue si une métadonnée manque.
6. **Les clés synthétiques ne doivent pas ressembler à un nom de secret** (`password`, `token`, `key`...) pour ne pas déclencher les règles génériques en plus de la règle précise.
7. **Pas de dépendance d'exécution supplémentaire.** Seul `sonar-analyzer-commons` est embarqué (chargement des métadonnées). Un nouveau format se traite avec le JDK.
8. **Java 17**, API plugin compilée en 9.17, plancher de compatibilité 10.7 (manifeste).
9. **Aucun nom d'hôte ou de domaine interne** dans le code, la documentation ou les messages de commit : ce dépôt est destiné à être public.
10. **Tout ajout de règle ou d'extracteur s'accompagne de tests** de bout en bout dans `FileScannerTest`, avec des secrets fictifs. Les formats reconnus par les scanners de secrets (Stripe, GitHub, Slack...) sont assemblés par concaténation dans les tests pour ne pas déclencher d'alerte dans le dépôt.
11. **Tout fichier source porte un en-tête `SPDX-License-Identifier`.** Code original :
    `LGPL-3.0-or-later`. Fichier dérivé de Whispers ou de Sonar Secrets : `LGPL-3.0-or-later AND Apache-2.0`, avec la mention de l'origine et du copyright de Skyscanner (obligation de l'Apache 2.0). Les fichiers qui ne peuvent pas porter d'en-tête (métadonnées `.json` et `.html`) sont sous la licence du dépôt.
12. **Les textes de licence sont embarqués dans le jar** (`META-INF/`) : toute nouvelle licence utilisée doit avoir son texte dans `LICENSES/`.
13. **Aucun secret, même fictif ou de sauvegarde, n'est versionné** : le `.gitignore` exclut `token*`, `*.bak`, `.env*` et les clés. Les secrets des tests sont des valeurs inventées.
14. **Aucune expression régulière ne porte sur du contenu non maîtrisé** (littéraux de chaîne, schémas d'URI,commentaires HTML) : ces éléments sont repérés par des analyseurs linéaires. Une expression à alternance répétée peut épuiser la pile de la JVM (règle S5998) ou ralentir l'analyse (ReDoS), et les quantificateurs possessifs, qui suppriment le risque, ne sont pas reconnus par FindSecBugs. Les expressions restantes sont courtes, précompilées, et s'appliquent à un contexte borné. `FileScanner` intercepte en plus `StackOverflowError`, pour qu'une ligne pathologique n'interrompe jamais l'analyse d'un projet.
15. **L'opérateur ternaire est autorisé pour choisir une valeur simple** (`x == null ? "" : x`), à quatre conditions : une seule condition, aucune imbrication, aucun effet de bord, et l'expression tient sur une ligne de 120 caractères au plus.
Dès qu'une de ces conditions n'est pas remplie, on écrit un `if / else`. Voir §4.10.

## 4️⃣ Choix retenus

### 4.1 Capteur multi-langage plutôt qu'un plugin par langage

*Contexte* : `sonar-secrets` (2018) fournissait un plugin Java et un plugin JavaScript, avec une règle écrite deux fois et dépendante des API de règles personnalisées de chaque analyseur.

*Décision* : un seul plugin, un `Sensor` qui lit tous les fichiers.

*Raisons* : un seul code à maintenir ; couvre les formats de configuration (YAML, XML, properties, Dockerfile...) où se trouvent beaucoup de secrets ; indépendant des versions des analyseurs de langage, dont les API de règles personnalisées changent ou disparaissent.

*Coût* : pas d'arbre syntaxique. Les constantes résolues, les concaténations et les chaînes sur plusieurs lignes ne sont pas suivies.

### 4.2 Langage virtuel `trksecrets`

Un dépôt de règles SonarQube est rattaché à un langage. Le plugin déclare un langage sans suffixe de fichier (« Secrets (Track Secrets) »), un dépôt `track-secrets` et un profil « Track Secrets ». Le capteur parcourt les fichiers de tous les langages et rapporte les anomalies sur chacun.

*Validation* : ce montage a été vérifié sur SonarQube Community Build 2026.11. Le serveur enregistre le profil, les 22 règles sont indexées et le capteur crée des anomalies sur des fichiers sans langage connu (`.env`, `.npmrc`, `Dockerfile`, `.properties`).

### 4.3 Compléter `sonar-text`, non  le remplacer

`sonar-text` est livré avec le serveur SonarQube, mis à jour à chaque version et couvre une trentaine de familles de jetons avec des filtres éprouvés. Notre plugin couvre ce qu'il ne fait pas :

- variables nommées `apikey` / `secret` / `token` et fichiers de configuration ;
- mots de passe dans les URI et les chaînes de connexion ;
- `.htpasswd`, `.dockercfg`, `.npmrc`, `pip.conf`, `.pypirc` ;
- webhooks Slack, Hubspot, Twilio ; jetons Slack, Stripe, SendGrid, Mailgun, Twilio, JWT, Terraform Cloud, Vault ;
- chaînes à forte entropie.

Pour éviter les doublons, les règles `aws-*`,`github-token` et `private-key` sont **inactives par défaut** (elles restent disponibles). `hardcoded-password` n'est pas rapportée dans les fichiers Java, Kotlin, C#, Python, JavaScript, TypeScript et PHP, où la règle S2068 des analyseurs de langage existe déjà (`track.secrets.skipNativeOverlap`).

Après chaque montée de version de SonarQube, relancer `tools/list-native-secret-rules.sh` pour comparer la couverture.

### 4.4 Règles déclaratives dans le code

Les règles sont décrites par `SecretRule` (clé, valeur, expression régulière, longueur minimale, similarité, base64, ASCII, URI, Luhn, entropie), construites dans `RuleCatalog`. Plusieurs `SecretRule` peuvent partager une règle SonarQube (trois formats de webhook, huit formats de jetons).

Les règles propres à un projet se déclarent dans un fichier `.properties` (`CustomRules`), sans recompilation.
Elles sont rapportées sous la règle SonarQube `custom-secret`, car le dépôt de règles est fixé au démarrage du serveur.

### 4.5 Analyseurs YAML, JSON et XML sans dépendance

Écrits en JDK pur (StAX pour XML). Avantages : numéros de ligne exacts (Whispers les retrouve par recherche textuelle), tolérance aux gabarits Helm ou Jinja qui rendent le YAML invalide, aucune bibliothèque à tenir à jour, DTD et entités externes désactivées.

Limite : le YAML est analysé ligne à ligne et non selon la grammaire complète (pas d'ancres, pas de scalaires multi-lignes non-bloc).

### 4.6 Aucune fuite de valeur

Les messages contiennent le nom de la clé, jamais la valeur. `Finding` n'a pas de champ pour la valeur.
Un test (`findings_never_carry_the_value`, `sensor_reports_issues_without_leaking_the_value`) le garantit.

### 4.7 Fichiers de test exclus par défaut

Les jeux d'essai contiennent des identifiants fictifs : seuls les fichiers `MAIN` sont analysés (`track.secrets.includeTests` pour changer).

### 4.8 Licence : LGPL 3.0 ou ultérieure

*Objectif* : garantir que le plugin reste ouvert.

*Décision* : **LGPL-3.0-or-later** pour le code, **CC BY-SA 4.0** pour la documentation.

*Raisons* : c'est un **copyleft**, donc personne ne peut fermer le plugin ; c'est aussi la licence de SonarQube, de son API de plugins et de `sonar-analyzer-commons` embarqué, donc elle n'ajoute aucune friction d'usage ; une GPL ou une AGPL aurait compliqué l'usage avec des éditions de SonarQube dont la licence n'est pas libre, sans apporter de garantie utile ici.

*Parties dérivées* : Whispers et Sonar Secrets (Apache 2.0) autorisent la réutilisation sous d'autres conditions, à condition de conserver leurs mentions, d'indiquer les modifications et de joindre leur licence.
Les fichiers concernés portent `LGPL-3.0-or-later AND Apache-2.0` et `LICENSES/Apache-2.0.txt` est fourni.
Détail et FAQ : [`LICENSING.md`](../LICENSING.md).

### 4.9 Alertes SonarQube : respecter la règle ou l'exclure du profil

Le serveur d'analyse active, en plus du profil recommandé « Sonar way », des paquets de règles tiers (Creedengo, PMD, Checkstyle, FindBugs). Pour chaque règle qui signale le code, une seule question : **la règle est-elle légitime ?**

- **Oui** : on la respecte, donc on corrige le code.
- **Non** (elle ne s'applique plus à du code moderne, fait double emploi, ou l'outil se trompe) : on **l'exclut du profil SonarQube**. On n'ajoute pas de `@SuppressWarnings` : il garde une règle sans objet active, encombre le code et se trouve lui-même sanctionné par la règle S1309.

Les règles du « Sonar way » sont légitimes par principe. La justification de chaque décision, règle par règle, est dans [`QUALITE.md`](QUALITE.md), avec la liste des règles à exclure du profil.

Un troisième cas existe : la règle est **légitime en général mais sans objet dans ce projet** (par exemple S2698, message dans les assertions, pour des tests AssertJ). On la garde dans le profil, pour les autres projets, et on l'exclut pour celui-ci par une **exclusion ciblée** (`sonar.issue.ignore.multicriteria` dans le `pom.xml`), toujours accompagnée d'un commentaire qui donne la raison. Une seule déclaration remplace un `@SuppressWarnings` par classe ou par méthode.

### 4.10 Opérateur ternaire

L'expression ternaire est pratique, mais illisible dès qu'il se complique. Deux outils font le même constat (S1774 et Checkstyle `AvoidInlineConditionals`) et interdisent **tous** les ternaires, y compris ceux qui sont plus clairs qu'un `if / else`.
Ces deux règles sont exclues du profil. La vigilance repose sur :

- **S3358**, du « Sonar way », qui interdit l'imbrication ;
- **S3776** (complexité cognitive, seuil 15), qui compte +1 par ternaire et davantage à chaque niveau d'imbrication ;
- la règle 15 ci-dessus, vérifiée en revue de code : une condition, pas d'imbrication, pas d'effet de bord, une ligne.

```java
// Accepté : une valeur, une condition
var label = finding.label() == null ? "" : finding.label();

// À réécrire en if / else : plusieurs conditions et un traitement
var level = a && b ? (c ? HIGH : MEDIUM) : LOW;
```

## 5️⃣ Écarts par rapport à Whispers

| Écart | Raison |
| --- | --- |
| `hardcoded-password` : au plus un espace dans la valeur | écarte les libellés (`msg.password=Entrez votre mot de passe`) |
| une valeur égale au dernier mot de la clé est un espace réservé (`label.password=Password`) | faux positif fréquent dans les fichiers de libellés |
| `hardcoded-api-key` : un chiffre ou un mélange majuscules/minuscules exigé | écarte les identifiants (`REPOSITORY_KEY = "mon-depot-interne"`) |
| exclusions de clés supplémentaires (`cacheKey`, `sortKey`, `primaryKey`...) | clés techniques sans rapport avec un secret |
| `sensitive-file` : liste réécrite avec séparateur obligatoire | la liste d'origine, repliée par YAML, contenait des espaces parasites et des extensions très bruyantes (`log`, `conf`, `sql`) |
| clés synthétiques renommées (`htaccess-entry`, `npm-registry-auth`...) | l'ancienne règle `npm authToken` ne pouvait pas correspondre à la clé produite `npm_authToken` |
| règle d'entropie ajoutée (Sonar Secrets), seuil 4,5 configurable, jeu de caractères restreint | le seuil d'origine de 5,6 ne détecte que les chaînes d'au moins 50 caractères |
| règle `private-key` appliquée à chaque ligne de tout fichier texte | Whispers ne détecte une clé que dans les fichiers qu'il sait analyser |
| paires `name`/`value` (Kubernetes, Spring) | Whispers ne gère que `key`/`value` |
| secrets en commentaire conservés pour `.properties`, `.ini`, shell | un secret commenté reste une fuite |
| l'entropie s'efface si une règle plus précise s'applique | évite les anomalies en double |

## 6️⃣ Limites connues et points à valider

- **Validation limitée** : le plugin a été essayé sur SonarQube 2026.11 avec un projet de démonstration (20 anomalies attendues, 20 obtenues). Le plancher annoncé dans le manifeste (SonarQube 10.7) n'a pas été testé, et aucun gros projet réel n'a encore servi à mesurer le taux de faux positifs ni les temps d'analyse.
- Les tests du capteur utilisent Mockito (`SensorContextTester` n'était pas disponible hors ligne).
- Pas d'arbre syntaxique : constantes, concaténations et chaînes multi-lignes non suivies.
- Le profil est unique pour le langage virtuel : la désactivation du recouvrement avec S2068 se fait par propriété (par extension de fichier), pas par profil.
- Fichiers binaires et fichiers de plus de 1 Mo ignorés (configurable).
- Les règles `comment-leak`, `insecure-cors` et `dangerous-function` (reprises de Whispers) sont inactives par défaut : elles ne concernent pas strictement les secrets (HTML et Python uniquement).

## 7️⃣ Compatibilité

| Élément | Valeur |
| --- | --- |
| Java (build et exécution) | 17 |
| API plugin SonarQube (compilation) | 9.17 |
| SonarQube minimal (manifeste) | 10.7 LTS |
| Serveur visé | SonarQube Community Build 2026.11 |
