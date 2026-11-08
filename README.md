# Track Secrets

Plugin SonarQube (Community Build 2026.x) de détection des **secrets codés en dur** : mots de passe, clés d'API, identifiants AWS, jetons, clés privées, etc.

Dans le respect des bonnes pratiques de sécurité, il est recommandé d'utiliser un coffre de secrets (comme credstash ou Vault) et de s'y référer par des identifiants, de sorte que le code source ne contienne jamais de secret en clair.

Il étend la détection du moteur natif `sonar-text` : les deux fonctionnent ensemble.

## 1️⃣ Points clés

- **Un seul plugin pour tous les langages et formats** : Java, Kotlin, JavaScript/TypeScript, Python, Go, PHP, C#, Ruby, Terraform, SQL, YAML, JSON, XML, `.properties`, `.env`, `.ini`, shell, Dockerfile, `.npmrc`, `.pypirc`, `.htpasswd`...
- **Complémentaire de `sonar-text`** : les règles qui recoupent le moteur natif sont inactives par défaut.
- **Aucune valeur de secret dans les rapports** : seul le nom de la clé apparaît dans les messages.
- **Règles personnalisées sans recompilation**, exclusions configurables, seuil d'entropie réglable.
- Aucune dépendance d'exécution supplémentaire.

## 2️⃣ Installation

```bash
mvn clean package                      # JDK 17
cp target/track-secrets-*.jar <sonarqube>/extensions/plugins/
# redémarrer SonarQube
```

Le profil **Track Secrets** (langage *Secrets (Track Secrets)*) est actif par défaut. Détails, propriétés et règles personnalisées : [Guide utilisateur](docs/USER_GUIDE.md).

## 3️⃣ Documentation

- [Guide utilisateur](docs/USER_GUIDE.md) : installation, règles, propriétés, règles personnalisées.
- [Architecture et décisions](docs/ARCHITECTURE.md) : conception, règles d'architecture, choix retenus, écarts par rapport à Whispers, limites.
- [Qualité du code : choix retenus](docs/QUALITE.md) : décision motivée pour chaque règle SonarQube, et règles à exclure du profil.
- [Journal des modifications](CHANGELOG.md).

## 4️⃣ État

Version `1.0.0-RELEASE`. 53 tests unitaires et de bout en bout.
Validé sur SonarQube Community Build 2026.11 avec le projet de démonstration (22 règles chargées, 20 anomalies attendues obtenues).
Non testé sur d'autres versions, ni sur de gros projets : voir les limites dans l'[architecture](docs/ARCHITECTURE.md#6-limites-connues-et-points-à-valider).

## 5️⃣ Licences

- **Code** : [GNU LGPL 3.0 ou ultérieure](LICENSE) (`LGPL-3.0-or-later`), licence à copyleft faible : les modifications du plugin restent ouvertes, sans gêner son usage avec SonarQube.
- **Documentation** (`README.md`, `docs/`) : [CC BY-SA 4.0](docs/LICENSE.md).

Motif et portée du choix de licence : [LICENSING.md](LICENSING.md).

Ce projet reprend des éléments de [Whispers](https://github.com/Skyscanner/whispers) et de [Sonar Secrets](https://github.com/Skyscanner/sonar-secrets) (Skyscanner, Apache 2.0). Les fichiers concernés portent l'en-tête `LGPL-3.0-or-later AND Apache-2.0`, et le texte de la licence Apache 2.0 est fourni dans [`LICENSES/Apache-2.0.txt`](LICENSES/Apache-2.0.txt). Voir [NOTICE](NOTICE).

> **SonarQube est une marque de SonarSource SA, Suisse.**
