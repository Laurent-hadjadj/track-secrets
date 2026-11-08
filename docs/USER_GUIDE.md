# Guide utilisateur

## 1️⃣ Installation

1. Construire le plugin : `mvn clean package` (JDK 17). Le jar est dans `target/track-secrets-<version>.jar`.
2. Copier le jar dans `extensions/plugins` de SonarQube.
3. Redémarrer le serveur. Le journal doit afficher `Deploy plugin Track Secrets / <version>`.

Le plugin est indépendant de `sonar-text` : les deux cohabitent.

## 2️⃣ Activation

Le plugin crée le langage **Secrets (Track Secrets)**, le dépôt de règles **Track Secrets** et le profil qualité **Track Secrets**, défini comme profil par défaut de ce langage.

Il s'applique donc à tous les projets sans configuration. Pour ajuster les règles actives : *Qualité → Profils qualité → Secrets (Track Secrets)*, puis
copier le profil et le modifier.

## 3️⃣ Règles

Pour retrouver les règles dans SonarQube, ouvrir la page *Règles* avec le tag ou le dépôt :

- `/coding_rules?tags=track-secrets` ou `/coding_rules?repositories=track-secrets`. La page conserve les filtres de la session précédente : en cas de résultat vide, effacer tous les filtres.
- Les anomalies se filtrent de la même façon par le tag `track-secrets`.

« Défaut » indique l'activation dans le profil fourni.

| Clé | Détecte | Défaut |
| --- | --- | :---: |
| `hardcoded-password` | mot de passe sous une clé `password`, `passwd`, `pwd`, `pass` | oui |
| `hardcoded-api-key` | clé ou jeton sous une clé finissant par `key` ou `token` | oui |
| `hardcoded-secret` | valeur sous une clé `secret` | oui |
| `service-token` | jetons Slack, Stripe, SendGrid, Mailgun, Twilio, JWT, Terraform Cloud, Vault | oui |
| `hardcoded-webhook` | webhooks Slack, Hubspot, Twilio | oui |
| `high-entropy-string` | chaînes alphanumériques à forte entropie | oui |
| `dockercfg-auth` | identifiants d'un `.dockercfg` ou `config.json` Docker | oui |
| `htpasswd-hash` | entrées d'un `.htpasswd` | oui |
| `npmrc-auth-token` | `_authToken` d'un `.npmrc` | oui |
| `pip-password` | mot de passe dans l'URL d'un `pip.conf` | oui |
| `pypirc-password` | mot de passe d'un `.pypirc` | oui |
| `custom-secret` | vos règles personnalisées | oui |
| `aws-access-key-id`, `aws-secret-access-key`, `aws-session-token` | identifiants AWS | non (couvert par `sonar-text`) |
| `github-token` | jetons GitHub | non (couvert par `sonar-text`) |
| `private-key` | en-têtes de clé privée | non (couvert par `sonar-text`) |
| `credit-card-number` | numéros passant la validation de Luhn | non (bruyant) |
| `sensitive-file` | fichiers connus pour contenir des secrets, d'après leur nom | non |
| `comment-leak` | commentaires HTML | non |
| `insecure-cors` | configuration CORS permissive (Python) | non |
| `dangerous-function` | `eval`, `exec`, `system`... (Python) | non |

Si `sonar-text` n'est pas installé, activez les règles AWS, GitHub et clé privée.

## 4️⃣ Propriétés

À définir dans l'administration (*Paramètres → Track Secrets*) ou dans `sonar-project.properties`.

| Propriété | Défaut | Rôle |
| --- | --- | --- |
| `track.secrets.exclusions.keys` | | expressions régulières (une par ligne, insensibles à la casse) de clés à ignorer |
| `track.secrets.exclusions.values` | | idem pour les valeurs |
| `track.secrets.entropy.threshold` | `4.5` | entropie minimale (bits par caractère) de `high-entropy-string` |
| `track.secrets.includeTests` | `false` | analyser aussi les fichiers de test |
| `track.secrets.maxFileSizeKb` | `1024` | taille maximale d'un fichier analysé |
| `track.secrets.skipNativeOverlap` | `true` | ne pas rapporter `hardcoded-password` en Java, Kotlin, C#, Python, JS, TS et PHP (règle S2068) |
| `track.secrets.customRules.path` | | fichier de règles personnalisées, relatif au répertoire du projet |

Les expressions régulières sont ancrées en début de texte (`.*` pour chercher au milieu).

### Exclusions intégrées

**Valeurs** : `true`, `false`, `yes`, `no`, `0`, `1`, valeurs finissant par `_user`, `_password`, `_token`, `_key`, `_placeholder`, `_name`, ARN AWS, URI `data:`.

**Clés** : celles contenant `public` ou `project`, et les clés techniques finissant par `key` (`cacheKey`, `sortKey`, `primaryKey`...).

Ne sont jamais considérés comme des secrets : les variables (`$VAR`, `${VAR}`, `%VAR%`, `{{ valeur }}`), les espaces réservés (`<valeur>`), les chemins, les valeurs vides ou égales à `null`, et les valeurs qui répètent le nom de la clé.

## 5️⃣ Règles personnalisées

Créer un fichier `.properties` dans le projet, par exemple `track-secrets-rules.properties` :

```properties
# Jeton interne : MJ suivi de 30 caractères
rule.jeton-interne.value=^MJ[A-Z0-9]{30}$
rule.jeton-interne.minlen=32
rule.jeton-interne.ignorecase=false

# Toute valeur sous une clé finissant par _credential
rule.credential.key=.*_credential$
```

puis la déclarer dans `sonar-project.properties` :

```properties
track.secrets.customRules.path=track-secrets-rules.properties
```

- `key` et/ou `value` : expressions régulières ancrées en début de texte (au moins une des deux).
- `minlen` : longueur minimale de la valeur.
- `ignorecase` : `true` par défaut.
- Les anomalies sont rapportées sous la règle `custom-secret`, avec le nom de votre règle dans le message.
- Un fichier invalide est ignoré et un avertissement est écrit dans le journal du scanner.

## 6️⃣ Que faire d'une anomalie ?

1. Considérer le secret comme **compromis** : le révoquer et en émettre un nouveau. Le supprimer du code ne suffit pas, il reste dans l'historique.
2. Le déplacer dans un coffre (Vault, credstash, gestionnaire de secrets du cloud ou de la CI) et le lire à l'exécution par un identifiant.
3. Si c'est un faux positif : marquer l'anomalie « faux positif » dans SonarQube, ou ajouter une exclusion (`track.secrets.exclusions.*`).

## 7️⃣ Fichiers analysés

Tous les fichiers indexés par SonarQube de type principal (pas les tests, sauf `includeTests`), de moins de 1 Mo, non binaires. Les types pris en charge sont listés dans [ARCHITECTURE.md](ARCHITECTURE.md#extracteurs).
Les autres fichiers ne sont analysés que pour les en-têtes de clé privée et le nom du fichier.

## 8️⃣ Comparer la couverture avec sonar-text

```bash
tools/list-native-secret-rules.sh /chemin/vers/sonarqube/lib/extensions
```

> [!TIP]
> Le script liste les familles de secrets du moteur natif et les règles de ce plugin. À relancer après chaque montée de version de SonarQube.
