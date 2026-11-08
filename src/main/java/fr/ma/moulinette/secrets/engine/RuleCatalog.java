/*
 * Copyright 2026 Laurent HADJADJ
 * Copyright Skyscanner Ltd et 2018 Skyscanner Limited (parties dérivées)
 * SPDX-License-Identifier: LGPL-3.0-or-later AND Apache-2.0
 *
 * Dérivé de Whispers et de Sonar Secrets (Skyscanner, licence Apache-2.0, texte dans
 * LICENSES/Apache-2.0.txt). Modifié : portage en Java. Voir NOTICE.
 */
package fr.ma.moulinette.secrets.engine;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * [Description RuleCatalog]
 *
 * Catalogue des règles de détection.
 */
public final class RuleCatalog {

  /** Seuil d'entropie de Shannon par défaut de la règle {@code high-entropy-string}. */
  public static final double DEFAULT_ENTROPY_THRESHOLD = 4.5;
  /** Nombre approximatif de règles de détection, pour dimensionner la liste. */
  private static final int EXPECTED_RULE_COUNT = 40;
  /** Longueur minimale d'une clé d'API ou d'un jeton. */
  private static final int API_KEY_MIN_LENGTH = 16;
  /** Longueur minimale d'une chaîne signalée par la règle d'entropie. */
  private static final int HIGH_ENTROPY_MIN_LENGTH = 20;
  /** Similarité clé/valeur à partir de laquelle la valeur est considérée comme un espace réservé. */
  private static final double PLACEHOLDER_SIMILARITY = 0.35;

  // Clés des règles SonarQube : identiques aux noms des fichiers de métadonnées (.json et .html)
  public static final String HARDCODED_PASSWORD = "hardcoded-password";
  public static final String HARDCODED_API_KEY = "hardcoded-api-key";
  public static final String HARDCODED_SECRET = "hardcoded-secret";
  public static final String AWS_ACCESS_KEY_ID = "aws-access-key-id";
  public static final String AWS_SECRET_ACCESS_KEY = "aws-secret-access-key";
  public static final String AWS_SESSION_TOKEN = "aws-session-token";
  public static final String PRIVATE_KEY = "private-key";
  public static final String GITHUB_TOKEN = "github-token";
  public static final String DOCKERCFG_AUTH = "dockercfg-auth";
  public static final String HTPASSWD_HASH = "htpasswd-hash";
  public static final String NPMRC_AUTH_TOKEN = "npmrc-auth-token";
  public static final String PIP_PASSWORD = "pip-password";
  public static final String PYPIRC_PASSWORD = "pypirc-password";
  public static final String HARDCODED_WEBHOOK = "hardcoded-webhook";
  public static final String SERVICE_TOKEN = "service-token";
  public static final String HIGH_ENTROPY_STRING = "high-entropy-string";
  public static final String CREDIT_CARD_NUMBER = "credit-card-number";
  public static final String SENSITIVE_FILE = "sensitive-file";
  public static final String COMMENT_LEAK = "comment-leak";
  public static final String INSECURE_CORS = "insecure-cors";
  public static final String DANGEROUS_FUNCTION = "dangerous-function";
  public static final String CUSTOM_SECRET = "custom-secret";

  /** Clés de règles SonarQube, avec leur activation par défaut dans le profil « Track Secrets ». */
  private static final Map<String, Boolean> RULE_KEYS = new LinkedHashMap<>();

  static {
    // Les règles aws-*, github-token et private-key recoupent le moteur natif sonar-text : disponibles mais inactives
    register(HARDCODED_PASSWORD, true);
    register(HARDCODED_API_KEY, true);
    register(HARDCODED_SECRET, true);
    register(AWS_ACCESS_KEY_ID, false);
    register(AWS_SECRET_ACCESS_KEY, false);
    register(AWS_SESSION_TOKEN, false);
    register(PRIVATE_KEY, false);
    register(GITHUB_TOKEN, false);
    register(DOCKERCFG_AUTH, true);
    register(HTPASSWD_HASH, true);
    register(NPMRC_AUTH_TOKEN, true);
    register(PIP_PASSWORD, true);
    register(PYPIRC_PASSWORD, true);
    register(HARDCODED_WEBHOOK, true);
    register(SERVICE_TOKEN, true);
    register(HIGH_ENTROPY_STRING, true);
    // Règles plus bruyantes ou hors périmètre strict des secrets : disponibles mais inactives par défaut
    register(CREDIT_CARD_NUMBER, false);
    register(SENSITIVE_FILE, false);
    register(COMMENT_LEAK, false);
    register(INSECURE_CORS, false);
    register(DANGEROUS_FUNCTION, false);
    // Règles définies par l'utilisateur dans un fichier externe (voir CustomRules)
    register(CUSTOM_SECRET, true);
  }

  /** Slack, Stripe, SendGrid, Mailgun, Twilio, JWT, Terraform Cloud, HashiCorp Vault. */
  private static final List<String> SERVICE_TOKEN_FORMATS = List.of(
    "^xox[abprs]-[A-Za-z0-9-]{10,}$",
    "^[sr]k_(live|test)_[A-Za-z0-9]{24,}$",
    "^SG\\.[A-Za-z0-9_-]{22}\\.[A-Za-z0-9_-]{43}$",
    "^key-[0-9a-f]{32}$",
    "^SK[0-9a-f]{32}$",
    "^eyJ[A-Za-z0-9_-]{10,}\\.eyJ[A-Za-z0-9_-]{10,}\\.[A-Za-z0-9_-]{10,}$",
    "^[A-Za-z0-9]{14}\\.atlasv1\\.[A-Za-z0-9_-]{60,}$",
    "^hv[sbr]\\.[A-Za-z0-9_-]{24,}$");

  /** Message affiché dans l'anomalie : il ne contient jamais la valeur détectée. */
  private static final Map<String, String> MESSAGES = Map.ofEntries(
    Map.entry(HARDCODED_PASSWORD, "Supprimez ce mot de passe écrit en dur et chargez-le depuis un coffre de secrets."),
    Map.entry(HARDCODED_API_KEY, "Supprimez cette clé d'API ou ce jeton écrit en dur et chargez-le depuis un coffre de secrets."),
    Map.entry(HARDCODED_SECRET, "Supprimez ce secret écrit en dur et chargez-le depuis un coffre de secrets."),
    Map.entry(AWS_ACCESS_KEY_ID, "Supprimez cet identifiant de clé d'accès AWS écrit en dur."),
    Map.entry(AWS_SECRET_ACCESS_KEY, "Supprimez cette clé d'accès secrète AWS écrite en dur."),
    Map.entry(AWS_SESSION_TOKEN, "Supprimez ce jeton de session AWS écrit en dur."),
    Map.entry(PRIVATE_KEY, "Supprimez cette clé privée du code source."),
    Map.entry(GITHUB_TOKEN, "Supprimez ce jeton GitHub écrit en dur et révoquez-le."),
    Map.entry(DOCKERCFG_AUTH, "Supprimez ces identifiants de registre Docker écrits en dur."),
    Map.entry(HTPASSWD_HASH, "Supprimez cet identifiant .htpasswd du dépôt."),
    Map.entry(NPMRC_AUTH_TOKEN, "Supprimez ce jeton d'authentification npm écrit en dur."),
    Map.entry(PIP_PASSWORD, "Supprimez ce mot de passe écrit en dur de la configuration de pip."),
    Map.entry(PYPIRC_PASSWORD, "Supprimez ce mot de passe écrit en dur du fichier .pypirc."),
    Map.entry(HARDCODED_WEBHOOK, "Supprimez cette URL de webhook écrite en dur : elle contient un jeton secret."),
    Map.entry(SERVICE_TOKEN, "Supprimez ce jeton de service écrit en dur et révoquez-le."),
    Map.entry(HIGH_ENTROPY_STRING, "Cette chaîne à forte entropie est peut-être un secret cryptographique écrit en dur."),
    Map.entry(CREDIT_CARD_NUMBER, "Cette valeur ressemble à un numéro de carte bancaire."),
    Map.entry(SENSITIVE_FILE, "Ce fichier est connu pour contenir des informations sensibles ; vérifiez qu'il doit bien être versionné."),
    Map.entry(COMMENT_LEAK, "Ce commentaire peut divulguer des informations sensibles."),
    Map.entry(INSECURE_CORS, "Vérifiez cette configuration permissive du partage de ressources entre origines (CORS)."),
    Map.entry(CUSTOM_SECRET, "Supprimez ce secret écrit en dur."),
    Map.entry(DANGEROUS_FUNCTION, "Vérifiez que cet appel à une fonction dangereuse ne peut pas être détourné."));

  private RuleCatalog() {
  }

  private static void register(String ruleKey, boolean defaultActive) {
    RULE_KEYS.put(ruleKey, defaultActive ? Boolean.TRUE : Boolean.FALSE);
  }

  /** Toutes les clés de règles, dans l'ordre de déclaration. */
  public static List<String> ruleKeys() {
    return Collections.unmodifiableList(new ArrayList<>(RULE_KEYS.keySet()));
  }

  /** Clés des règles activées par défaut. */
  public static List<String> defaultActiveRuleKeys() {
    List<String> keys = new ArrayList<>(RULE_KEYS.size());
    RULE_KEYS.forEach((k, active) -> {
      if (Boolean.TRUE.equals(active)) {
        keys.add(k);
      }
    });
    return keys;
  }

  /** Message affiché dans l'anomalie (ne contient jamais la valeur détectée). */
  public static String message(String ruleKey) {
    return MESSAGES.getOrDefault(ruleKey, "Secret écrit en dur détecté.");
  }

  /** Règles de détection avec le seuil d'entropie par défaut. */
  public static List<SecretRule> all() {
    return all(DEFAULT_ENTROPY_THRESHOLD);
  }

  /** Règles de détection. */
  public static List<SecretRule> all(double entropyThreshold) {
    List<SecretRule> rules = new ArrayList<>(EXPECTED_RULE_COUNT);

    rules.add(SecretRule.builder(HARDCODED_PASSWORD)
      .key(FieldSpec.create().regexIgnoreCase("^\\S*(passwords?|passwd|pass|pwd)_?(hash)?[0-9]*$").onlyAscii())
      // Au plus un espace : écarte les libellés d'interface (« Mot de passe oublié »)
      .value(FieldSpec.create().regex("^[^ ]*( [^ ]*)?$").expectUri(false))
      .build());

    rules.add(SecretRule.builder(HARDCODED_API_KEY)
      .key(FieldSpec.create().regexIgnoreCase(".*[A-Za-z0-9\\-_]+(key|token)$"))
      // Sans espace, avec un chiffre ou un mélange majuscules/minuscules : écarte les identifiants
      // en minuscules (ex. REPOSITORY_KEY = "mon-depot-interne")
      .value(FieldSpec.create()
        .regex("^(?!.* )(?:(?=.*[0-9])|(?=.*[a-z])(?=.*[A-Z]))")
        .minLen(API_KEY_MIN_LENGTH)
        .expectUri(false))
      .similar(PLACEHOLDER_SIMILARITY)
      .build());

    rules.add(SecretRule.builder(HARDCODED_SECRET)
      .key(FieldSpec.create().regexIgnoreCase(".*(secrets?)_?(hash)?$"))
      .similar(PLACEHOLDER_SIMILARITY)
      .build());

    // https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_identifiers.html#identifiers-unique-ids
    rules.add(SecretRule.builder(AWS_ACCESS_KEY_ID)
      .value(FieldSpec.create()
        .regex("^(?=.*[A-Z])(?=.*[0-9])A(AG|CC|GP|ID|IP|KI|NP|NV|PK|RO|SC|SI)A[A-Z0-9]{16}$"))
      .build());

    rules.add(SecretRule.builder(AWS_SECRET_ACCESS_KEY)
      .key(FieldSpec.create().regexIgnoreCase("^(?!.*name)"))
      .value(FieldSpec.create().regex("^(?=.*[A-Z])(?=.*[a-z])(?=.*[0-9])[A-Za-z0-9+/]{40}$"))
      .build());

    rules.add(SecretRule.builder(AWS_SESSION_TOKEN)
      .value(FieldSpec.create()
        .regex("^(?=.*[A-Z])(?=.*[a-z])(?=.*[0-9])[A-Za-z0-9+/]{270,450}$").expectBase64(true))
      .build());

    rules.add(SecretRule.builder(PRIVATE_KEY)
      .value(FieldSpec.create().regex(
        ".*-{3,}BEGIN (RSA|DSA|EC|OPENSSH|ENCRYPTED|PGP)? ?(PRIVATE)? ?KEY( BLOCK)?-{3,}.*"))
      .rawLine()
      .build());

    rules.add(SecretRule.builder(GITHUB_TOKEN)
      .value(FieldSpec.create()
        // Jetons classiques (36 à 255 caractères), jetons d'installation « ghs_<id>_<JWT> » et jetons à
        // granularité fine,
        // alignés sur le moteur natif sonar-text 2.53
        .regex("^(gh[pusor]_[a-zA-Z0-9]{36,255}|ghs_\\d++_eyJ[\\w-]++\\.eyJ[\\w-]++\\.[\\w-]{20,}+"
          + "|github_pat_[A-Za-z0-9_]{22,255})$"))
      .build());

    rules.add(SecretRule.builder(DOCKERCFG_AUTH)
      .key(FieldSpec.create().regex("^docker-registry-auth$"))
      .value(FieldSpec.create().expectBase64(true).onlyAscii().minLen(1))
      .build());

    rules.add(SecretRule.builder(HTPASSWD_HASH)
      .key(FieldSpec.create().regex("^htaccess-entry$"))
      .value(FieldSpec.create().minLen(1))
      .build());

    rules.add(SecretRule.builder(NPMRC_AUTH_TOKEN)
      .key(FieldSpec.create().regex("^npm-registry-auth$"))
      .value(FieldSpec.create().minLen(1))
      .build());

    rules.add(SecretRule.builder(PIP_PASSWORD)
      .key(FieldSpec.create().regex("^pip-index-credentials$"))
      .value(FieldSpec.create().minLen(1))
      .build());

    rules.add(SecretRule.builder(PYPIRC_PASSWORD)
      .key(FieldSpec.create().regex("^pypi-upload-credentials$"))
      .value(FieldSpec.create().minLen(1))
      .build());

    // Webhooks : Slack, Hubspot, Twilio
    rules.add(SecretRule.builder(HARDCODED_WEBHOOK)
      .value(FieldSpec.create()
        .regexIgnoreCase("https://hooks\\.slack\\.com/services/[A-Z0-9]{9}/[A-Z0-9]{9}/[a-zA-Z0-9]+"))
      .build());
    rules.add(SecretRule.builder(HARDCODED_WEBHOOK)
      .value(FieldSpec.create().regexIgnoreCase("https://api\\.hubapi\\.com/webhooks/v1/[a-z0-9]+/"))
      .build());
    rules.add(SecretRule.builder(HARDCODED_WEBHOOK)
      .value(FieldSpec.create().regexIgnoreCase("https://chat\\.twilio\\.com/v2/Services/[A-Z0-9]{32}"))
      .build());

    // Jetons à format reconnaissable que le moteur natif sonar-text ne couvre pas (au 2026.11)
    for (String regex : SERVICE_TOKEN_FORMATS) {
      rules.add(SecretRule.builder(SERVICE_TOKEN).value(FieldSpec.create().regex(regex)).build());
    }

    // Idée de Sonar Secrets : chaîne à forte entropie. Au moins une lettre et un chiffre, sans espace.
    rules.add(SecretRule.builder(HIGH_ENTROPY_STRING)
      .value(FieldSpec.create()
        // Jeu de caractères du base64, du base64url et des jetons : exclut parenthèses, points, deux-points...
        .regex("^(?=.*[A-Za-z])(?=.*[0-9])[A-Za-z0-9+/=_-]+$")
        .minLen(HIGH_ENTROPY_MIN_LENGTH).expectUri(false).minEntropy(entropyThreshold))
      .build());

    rules.add(SecretRule.builder(CREDIT_CARD_NUMBER)
      .value(FieldSpec.create().regex("^[0-9]{13,19}$").requireLuhn())
      .build());

    // Le couple ("file", chemin) est produit pour chaque fichier analysé.
    rules.add(SecretRule.builder(SENSITIVE_FILE)
      .key(FieldSpec.create().regex("^file$"))
      .value(FieldSpec.create().regexIgnoreCase(
        ".*(^|[/\\\\._-])(id_rsa|id_dsa|id_ed25519|id_ecdsa|rsa|dsa|ed25519|ecdsa|pem|crt|cer|ca-bundle"
          + "|p7b|p7c|p7s|key|keystore|keyring|jks|pkcs12|pfx|p12|asc|ovpn|kdbx?|keychain|kwallet"
          + "|pgpass|netrc|git-credentials|htpasswd|npmrc|pypirc|dockercfg|s3cfg|tfvars|env"
          + "|(bash|zsh|sh|mysql|psql|irb)[_-]?history|(password|credential|secret)s?(\\.[A-Za-z0-9]+)?)$"))
      .build());

    rules.add(SecretRule.builder(COMMENT_LEAK)
      .key(FieldSpec.create().regex("^comment$").minLen(1))
      .build());

    rules.add(SecretRule.builder(INSECURE_CORS)
      .key(FieldSpec.create().regex("^function$"))
      .value(FieldSpec.create().regex(
        "^(aiohttp_cors.)?ResourceOptions.*(allow_credentials|expose_headers|allow_headers)="
          + "(True|'?\"?\\*'?\"?)"))
      .build());

    rules.add(SecretRule.builder(DANGEROUS_FUNCTION)
      .key(FieldSpec.create().regex("^function$"))
      .value(FieldSpec.create().regexIgnoreCase(
        "^(eval|exec|(os.)?system|popen|call|subprocess\\.(check_output|call))\\("))
      .build());

    return rules;
  }
}
