/*
 * Copyright 2026 Laurent HADJADJ
 * Copyright Skyscanner Ltd (parties dérivées)
 * SPDX-License-Identifier: LGPL-3.0-or-later AND Apache-2.0
 *
 * Dérivé de Whispers (Skyscanner, licence Apache-2.0, texte dans
 * LICENSES/Apache-2.0.txt). Modifié : portage en Java. Voir NOTICE.
 */
package fr.ma.moulinette.secrets.engine;

import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Function;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

/**
 * [Description Detector]
 * Applique les règles à un couple clé/valeur : normalisation, filtre des valeurs non
 * statiques (variables, espaces réservés...), exclusions configurées, puis règles actives.
 */
public final class Detector {

  /** Au-delà, la valeur n'est pas analysée (blob, donnée binaire encodée...). */
  public static final int MAX_VALUE_LENGTH = 20_000;
  /** Un jeton entre accolades n'est retenu que s'il est assez long pour être un secret. */
  private static final int MIN_BRACED_TOKEN_LENGTH = 50;
  /** Variable de shell : le {@code $} puis le premier caractère du nom ou l'accolade ouvrante. */
  private static final int VARIABLE_PREFIX_LENGTH = 2;

  /** Exclusions par défaut (reprises de la configuration de Whispers). */
  public static final List<String> DEFAULT_EXCLUDED_KEYS = List.of(
    ".*(public|project).*",
    // Clés techniques qui se terminent par « key » sans être des secrets
    ".*(cache|primary|foreign|sort|translation|i18n|partition|routing|idempotency).*key$");

  public static final List<String> DEFAULT_EXCLUDED_VALUES = List.of(
    "^(true|false|yes|no|1|0)$",
    ".*_(user|password|token|key|placeholder|name)$",
    "^aws_(access_key_id|secret_access_key|session_token)$",
    "^arn:aws:.*",
    "^data:.*");

  private static final Pattern YAML_INTRINSIC = Pattern.compile("!\\w+ .+");

  private final List<SecretRule> rules;
  private final List<Pattern> excludedKeys;
  private final List<Pattern> excludedValues;

  public Detector(Collection<SecretRule> rules, Collection<String> excludedKeys, Collection<String> excludedValues) {
    this.rules = List.copyOf(rules);
    this.excludedKeys = compile(excludedKeys);
    this.excludedValues = compile(excludedValues);
  }

  private static List<Pattern> compile(Collection<String> expressions) {
    return expressions.stream()
      .filter(e -> e != null && !e.isBlank())
      .map(e -> Pattern.compile(e.strip(), Pattern.CASE_INSENSITIVE))
      .toList();
  }

  /** Analyse un couple et retourne les anomalies (dédoublonnées par règle). */
  public List<Finding> check(Pair pair) {
    var key = Strings.strip(pair.key());
    String value = pair.value() == null ? "" : Strings.strip(pair.value());
    List<Finding> findings = new ArrayList<>();
    if (value.isEmpty() || value.length() > MAX_VALUE_LENGTH || !isStatic(key, value) || isExcluded(pair)) {
      return findings;
    }
    List<String> seen = new ArrayList<>();
    for (SecretRule rule : rules) {
      if (!seen.contains(rule.ruleKey()) && rule.matches(key, value)) {
        seen.add(rule.ruleKey());
        findings.add(new Finding(rule.ruleKey(), key, pair.line(), rule.label()));
      }
    }
    // L'entropie est un filtre générique : elle s'efface devant une règle plus précise sur la même valeur
    if (findings.size() > 1) {
      findings.removeIf(f -> RuleCatalog.HIGH_ENTROPY_STRING.equals(f.ruleKey()));
    }
    return findings;
  }

  /** Analyse une ligne brute avec les seules règles « ligne brute » (ex. en-tête de clé privée). */
  public List<Finding> checkRawLine(String line, int lineNumber) {
    if (line.length() > MAX_VALUE_LENGTH) {
      return List.of();
    }
    // une seule anomalie par règle : la première qui correspond
    Map<String, Finding> byRule = rules.stream()
      .filter(rule -> rule.matchesRawLine(line))
      .map(rule -> new Finding(rule.ruleKey(), "", lineNumber, rule.label()))
      .collect(Collectors.toMap(Finding::ruleKey, Function.identity(), (first, second) -> first, LinkedHashMap::new));
    return List.copyOf(byRule.values());
  }

  /** Vrai si la valeur est codée en dur, c'est-à-dire ni une variable, ni un espace réservé. */
  boolean isStatic(String key, String value) {
    if (value.isEmpty() || isVariable(value)) {
      return false;
    }
    if (value.startsWith("{") && value.endsWith("}")) {
      return isLongBase64Token(value);
    }
    // un espace réservé ou un chemin système n'est pas un secret
    return !isPlaceholder(value) && !Patterns.isPath(value)
      && !repeatsOrExcludesKey(key, value) && !matchesAny(excludedValues, value);
  }

  /** Un jeton encadré d'accolades est conservé s'il est long et en base64. */
  private static boolean isLongBase64Token(String value) {
    return value.length() > MIN_BRACED_TOKEN_LENGTH
      && Patterns.BASE64.matcher(value.substring(1, value.length() - 1)).matches();
  }

  /** Variable ou gabarit : {@code $VAR}, {@code ${VAR}}, {@code %VAR%}, {@code {{ valeur }}}. */
  private static boolean isVariable(String value) {
    var afterPrefix = value.substring(Math.min(VARIABLE_PREFIX_LENGTH, value.length()));
    boolean shell = value.startsWith("$") && !afterPrefix.contains("$");
    boolean windows = value.startsWith("%") && value.endsWith("%");
    boolean template = value.contains("{{") && value.contains("}}");
    return shell || windows || template;
  }

  /** Espace réservé : {@code <valeur>}, {@code null}, ou syntaxe intrinsèque YAML ({@code !Ref x}). */
  private static boolean isPlaceholder(String value) {
    boolean angle = value.startsWith("<") && value.endsWith(">");
    return angle || "null".equals(value) || YAML_INTRINSIC.matcher(value).matches();
  }

  /** Vrai si la valeur répète le nom de la clé (ex. label.password=Password) ou si la clé est exclue. */
  private boolean repeatsOrExcludesKey(String key, String value) {
    if (key.isEmpty()) {
      return false;
    }
    var simpleKey = Strings.simple(key);
    var simpleValue = Strings.simple(value);
    boolean repeats = simpleKey.equals(simpleValue) || simpleValue.endsWith(simpleKey)
      || simpleKey.endsWith("_" + simpleValue);
    return repeats || matchesAny(excludedKeys, key);
  }

  private boolean isExcluded(Pair pair) {
    for (String crumb : pair.breadcrumbs()) {
      if (matchesAny(excludedKeys, crumb)) {
        return true;
      }
    }
    return false;
  }

  private static boolean matchesAny(Collection<Pattern> patterns, String text) {
    for (Pattern p : patterns) {
      if (p.matcher(text).lookingAt()) {
        return true;
      }
    }
    return false;
  }
}
