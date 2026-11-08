/*
 * Copyright 2026 Laurent HADJADJ
 * SPDX-License-Identifier: LGPL-3.0-or-later
 */
package fr.ma.moulinette.secrets.engine;

import java.util.List;
import java.util.Properties;
import java.util.SortedSet;
import java.util.TreeSet;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

/**
 * Règles personnalisées, chargées depuis un fichier {@code .properties} sans recompilation du plugin :
 *
 * <pre>
 * rule.mon-jeton.key=^.*jeton_interne$
 * rule.mon-jeton.value=^MJ[A-Z0-9]{30}$
 * rule.mon-jeton.minlen=32
 * rule.mon-jeton.ignorecase=false
 * </pre>
 *
 * Toutes les anomalies sont rapportées sous la règle SonarQube {@code custom-secret}, avec le nom de la règle
 * personnalisée dans le message. {@code key} et {@code value} sont optionnels, mais au moins l'un des deux est requis.
 */
public final class CustomRules {

  public static final String RULE_KEY = RuleCatalog.CUSTOM_SECRET;

  private static final Pattern PROPERTY = Pattern.compile("^rule\\.([^.]+)\\.(key|value|minlen|ignorecase)$");

  private CustomRules() {
  }

  /**
   * @throws IllegalArgumentException si une règle est invalide (expression régulière, longueur...)
   */
  public static List<SecretRule> parse(Properties props) {
    SortedSet<String> names = new TreeSet<>();
    for (String property : props.stringPropertyNames()) {
      var m = PROPERTY.matcher(property);
      if (m.matches()) {
        names.add(m.group(1));
      }
    }
    return names.stream().map(name -> build(name, props)).toList();
  }

  private static SecretRule build(String name, Properties props) {
    String prefix = "rule." + name + ".";
    String keyRegex = props.getProperty(prefix + "key");
    String valueRegex = props.getProperty(prefix + "value");
    if (isBlank(keyRegex) && isBlank(valueRegex)) {
      throw new IllegalArgumentException("La règle '" + name + "' doit définir 'key' ou 'value'.");
    }
    var ignoreCase = Boolean.parseBoolean(props.getProperty(prefix + "ignorecase", "true"));
    try {
      var builder = SecretRule.builder(RULE_KEY).label(name);
      if (!isBlank(keyRegex)) {
        builder.key(withRegex(FieldSpec.create(), keyRegex.strip(), ignoreCase));
      }
      var value = FieldSpec.create();
      if (!isBlank(valueRegex)) {
        withRegex(value, valueRegex.strip(), ignoreCase);
      }
      String minLen = props.getProperty(prefix + "minlen");
      if (!isBlank(minLen)) {
        value.minLen(Integer.parseInt(minLen.strip()));
      }
      return builder.value(value).build();
    } catch (PatternSyntaxException | NumberFormatException e) {
      throw new IllegalArgumentException("La règle '" + name + "' est invalide : " + e.getMessage(), e);
    }
  }

  private static boolean isBlank(String s) {
    return s == null || s.isBlank();
  }

  private static FieldSpec withRegex(FieldSpec spec, String expression, boolean ignoreCase) {
    return ignoreCase ? spec.regexIgnoreCase(expression) : spec.regex(expression);
  }
}
