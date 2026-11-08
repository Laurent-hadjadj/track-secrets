/*
 * Copyright 2026 Laurent HADJADJ
 * Copyright Skyscanner Ltd et 2018 Skyscanner Limited (parties dérivées)
 * SPDX-License-Identifier: LGPL-3.0-or-later AND Apache-2.0
 *
 * Dérivé de Whispers et de Sonar Secrets (Skyscanner, licence Apache-2.0, texte dans
 * LICENSES/Apache-2.0.txt). Modifié : portage en Java. Voir NOTICE.
 */
package fr.ma.moulinette.secrets.engine;

import java.util.HashMap;
import java.util.Locale;
import java.util.Map;
import java.util.regex.Pattern;

/**
 * [Description Strings]
 *
 * Fonctions utilitaires sur les chaînes.
 */
public final class Strings {

  private static final Pattern NON_ALNUM = Pattern.compile("[^a-z0-9]");
  /** Facteur de la similarité : 2 × (sous-séquence commune la plus longue) / (somme des longueurs). */
  private static final double SIMILARITY_FACTOR = 2.0;
  /** Logarithme de 2, pour exprimer l'entropie de Shannon en bits. */
  private static final double LOG_BASE_2 = Math.log(2);
  /** Longueur minimale d'un texte entre guillemets : le guillemet ouvrant et le guillemet fermant. */
  private static final int MIN_QUOTED_LENGTH = 2;
  /** Algorithme de Luhn : un chiffre doublé est ramené à la somme de ses chiffres (n - 9) s'il dépasse 9. */
  private static final int LUHN_DOUBLING = 2;
  private static final int LUHN_MAX_DIGIT = 9;
  private static final int LUHN_MODULUS = 10;
  /** Caractères retirés en début et fin de chaîne : espaces, guillemets, retours à la ligne, tabulations. */
  private static final String STRIPPED = " '\"\n\r\t";

  private Strings() {
  }

  /** Supprime les espaces, retours à la ligne, tabulations et guillemets en début et fin. */
  public static String strip(String value) {
    if (value == null) {
      return "";
    }
    var start = 0;
    int end = value.length();
    while (start < end && isStripped(value.charAt(start))) {
      start++;
    }
    while (end > start && isStripped(value.charAt(end - 1))) {
      end--;
    }
    return value.substring(start, end);
  }

  private static boolean isStripped(char c) {
    return STRIPPED.indexOf(c) >= 0;
  }

  /** Version simplifiée pour comparaison souple : minuscules, caractères non alphanumériques en "_". */
  public static String simple(String value) {
    if (value == null || value.isEmpty()) {
      return "";
    }
    String v = strip(value);
    while (v.endsWith("\\")) {
      v = v.substring(0, v.length() - 1);
    }
    return NON_ALNUM.matcher(v.toLowerCase(Locale.ROOT).strip()).replaceAll("_");
  }

  /** Coefficient de similarité [0,1] entre deux chaînes (équivalent à Levenshtein.ratio). */
  public static double similarity(String a, String b) {
    String x = simple(a).replace("_", "");
    String y = simple(b).replace("_", "");
    int total = x.length() + y.length();
    if (total == 0) {
      return 1.0;
    }
    return SIMILARITY_FACTOR * lcsLength(x, y) / total;
  }

  private static int lcsLength(String x, String y) {
    var prev = new int[y.length() + 1];
    var cur = new int[y.length() + 1];
    for (var i = 1; i <= x.length(); i++) {
      for (var j = 1; j <= y.length(); j++) {
        cur[j] = x.charAt(i - 1) == y.charAt(j - 1) ? (prev[j - 1] + 1) : Math.max(prev[j], cur[j - 1]);
      }
      int[] tmp = prev;
      prev = cur;
      cur = tmp;
    }
    return prev[y.length()];
  }

  public static boolean isQuoted(String value) {
    if (value.length() < MIN_QUOTED_LENGTH) {
      return false;
    }
    return isQuote(value.charAt(0)) && isQuote(value.charAt(value.length() - 1));
  }

  private static boolean isQuote(char c) {
    return c == '"' || c == '\'';
  }

  /** Vrai si la valeur ressemble à un appel de fonction (parenthèses équilibrées). */
  public static boolean isFunction(String value) {
    var open = 0;
    var close = 0;
    for (var i = 0; i < value.length(); i++) {
      var c = value.charAt(i);
      // les autres caractères sont ignorés
      if (c == '(') {
        open++;
      }
      if (c == ')') {
        close++;
      }
    }
    return open > 0 && open == close;
  }

  /** Entropie de Shannon (en bits par caractère). */
  public static double entropy(String s) {
    if (s == null || s.isEmpty()) {
      return 0.0;
    }
    Map<Character, Integer> occurrences = new HashMap<>();
    for (var i = 0; i < s.length(); i++) {
      occurrences.merge(s.charAt(i), 1, Integer::sum);
    }
    var e = 0.0;
    for (var count : occurrences.values()) {
      double p = (double) count / s.length();
      e -= p * (Math.log(p) / LOG_BASE_2);
    }
    return e;
  }

  /** Validation de Luhn (numéros de carte bancaire). */
  public static boolean luhn(String digits) {
    if (digits.isEmpty() || !digits.chars().allMatch(Character::isDigit)) {
      return false;
    }
    var sum = 0;
    var alternate = false;
    for (int i = digits.length() - 1; i >= 0; i--) {
      int n = digits.charAt(i) - '0';
      if (alternate) {
        n *= LUHN_DOUBLING;
        if (n > LUHN_MAX_DIGIT) {
          n -= LUHN_MAX_DIGIT;
        }
      }
      sum += n;
      alternate = !alternate;
    }
    return sum % LUHN_MODULUS == 0;
  }
}
