/*
 * Copyright 2026 Laurent HADJADJ
 * Copyright Skyscanner Ltd (parties dérivées)
 * SPDX-License-Identifier: LGPL-3.0-or-later AND Apache-2.0
 *
 * Dérivé de Whispers (Skyscanner, licence Apache-2.0, texte dans
 * LICENSES/Apache-2.0.txt). Modifié : portage en Java. Voir NOTICE.
 */
package fr.ma.moulinette.secrets.engine;

import java.util.regex.Pattern;

/** Expressions régulières partagées (anciennes règles « utilitaires » de Whispers). */
public final class Patterns {

  private static final String SCHEME_SEPARATOR = "://";
  /** Longueur de {@code file:} et de {@code root:}, et d'une lettre de lecteur suivie de {@code :}. */
  private static final int PATH_KEYWORD_LENGTH = 5;
  private static final int DRIVE_PREFIX_LENGTH = 2;

  /** Texte ressemblant à du base64 (quantificateurs possessifs pour éviter tout débordement de pile). */
  public static final Pattern BASE64 = Pattern.compile(
    "^(?:[A-Za-z0-9+/]{4})*+(?:[A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{2}==)?$");

  private Patterns() {
  }

  /**
   * Vrai si le texte commence par une URI de n'importe quel schéma ({@code http://}, {@code jdbc:mysql://},
   * {@code postgres://}, {@code mongodb://}, {@code redis://}...) suivie d'au moins un caractère. Whispers se
   * limitait à quelques schémas. Le schéma est validé en une passe : il n'y a pas d'expression régulière, donc
   * aucun risque de retour en arrière sur un texte quelconque.
   */
  public static boolean looksLikeUri(String text) {
    int separator = text.indexOf(SCHEME_SEPARATOR);
    boolean hasContent = separator >= 1 && separator + SCHEME_SEPARATOR.length() < text.length();
    return hasContent && isScheme(text, separator);
  }

  /** Schéma : une lettre, puis des lettres, chiffres, {@code + . -}, avec des segments séparés par {@code :}. */
  private static boolean isScheme(String text, int end) {
    if (!isAsciiLetter(text.charAt(0))) {
      return false;
    }
    for (var i = 1; i < end; i++) {
      var c = text.charAt(i);
      // un ':' ne peut pas suivre un autre ':' ; tout autre caractère doit être un caractère de schéma
      boolean valid = (c == ':') ? (text.charAt(i - 1) != ':') : isSchemeChar(c);
      if (!valid) {
        return false;
      }
    }
    // un segment doit suivre chaque ':'
    return text.charAt(end - 1) != ':';
  }

  private static boolean isSchemeChar(char c) {
    return isAsciiLetter(c) || isDigit(c) || "+.-".indexOf(c) >= 0;
  }

  /**
   * Chemin système ou réseau : préfixe facultatif ({@code C:}, {@code file:}, {@code root:}), points facultatifs, puis
   * au moins un séparateur ({@code /} ou {@code \}).
   */
  public static boolean isPath(String text) {
    var prefix = prefixLength(text);
    return startsWithSeparator(text, 0) || (prefix > 0 && startsWithSeparator(text, prefix));
  }

  private static int prefixLength(String text) {
    if (text.regionMatches(true, 0, "file:", 0, PATH_KEYWORD_LENGTH)
        || text.regionMatches(true, 0, "root:", 0, PATH_KEYWORD_LENGTH)) {
      return PATH_KEYWORD_LENGTH;
    }
    return text.length() > 1 && isAsciiLetter(text.charAt(0)) && text.charAt(1) == ':' ? DRIVE_PREFIX_LENGTH : 0;
  }

  private static boolean startsWithSeparator(String text, int from) {
    var index = from;
    while (index < text.length() && text.charAt(index) == '.') {
      index++;
    }
    return index < text.length() && (text.charAt(index) == '/' || text.charAt(index) == '\\');
  }

  private static boolean isDigit(char c) {
    return c >= '0' && c <= '9';
  }

  private static boolean isAsciiLetter(char c) {
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z');
  }
}
