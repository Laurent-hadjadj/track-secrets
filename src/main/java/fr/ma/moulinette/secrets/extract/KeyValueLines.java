/*
 * Copyright 2026 Laurent HADJADJ
 * Copyright Skyscanner Ltd (parties dérivées)
 * SPDX-License-Identifier: LGPL-3.0-or-later AND Apache-2.0
 *
 * Dérivé de Whispers (Skyscanner, licence Apache-2.0, texte dans
 * LICENSES/Apache-2.0.txt). Modifié : portage en Java. Voir NOTICE.
 */
package fr.ma.moulinette.secrets.extract;

import java.util.List;

/**
 * [Description KeyValueLines]
 *
 * Découpage d'une ligne {@code clé / valeur} en un seul passage, sans expression régulière :
 * le temps de traitement reste linéaire quelle que soit la longueur de la ligne
 * (pas de retour arrière, règle S8786).

 */
final class KeyValueLines {

  private static final String BLANKS = " \t\n\u000B\f\r";
  private static final String PROPERTY_MARKERS = "=:#!";
  private static final String COMMENT_MARKERS = "#!";
  private static final String SEPARATORS = "=:";
  private static final String PASSWORD = "password";
  /** Caractères qui ne peuvent pas ouvrir une clé YAML non guillemetée. */
  private static final String YAML_FORBIDDEN_FIRST = ":#'\"[]{},&*!|>%@`";
  private static final String YAML_KEY_STOPS = ":#";
  private static final List<String> DOCKER_KEYWORDS = List.of("ENV", "ARG");
  private KeyValueLines() {
  }

  /** Ligne {@code clé=valeur}, {@code clé:valeur} ou {@code clé valeur} ; {@code null} si la ligne n'en est pas une. */
  static KeyValue property(String line) {
    var start = skipBlanks(line, 0);
    if (start >= line.length() || PROPERTY_MARKERS.indexOf(line.charAt(start)) >= 0) {
      return null;
    }
    var end = start + 1;
    while (end < line.length() && !isKeyEnd(line.charAt(end))) {
      end++;
    }
    if (end >= line.length()) {
      return null;
    }
    var afterBlanks = skipBlanks(line, end);
    if (afterBlanks < line.length() && SEPARATORS.indexOf(line.charAt(afterBlanks)) >= 0) {
      afterBlanks++;
    }
    return new KeyValue(line.substring(start, end), line.substring(skipBlanks(line, afterBlanks)));
  }

  /** Propriété mise en commentaire ({@code # clé=valeur}) : seule cette forme est retenue. */
  static KeyValue commentedProperty(String line) {
    var start = skipBlanks(line, 0);
    var marker = start;
    while (marker < line.length() && COMMENT_MARKERS.indexOf(line.charAt(marker)) >= 0) {
      marker++;
    }
    var keyStart = skipBlanks(line, marker);
    if (marker == start || keyStart >= line.length() || !isKeyStart(line.charAt(keyStart))) {
      return null;
    }
    var keyEnd = endOfKey(line, keyStart + 1);
    var valueStart = valueStart(line, keyEnd);
    return valueStart < 0 ? null : new KeyValue(line.substring(keyStart, keyEnd), line.substring(valueStart));
  }

  private static int endOfKey(String line, int from) {
    var end = from;
    while (end < line.length() && !isKeyEnd(line.charAt(end))) {
      end++;
    }
    return end;
  }

  /** Début de la valeur qui suit « = » ou « : » après la clé, ou -1 s'il n'y a ni séparateur ni valeur. */
  private static int valueStart(String line, int keyEnd) {
    var separator = skipBlanks(line, keyEnd);
    if (separator >= line.length() || SEPARATORS.indexOf(line.charAt(separator)) < 0) {
      return -1;
    }
    var start = skipBlanks(line, separator + 1);
    return start < line.length() ? start : -1;
  }

  /**
   * Ligne YAML {@code clé: valeur} : la clé (avec ses guillemets éventuels) et la valeur ({@code ""} si absente), ou
   * {@code null}. Le deux-points doit être suivi d'un espace ou de la fin de ligne. Pas d'expression régulière :
   * le temps de traitement est linéaire.
   */
  static KeyValue mapping(String text) {
    if (text.isEmpty()) {
      return null;
    }
    var first = text.charAt(0);
    var keyEnd = first == '"' || first == '\'' ? quotedKeyEnd(text, first) : plainKeyEnd(text);
    var colon = keyEnd < 0 ? -1 : skipBlanks(text, keyEnd);
    if (colon < 0 || colon >= text.length() || text.charAt(colon) != ':') {
      return null;
    }
    return afterColon(text, text.substring(0, keyEnd), colon);
  }

  /** Fin (exclue) d'une clé entre guillemets, ou -1 si le guillemet n'est jamais refermé. */
  private static int quotedKeyEnd(String text, char quote) {
    var close = text.indexOf(quote, 1);
    return close < 0 ? -1 : (close + 1);
  }

  /** Fin (exclue, sans espaces de fin) d'une clé non guillemetée, ou -1 si la ligne n'en contient pas. */
  private static int plainKeyEnd(String text) {
    var first = text.charAt(0);
    if (BLANKS.indexOf(first) >= 0 || YAML_FORBIDDEN_FIRST.indexOf(first) >= 0) {
      return -1;
    }
    var stop = firstOf(text, YAML_KEY_STOPS);
    if (stop < 0 || text.charAt(stop) != ':') {
      return -1;
    }
    var end = stop;
    while (end > 1 && BLANKS.indexOf(text.charAt(end - 1)) >= 0) {
      end--;
    }
    return end;
  }

  /** Valeur qui suit le deux-points : il doit être suivi d'un espace ou de la fin de ligne. */
  private static KeyValue afterColon(String text, String key, int colon) {
    var after = colon + 1;
    if (after == text.length()) {
      return new KeyValue(key, "");
    }
    return BLANKS.indexOf(text.charAt(after)) < 0 ? null : new KeyValue(key, text.substring(skipBlanks(text, after)));
  }

  private static int firstOf(String text, String characters) {
    for (var i = 0; i < text.length(); i++) {
      if (characters.indexOf(text.charAt(i)) >= 0) {
        return i;
      }
    }
    return -1;
  }

  /** Reste d'une instruction {@code ENV} ou {@code ARG} (casse indifférente), ou {@code null}. */
  static String dockerInstruction(String line) {
    var text = line.strip();
    for (String keyword : DOCKER_KEYWORDS) {
      if (text.regionMatches(true, 0, keyword, 0, keyword.length())
          && text.length() > keyword.length() && BLANKS.indexOf(text.charAt(keyword.length())) >= 0) {
        var rest = text.substring(keyword.length()).strip();
        return rest.isEmpty() ? null : rest;
      }
    }
    return null;
  }

  /** Instruction {@code ENV A 1} : la clé, puis le reste de la ligne (déjà privée de ses espaces de bordure). */
  static KeyValue keyThenRest(String text) {
    var keyEnd = 0;
    while (keyEnd < text.length() && BLANKS.indexOf(text.charAt(keyEnd)) < 0) {
      keyEnd++;
    }
    var valueStart = skipBlanks(text, keyEnd);
    if (keyEnd == 0 || valueStart >= text.length()) {
      return null;
    }
    return new KeyValue(text.substring(0, keyEnd), text.substring(valueStart));
  }

  /** Valeur qui suit le premier {@code password = ...} (ou {@code password: ...}) de la ligne, ou {@code null}. */
  static String passwordValue(String line) {
    var from = line.indexOf(PASSWORD);
    while (from >= 0) {
      var separator = skipBlanks(line, from + PASSWORD.length());
      if (separator < line.length() && SEPARATORS.indexOf(line.charAt(separator)) >= 0) {
        var valueStart = skipBlanks(line, separator + 1);
        if (valueStart < line.length()) {
          return line.substring(valueStart);
        }
      }
      from = line.indexOf(PASSWORD, from + 1);
    }
    return null;
  }

  private static int skipBlanks(String text, int from) {
    var index = from;
    while (index < text.length() && BLANKS.indexOf(text.charAt(index)) >= 0) {
      index++;
    }
    return index;
  }

  private static boolean isKeyEnd(char c) {
    return SEPARATORS.indexOf(c) >= 0 || BLANKS.indexOf(c) >= 0;
  }

  private static boolean isKeyStart(char c) {
    return c == '_' || isAsciiLetter(c);
  }

  private static boolean isAsciiLetter(char c) {
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z');
  }

  /** Clé et valeur d'une ligne. */
  record KeyValue(String key, String value) {
  }
}
