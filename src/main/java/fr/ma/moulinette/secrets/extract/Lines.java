/*
 * Copyright 2026 Laurent HADJADJ
 * SPDX-License-Identifier: LGPL-3.0-or-later
 */
package fr.ma.moulinette.secrets.extract;

import java.util.regex.Pattern;

/**
 * [Description Lines]
 *
 * Découpage d'un contenu en lignes, partagé par les extracteurs.
 */
final class Lines {

  private static final Pattern LINE_BREAK = Pattern.compile("\\r?\\n");

  private Lines() {
  }

  /** Lignes du contenu, sans les fins de ligne ; une dernière ligne vide est conservée. */
  static String[] of(String content) {
    return LINE_BREAK.split(content, -1);
  }
}
