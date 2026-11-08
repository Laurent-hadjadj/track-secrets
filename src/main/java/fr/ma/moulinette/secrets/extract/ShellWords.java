/*
 * Copyright 2026 Laurent HADJADJ
 * Copyright Skyscanner Ltd (parties dérivées)
 * SPDX-License-Identifier: LGPL-3.0-or-later AND Apache-2.0
 *
 * Dérivé de Whispers (Skyscanner, licence Apache-2.0, texte dans
 * LICENSES/Apache-2.0.txt). Modifié : portage en Java. Voir NOTICE.
 */
package fr.ma.moulinette.secrets.extract;

import java.util.ArrayList;
import java.util.List;

/**
 * [Description ShellWords]
 *
 * Découpage d'une ligne de commande en mots, façon shell : guillemets simples et doubles,
 * antislash d'échappement.
 * Un guillemet non fermé rend le découpage impossible : la liste est alors vide.
 */
final class ShellWords {

  private final String input;
  private final List<String> tokens = new ArrayList<>();
  private final StringBuilder current = new StringBuilder();
  private boolean inToken;
  /** Guillemet ouvert, ou 0 hors guillemets. */
  private char quote;
  private int index;

  private ShellWords(String input) {
    this.input = input;
  }

  static List<String> split(String input) {
    return new ShellWords(input).run();
  }

  private List<String> run() {
    while (index < input.length()) {
      var c = next();
      if (quote == 0) {
        outsideQuotes(c);
      } else {
        insideQuotes(c);
      }
    }
    if (quote != 0) {
      // guillemet non fermé
      return List.of();
    }
    endToken();
    return List.copyOf(tokens);
  }

  private void insideQuotes(char c) {
    if (c == quote) {
      quote = 0;
    } else if (c == '\\' && quote == '"' && hasNext()) {
      current.append(next());
    } else {
      current.append(c);
    }
  }

  private void outsideQuotes(char c) {
    if (c == '\'' || c == '"') {
      quote = c;
      inToken = true;
    } else if (c == '\\' && hasNext()) {
      current.append(next());
      inToken = true;
    } else if (Character.isWhitespace(c)) {
      endToken();
    } else {
      current.append(c);
      inToken = true;
    }
  }

  private char next() {
    var c = input.charAt(index);
    index++;
    return c;
  }

  private boolean hasNext() {
    return index < input.length();
  }

  private void endToken() {
    if (inToken) {
      tokens.add(current.toString());
      current.setLength(0);
      inToken = false;
    }
  }
}
