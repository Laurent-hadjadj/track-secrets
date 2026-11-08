/*
 * Copyright 2026 Laurent HADJADJ
 * Copyright Skyscanner Ltd (parties dérivées)
 * SPDX-License-Identifier: LGPL-3.0-or-later AND Apache-2.0
 *
 * Dérivé de Whispers (Skyscanner, licence Apache-2.0, texte dans
 * LICENSES/Apache-2.0.txt). Modifié : portage en Java. Voir NOTICE.
 */
package fr.ma.moulinette.secrets.extract;

import fr.ma.moulinette.secrets.engine.Pair;
import java.util.List;
import java.util.function.Consumer;
import java.util.regex.Pattern;

/**
 * [Description UriPairs]
 *
 * Décompose une URI : mot de passe de l'autorité et paramètres de requête.
 */
final class UriPairs {

  /** Clé synthétique du mot de passe contenu dans une URI. */
  public static final String PASSWORD_KEY = "URI_Password";

  private static final Pattern PARAM_SEPARATOR = Pattern.compile("[&;]");
  private static final Pattern SCHEME = Pattern.compile("^[A-Za-z][A-Za-z0-9+.:\\-]*://");

  private UriPairs() {
  }

  static void extract(String uri, int line, List<String> breadcrumbs, Consumer<Pair> out) {
    var m = SCHEME.matcher(uri);
    if (m.find()) {
      var rest = uri.substring(m.end());
      password(rest, line, breadcrumbs, out);
      queryParameters(rest, line, breadcrumbs, out);
    }
  }

  /** Mot de passe de l'autorité : {@code utilisateur:mot_de_passe@hôte}. */
  private static void password(String rest, int line, List<String> breadcrumbs, Consumer<Pair> out) {
    int end = indexOfAny(rest, "/?#");
    String authority = end < 0 ? rest : rest.substring(0, end);
    int at = authority.lastIndexOf('@');
    if (at > 0) {
      var userInfo = authority.substring(0, at);
      int colon = userInfo.indexOf(':');
      if (colon >= 0 && colon < userInfo.length() - 1) {
        out.accept(new Pair(PASSWORD_KEY, userInfo.substring(colon + 1), breadcrumbs, line));
      }
    }
  }

  /** Paramètres de requête : {@code ?a=1&b=2}. */
  private static void queryParameters(String rest, int line, List<String> breadcrumbs, Consumer<Pair> out) {
    int q = rest.indexOf('?');
    if (q < 0) {
      return;
    }
    var query = rest.substring(q + 1);
    int hash = query.indexOf('#');
    if (hash >= 0) {
      query = query.substring(0, hash);
    }
    for (String param : PARAM_SEPARATOR.split(query)) {
      int eq = param.indexOf('=');
      if (eq > 0 && eq < param.length() - 1) {
        out.accept(new Pair(param.substring(0, eq), param.substring(eq + 1), breadcrumbs, line));
      }
    }
  }

  private static int indexOfAny(String s, String chars) {
    for (var i = 0; i < s.length(); i++) {
      if (chars.indexOf(s.charAt(i)) >= 0) {
        return i;
      }
    }
    return -1;
  }
}
