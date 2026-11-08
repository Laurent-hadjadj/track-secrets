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
import fr.ma.moulinette.secrets.engine.Patterns;
import fr.ma.moulinette.secrets.engine.Strings;
import java.util.List;
import java.util.function.Consumer;
import java.util.regex.Pattern;

/**
 * [Description SimpleExtractors]
 * Extracteurs basés sur un découpage ligne à ligne.
 */
final class SimpleExtractors {

  private static final Pattern COMMENT_PREFIX = Pattern.compile("^[#;]+\\s*");
  private static final Pattern EXPORT_PREFIX = Pattern.compile("^export\\s+");
  private static final Pattern DOCKER_AUTH = Pattern.compile("\"auth\"\\s*:\\s*\"([^\"]+)\"");
  private static final Pattern WHITESPACE = Pattern.compile("\\s+");

  private static final String NPM_AUTH_TOKEN = ":_authToken=";
  private static final String HTML_COMMENT_START = "<!--";
  private static final String HTML_COMMENT_END = "-->";

  /** Fichiers {@code .properties} : {@code a.b=valeur}. Les points de la clé deviennent des "_". */
  public static final Extractor PROPERTIES = SimpleExtractors::properties;
  /** Fichiers de configuration {@code clé = valeur} (ini, conf, env, credentials...). */
  public static final Extractor CONFIG = SimpleExtractors::config;
  public static final Extractor NPMRC = SimpleExtractors::npmrc;
  public static final Extractor PYPIRC = SimpleExtractors::pypirc;
  public static final Extractor PIP = SimpleExtractors::pip;
  public static final Extractor HTPASSWD = SimpleExtractors::htpasswd;
  public static final Extractor DOCKERCFG = SimpleExtractors::dockercfg;
  /** Instructions {@code ENV} et {@code ARG} d'un Dockerfile. */
  public static final Extractor DOCKERFILE = SimpleExtractors::dockerfile;
  /** Texte libre : seules les URI qu'il contient sont analysées (mots de passe, jetons en paramètre). */
  public static final Extractor PLAINTEXT = SimpleExtractors::plaintext;
  /** Commentaires HTML, susceptibles de divulguer des informations. */
  public static final Extractor HTML = SimpleExtractors::html;

  private SimpleExtractors() {
  }

  // --- .properties -------------------------------------------------------------------------------------

  private static void properties(String content, Consumer<Pair> out) {
    String[] lines = Lines.of(content);
    var i = 0;
    while (i < lines.length) {
      var entry = propertyEntry(lines[i]);
      int start = i;
      if (entry != null) {
        var value = new StringBuilder(entry.value());
        i = appendContinuations(lines, i, value);
        out.accept(Pair.of(entry.key().replace('.', '_'), value.toString().strip(), start + 1));
      }
      i++;
    }
  }

  /** Clé et valeur d'une ligne de propriété (éventuellement commentée), ou {@code null}. */
  private static KeyValueLines.KeyValue propertyEntry(String line) {
    var entry = KeyValueLines.property(line);
    return entry != null ? entry : KeyValueLines.commentedProperty(line);
  }

  /** Ajoute les lignes de continuation (valeur terminée par un antislash) ; retourne l'index de la dernière lue. */
  private static int appendContinuations(String[] lines, int index, StringBuilder value) {
    int last = index;
    while (value.toString().endsWith("\\") && last + 1 < lines.length) {
      value.setLength(value.length() - 1);
      last++;
      value.append(lines[last].strip());
    }
    return last;
  }

  // --- fichiers de configuration ---------------------------------------------------------------------

  private static void config(String content, Consumer<Pair> out) {
    String[] lines = Lines.of(content);
    for (var i = 0; i < lines.length; i++) {
      String line = lines[i].strip();
      int eq = line.indexOf('=');
      if (eq > 0) {
        var value = Strings.strip(line.substring(eq + 1));
        if (!value.isEmpty()) {
          out.accept(Pair.of(configKey(line.substring(0, eq)), value, i + 1));
        }
      }
    }
  }

  /** Clé sans guillemets, sans marque de commentaire ni mot-clé {@code export}. */
  private static String configKey(String raw) {
    String key = COMMENT_PREFIX.matcher(Strings.strip(raw)).replaceFirst("");
    return EXPORT_PREFIX.matcher(key).replaceFirst("");
  }

  // --- fichiers de secrets connus ---------------------------------------------------------------------

  private static void npmrc(String content, Consumer<Pair> out) {
    String[] lines = Lines.of(content);
    for (var i = 0; i < lines.length; i++) {
      int idx = lines[i].indexOf(NPM_AUTH_TOKEN);
      if (idx >= 0) {
        String value = lines[i].substring(idx + NPM_AUTH_TOKEN.length()).strip();
        if (!value.isEmpty()) {
          out.accept(Pair.of("npm-registry-auth", value, i + 1));
        }
      }
    }
  }

  private static void pypirc(String content, Consumer<Pair> out) {
    String[] lines = Lines.of(content);
    for (var i = 0; i < lines.length; i++) {
      var password = KeyValueLines.passwordValue(lines[i].strip());
      if (password != null) {
        out.accept(Pair.of("pypi-upload-credentials", password.strip(), i + 1));
      }
    }
  }

  private static void pip(String content, Consumer<Pair> out) {
    String[] lines = Lines.of(content);
    for (var i = 0; i < lines.length; i++) {
      if (lines[i].contains("http")) {
        String value = lines[i].substring(lines[i].lastIndexOf('=') + 1).strip();
        int line = i + 1;
        UriPairs.extract(value, line, List.of(), p -> {
          if (UriPairs.PASSWORD_KEY.equals(p.key())) {
            out.accept(Pair.of("pip-index-credentials", p.value(), line));
          }
        });
      }
    }
  }

  private static void htpasswd(String content, Consumer<Pair> out) {
    String[] lines = Lines.of(content);
    for (var i = 0; i < lines.length; i++) {
      int colon = lines[i].indexOf(':');
      if (colon >= 0) {
        var hash = Strings.strip(lines[i].substring(colon + 1));
        if (!hash.isEmpty()) {
          out.accept(Pair.of("htaccess-entry", hash, i + 1));
        }
      }
    }
  }

  private static void dockercfg(String content, Consumer<Pair> out) {
    String[] lines = Lines.of(content);
    for (var i = 0; i < lines.length; i++) {
      var m = DOCKER_AUTH.matcher(lines[i]);
      while (m.find()) {
        out.accept(Pair.of("docker-registry-auth", m.group(1), i + 1));
      }
    }
  }

  // --- Dockerfile -------------------------------------------------------------------------------------

  private static void dockerfile(String content, Consumer<Pair> out) {
    String[] lines = Lines.of(content);
    for (var i = 0; i < lines.length; i++) {
      var instruction = KeyValueLines.dockerInstruction(lines[i]);
      if (instruction != null) {
        dockerInstruction(instruction, i + 1, out);
      }
    }
  }

  /** {@code ENV A=1 B="x y"} (valeurs découpées comme dans un shell) ou {@code ENV A 1}. */
  private static void dockerInstruction(String rest, int line, Consumer<Pair> out) {
    if (!rest.contains("=")) {
      var keyAndValue = KeyValueLines.keyThenRest(rest);
      if (keyAndValue != null) {
        out.accept(Pair.of(keyAndValue.key(), keyAndValue.value(), line));
      }
      return;
    }
    for (String token : ShellWords.split(rest)) {
      int eq = token.indexOf('=');
      if (eq > 0) {
        out.accept(Pair.of(token.substring(0, eq), token.substring(eq + 1), line));
      }
    }
  }

  // --- texte libre et HTML ------------------------------------------------------------------------------

  private static void plaintext(String content, Consumer<Pair> out) {
    String[] lines = Lines.of(content);
    for (var i = 0; i < lines.length; i++) {
      for (String token : WHITESPACE.split(lines[i])) {
        if (Patterns.looksLikeUri(token)) {
          UriPairs.extract(token, i + 1, List.of(), out);
        }
      }
    }
  }

  /** Recherche des commentaires par {@code indexOf} : linéaire, sans expression régulière. */
  private static void html(String content, Consumer<Pair> out) {
    int start = content.indexOf(HTML_COMMENT_START);
    int end = start < 0 ? -1 : content.indexOf(HTML_COMMENT_END, start + HTML_COMMENT_START.length());
    while (end >= 0) {
      String comment = WHITESPACE.matcher(content.substring(start + HTML_COMMENT_START.length(), end))
        .replaceAll(" ").strip();
      if (!comment.isEmpty()) {
        out.accept(Pair.of("comment", comment, lineNumberAt(content, start)));
      }
      start = content.indexOf(HTML_COMMENT_START, end + HTML_COMMENT_END.length());
      end = start < 0 ? -1 : content.indexOf(HTML_COMMENT_END, start + HTML_COMMENT_START.length());
    }
  }

  /** Numéro de ligne (à partir de 1) de la position donnée. */
  private static int lineNumberAt(String content, int position) {
    var line = 1;
    for (var i = 0; i < position; i++) {
      if (content.charAt(i) == '\n') {
        line++;
      }
    }
    return line;
  }
}
