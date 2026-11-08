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
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;
import java.util.regex.Pattern;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * [Description JsonExtractor]
 *
 * Extracteur JSON tolérant (les commentaires de style C sont acceptés) qui conserve
 * le numéro de ligne de chaque clé.
 * Un document invalide produit les paires lues jusqu'à l'erreur.
 */
final class JsonExtractor implements Extractor {

  private static final Logger LOG = LoggerFactory.getLogger(JsonExtractor.class);
  private static final int MAX_DEPTH = 100;
  /** Longueur d'un délimiteur de commentaire de style C ({@code /*} ou {@code *}{@code /}). */
  private static final int COMMENT_DELIMITER_LENGTH = 2;
  /** Séquence d'échappement Unicode (antislash, « u », puis quatre chiffres hexadécimaux). */
  private static final int UNICODE_ESCAPE_LENGTH = 4;
  private static final int HEX_RADIX = 16;
  private static final Pattern INTEGER = Pattern.compile("-?\\d+");

  @Override
  public void extract(String content, Consumer<Pair> out) {
    var parser = new Parser(content, out);
    try {
      parser.skip();
      parser.value(null, new ArrayList<>(), 0);
    } catch (RuntimeException e) {
      LOG.debug("Track Secrets: JSON invalide, lecture interrompue", e);
      // document invalide : on conserve ce qui a déjà été émis
    }
  }

  private static final class Parser {
    private final String s;
    private final Consumer<Pair> out;
    private int pos;
    private int line = 1;

    Parser(String s, Consumer<Pair> out) {
      this.s = s;
      this.out = out;
    }

    private char peek() {
      return pos < s.length() ? s.charAt(pos) : '\0';
    }

    private char next() {
      var c = s.charAt(pos);
      pos++;
      return c;
    }

    /** Saute les espaces, virgules, commentaires de style C et le BOM. */
    private void skip() {
      var more = true;
      while (more && pos < s.length()) {
        more = skipOneBlank();
      }
    }

    /** Avance d'un élément blanc ou d'un commentaire ; faux si le caractère courant n'en est pas un. */
    private boolean skipOneBlank() {
      var c = s.charAt(pos);
      var next = pos + 1 < s.length() ? s.charAt(pos + 1) : '\0';
      var skipped = true;
      if (c == '\n') {
        line++;
        pos++;
      } else if (Character.isWhitespace(c) || c == '\uFEFF' || c == ',') {
        pos++;
      } else if (c == '/' && next == '/') {
        skipLineComment();
      } else if (c == '/' && next == '*') {
        skipBlockComment();
      } else {
        skipped = false;
      }
      return skipped;
    }

    private void skipLineComment() {
      while (pos < s.length() && s.charAt(pos) != '\n') {
        pos++;
      }
    }

    private void skipBlockComment() {
      int end = s.indexOf("*/", pos + COMMENT_DELIMITER_LENGTH);
      int stop = end < 0 ? s.length() : (end + COMMENT_DELIMITER_LENGTH);
      for (int i = pos; i < stop; i++) {
        if (s.charAt(i) == '\n') {
          line++;
        }
      }
      pos = stop;
    }

    /** Lit une valeur ; retourne sa forme scalaire ({@code null} pour un objet, un tableau ou null). */
    String value(String key, List<String> crumbs, int depth) {
      if (depth > MAX_DEPTH) {
        throw new IllegalStateException("profondeur excessive");
      }
      skip();
      char c = peek();
      String scalar = null;
      if (c == '{') {
        object(crumbs, depth);
      } else if (c == '[') {
        array(key, crumbs, depth);
      } else if (c == '"') {
        scalar = quotedValue(key, crumbs);
      } else {
        scalar = bareValue(key, crumbs);
      }
      return scalar;
    }

    private String quotedValue(String key, List<String> crumbs) {
      var startLine = line;
      var text = string();
      emit(key, text, crumbs, startLine);
      return text;
    }

    /** Valeur sans guillemets : seuls les entiers sont émis (les booléens, {@code null} et décimaux sont ignorés). */
    private String bareValue(String key, List<String> crumbs) {
      int start = pos;
      while (pos < s.length() && ",}] \t\r\n".indexOf(s.charAt(pos)) < 0) {
        pos++;
      }
      var token = s.substring(start, pos);
      if (token.isEmpty()) {
        throw new IllegalStateException("valeur attendue à la ligne " + line);
      }
      var integer = INTEGER.matcher(token).matches();
      if (integer) {
        emit(key, token, crumbs, line);
      }
      return integer ? token : null;
    }

    /** Lit le « : » puis la valeur du membre {@code key}. */
    private String memberValue(String key, List<String> crumbs, int depth) {
      skip();
      if (peek() != ':') {
        throw new IllegalStateException("':' attendu à la ligne " + line);
      }
      pos++;
      crumbs.add(key);
      var scalar = value(key, crumbs, depth + 1);
      crumbs.remove(crumbs.size() - 1);
      return scalar;
    }

    private void object(List<String> crumbs, int depth) {
      // accolade ouvrante
      pos++;
      Map<String, Pair> scalars = new LinkedHashMap<>();
      while (true) {
        skip();
        if (peek() == '}') {
          pos++;
          break;
        }
        if (peek() != '"') {
          throw new IllegalStateException("clé attendue à la ligne " + line);
        }
        var keyLine = line;
        var key = string();
        var scalar = memberValue(key, crumbs, depth);
        if (scalar != null) {
          scalars.put(key, new Pair(key, scalar, List.copyOf(crumbs), keyLine));
        }
      }
      // Deux formes : clé et valeur nommées « key » / « name » et « value »
      Pair value = scalars.get("value");
      Pair name = scalars.get("key");
      if (name == null) {
        name = scalars.get("name");
      }
      if (value != null && name != null) {
        out.accept(new Pair(name.value(), value.value(), List.copyOf(crumbs), value.line()));
      }
    }

    private void array(String key, List<String> crumbs, int depth) {
      // crochet ouvrant
      pos++;
      while (true) {
        skip();
        if (peek() == ']') {
          pos++;
          return;
        }
        value(key, crumbs, depth + 1);
      }
    }

    private void emit(String key, String text, List<String> crumbs, int atLine) {
      List<String> path = List.copyOf(crumbs);
      out.accept(new Pair(key == null ? "" : key, text, path, atLine));
      // Fichier d'authentification Docker : la valeur « auth » sous « auths »
      if ("auth".equals(key) && path.contains("auths")) {
        out.accept(new Pair("docker-registry-auth", text, path, atLine));
      }
      int eq = text.indexOf('=');
      if (eq > 0 && eq < text.length() - 1) {
        out.accept(new Pair(text.substring(0, eq), text.substring(eq + 1), path, atLine));
      }
      if (Patterns.looksLikeUri(text)) {
        UriPairs.extract(text, atLine, path, out);
      }
    }

    private String string() {
      // guillemet ouvrant
      pos++;
      var sb = new StringBuilder();
      while (pos < s.length()) {
        var c = next();
        if (c == '"') {
          return sb.toString();
        }
        if (c == '\n') {
          line++;
        }
        if (c == '\\' && pos < s.length()) {
          appendEscape(sb, next());
        } else {
          sb.append(c);
        }
      }
      throw new IllegalStateException("chaîne non terminée");
    }

    private void appendEscape(StringBuilder sb, char escaped) {
      switch (escaped) {
        case 'n' -> sb.append('\n');
        case 't' -> sb.append('\t');
        case 'r' -> sb.append('\r');
        case 'b' -> sb.append('\b');
        case 'f' -> sb.append('\f');
        case 'u' -> appendUnicode(sb);
        default -> sb.append(escaped);
      }
    }

    private void appendUnicode(StringBuilder sb) {
      int end = pos + UNICODE_ESCAPE_LENGTH;
      if (end <= s.length()) {
        sb.append((char) Integer.parseInt(s.substring(pos, end), HEX_RADIX));
        pos = end;
      }
    }
  }
}
