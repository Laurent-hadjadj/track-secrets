/*
 * Copyright 2026 Laurent HADJADJ
 * Copyright Skyscanner Ltd et 2018 Skyscanner Limited (parties dérivées)
 * SPDX-License-Identifier: LGPL-3.0-or-later AND Apache-2.0
 *
 * Dérivé de Whispers et de Sonar Secrets (Skyscanner, licence Apache-2.0, texte dans
 * LICENSES/Apache-2.0.txt). Modifié : portage en Java. Voir NOTICE.
 */
package fr.ma.moulinette.secrets.extract;

import fr.ma.moulinette.secrets.engine.Pair;
import fr.ma.moulinette.secrets.engine.Patterns;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Consumer;
import java.util.regex.Pattern;

/**
 * [Description CodeExtractor]
 *
 * Extracteur pour les langages de programmation et de script (Java, Kotlin, JS/TS, Python,
 * Go, PHP, C#, Ruby, Terraform...). Il n'utilise pas d'arbre syntaxique : il repère, ligne
 * à ligne, les littéraux de chaîne et le nom auquel ils sont associés.
 * C'est ce qui permet de couvrir tous les langages avec un seul moteur, au prix de
 * quelques cas non résolus (constantes, concaténations, chaînes sur plusieurs lignes).
 *
 * <p>Les littéraux sont repérés par un analyseur linéaire et non par une expression
 * régulière : le contenu d'un fichier n'est pas maîtrisé, et une expression à alternance
 * répétée peut épuiser la pile de la JVM ou ralentir l'analyse. Les expressions régulières
 * restantes s'appliquent à un court contexte avant ou après le littéral.
 */
final class CodeExtractor implements Extractor {

  private static final String OPERATOR = "(=>|:=|\\+=|===|==|=|:)";

  /** {@code nom = "valeur"}, {@code nom => "valeur"}, {@code nom == "valeur"}, {@code nom: "valeur"}... */
  private static final Pattern IDENTIFIER_ASSIGNMENT =
    Pattern.compile("(?<![\\w$.@])([A-Za-z_$@][\\w$.\\-]*+)\\s*+" + OPERATOR + "\\s*+$");

  /** Affectation typée : {@code password: str = "x"}, {@code val password: String = "x"}. */
  private static final Pattern TYPED_ASSIGNMENT =
    Pattern.compile("(?<![\\w$.@])([A-Za-z_$][\\w$]*+)\\s*+:[\\w\\[\\],.|?<> ]++=\\s*+$");

  /** Entre une clé entre guillemets et sa valeur : {@code "nom": }, {@code ['nom'] = }. */
  private static final Pattern QUOTED_KEY_GAP = Pattern.compile("^\\]?\\s*+" + OPERATOR + "\\s*+$");

  private static final Pattern KEY_NAME = Pattern.compile("^[\\w.\\-]{1,80}$");
  private static final Pattern COMMA_GAP = Pattern.compile("^\\s*+,\\s*+$");
  private static final Pattern OPEN_PARENTHESIS = Pattern.compile("\\(\\s*+$");
  private static final Pattern CLOSE_PARENTHESIS = Pattern.compile("^\\s*+\\)");

  /** {@code setPassword("x")}, {@code withToken("x")}. */
  private static final Pattern SETTER_BEFORE = Pattern.compile("\\b(?:set|with)([A-Z]\\w*+)\\s*+\\(\\s*+$");

  /** Style « builder » : {@code .password("x")}. */
  private static final Pattern BUILDER_BEFORE = Pattern.compile(
    "\\.(password|passwd|pwd|secret|token|apiKey|accessKey|secretKey|clientSecret)\\s*+\\(\\s*+$");

  /** SQL : {@code CREATE USER x IDENTIFIED BY 'mot_de_passe'}. */
  private static final Pattern SQL_BEFORE = Pattern.compile("(?i)\\bidentified\\s++(?:by|with\\s++\\w++\\s++by)\\s++$");

  /** Python : appels dont on contrôle l'expression complète (règles dangerous-function et insecure-cors). */
  private static final Pattern PY_CALL = Pattern.compile(
    "\\b(eval|exec|os\\.system|system|popen|subprocess\\.call|subprocess\\.check_output|call"
      + "|aiohttp_cors\\.ResourceOptions|ResourceOptions)\\(.*");

  private static final int MAX_LINE_LENGTH = 10_000;
  /** Un antislash et le caractère qu'il échappe. */
  private static final int ESCAPE_SEQUENCE_LENGTH = 2;
  private static final int MIN_STANDALONE_LENGTH = 16;
  /** Nombre de caractères examinés avant et après un littéral. */
  private static final int CONTEXT_LENGTH = 200;
  private final boolean python;

  CodeExtractor(boolean python) {
    this.python = python;
  }

  @Override
  public void extract(String content, Consumer<Pair> out) {
    String[] lines = Lines.of(content);
    for (var i = 0; i < lines.length; i++) {
      String line = lines[i];
      // une ligne trop longue est typiquement du code minifié : elle est ignorée
      if (line.length() <= MAX_LINE_LENGTH && !line.isBlank()) {
        scan(line, i + 1, out);
      }
    }
  }

  private void scan(String line, int lineNo, Consumer<Pair> out) {
    List<Literal> literals = literals(line);
    for (var k = 0; k < literals.size(); k++) {
      var literal = literals.get(k);
      Literal previous = k > 0 ? literals.get(k - 1) : null;
      keyedBy(line, literal, previous, lineNo, out);
      if (literal.text().length() >= MIN_STANDALONE_LENGTH) {
        // Tout littéral assez long est aussi analysé sans clé (formats de jetons, URI avec identifiants, entropie)
        out.accept(Pair.of("", literal.text(), lineNo));
        if (Patterns.looksLikeUri(literal.text())) {
          UriPairs.extract(literal.text(), lineNo, List.of(), out);
        }
      }
    }
    if (python) {
      var m = PY_CALL.matcher(line);
      while (m.find()) {
        out.accept(Pair.of("function", m.group(0), lineNo));
      }
    }
  }

  /** Cherche le nom auquel un littéral est associé et émet les couples correspondants. */
  private static void keyedBy(String line, Literal literal, Literal previous, int lineNo, Consumer<Pair> out) {
    String value = literal.text();
    var before = line.substring(Math.max(0, literal.start() - CONTEXT_LENGTH), literal.start());
    var after = line.substring(literal.end(), Math.min(line.length(), literal.end() + CONTEXT_LENGTH));

    emit(out, lineNo, value, firstGroup(IDENTIFIER_ASSIGNMENT, before));
    emit(out, lineNo, value, firstGroup(TYPED_ASSIGNMENT, before));
    emit(out, lineNo, value, firstGroup(SETTER_BEFORE, before), CLOSE_PARENTHESIS.matcher(after).find());
    emit(out, lineNo, value, firstGroup(BUILDER_BEFORE, before), CLOSE_PARENTHESIS.matcher(after).find());
    if (SQL_BEFORE.matcher(before).find()) {
      out.accept(Pair.of("password", value, lineNo));
    }

    if (previous != null && previous.isQuoted()) {
      var between = line.substring(previous.end(), literal.start());
      if (QUOTED_KEY_GAP.matcher(between).matches()) {
        // "clé": "valeur"
        out.accept(Pair.of(normalizeKey(previous.text()), value, lineNo));
      }
      // put("clé", "valeur"), getenv("CLÉ", "défaut"), define('CLÉ', 'valeur')
      var beforePrevious = line.substring(Math.max(0, previous.start() - CONTEXT_LENGTH), previous.start());
      if (KEY_NAME.matcher(previous.text()).matches() && COMMA_GAP.matcher(between).matches()
        && OPEN_PARENTHESIS.matcher(beforePrevious).find()) {
        out.accept(Pair.of(previous.text(), value, lineNo));
      }
    }
  }

  private static void emit(Consumer<Pair> out, int lineNo, String value, String key) {
    emit(out, lineNo, value, key, true);
  }

  private static void emit(Consumer<Pair> out, int lineNo, String value, String key, boolean condition) {
    if (key != null && condition) {
      out.accept(Pair.of(normalizeKey(key), value, lineNo));
    }
  }

  /** Premier groupe capturé de la première occurrence du motif, ou {@code null}. */
  private static String firstGroup(Pattern pattern, String text) {
    var m = pattern.matcher(text);
    return m.find() ? m.group(1) : null;
  }

  /** Repère tous les littéraux d'une ligne, en une seule passe. */
  private static List<Literal> literals(String line) {
    List<Literal> found = new ArrayList<>();
    var i = 0;
    while (i < line.length()) {
      var c = line.charAt(i);
      int end = isQuote(c) && opensLiteral(line, i) ? closingQuote(line, i + 1, c) : -1;
      if (end > 0) {
        found.add(new Literal(i, end + 1, c, line.substring(i + 1, end)));
        i = end + 1;
      } else {
        i++;
      }
    }
    return found;
  }

  private static boolean isQuote(char c) {
    return c == '"' || c == '\'' || c == '`';
  }

  /** Une apostrophe précédée d'une lettre ou d'un chiffre est une élision (« don't »), pas un guillemet ouvrant. */
  private static boolean opensLiteral(String line, int index) {
    return line.charAt(index) != '\'' || index == 0 || !Character.isLetterOrDigit(line.charAt(index - 1));
  }

  /** Position du guillemet fermant, ou -1. Un antislash échappe le caractère suivant (sauf entre accents graves). */
  private static int closingQuote(String line, int from, char quote) {
    int i = from;
    while (i < line.length()) {
      var c = line.charAt(i);
      if (c == quote) {
        return i;
      }
      i += c == '\\' && quote != '`' ? ESCAPE_SEQUENCE_LENGTH : 1;
    }
    return -1;
  }

  /** Retire les préfixes {@code $} et {@code @}, puis ne garde que le dernier segment d'un nom pointé. */
  private static String normalizeKey(String raw) {
    String key = raw.strip();
    var start = 0;
    while (start < key.length() && (key.charAt(start) == '$' || key.charAt(start) == '@')) {
      start++;
    }
    key = key.substring(start);
    int dot = key.lastIndexOf('.');
    return dot >= 0 && dot < key.length() - 1 ? key.substring(dot + 1) : key;
  }

  /** Littéral de chaîne : positions dans la ligne ({@code end} exclu), guillemet utilisé et contenu. */
  private record Literal(int start, int end, char quote, String text) {
    boolean isQuoted() {
      return quote != '`';
    }
  }
}
