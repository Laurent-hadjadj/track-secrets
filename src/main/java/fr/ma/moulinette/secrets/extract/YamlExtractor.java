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
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.NavigableMap;
import java.util.TreeMap;
import java.util.function.Consumer;
import java.util.regex.Pattern;

/**
 * [Description YamlExtractor]
 *
 * Extracteur YAML léger, basé sur l'indentation et sans dépendance.
 * Il fournit des numéros de ligne exacts et reste tolérant aux gabarits (Helm, Jinja)
 * qui rendent le YAML invalide.
 * Il gère les cartes, les listes, les scalaires de bloc, les cartes de flux sur une ligne,
 * les paramètres
 * CloudFormation et les paires {@code key|name} / {@code value} (variables d'environnement
 * Kubernetes).
 */
final class YamlExtractor implements Extractor {

  private static final Pattern BLOCK_SCALAR = Pattern.compile("^[|>][+\\-0-9]*$");

  /** Un paramètre CloudFormation se trouve sous {@code Parameters.<Nom>} : deux niveaux de clés. */
  private static final int CLOUDFORMATION_PARAMETER_DEPTH = 2;
  /** Longueur minimale d'une valeur entre guillemets : le guillemet ouvrant et le guillemet fermant. */
  private static final int QUOTES_LENGTH = 2;
  @Override
  public void extract(String content, Consumer<Pair> out) {
    var st = new State(out);
    String[] lines = Lines.of(content);
    var i = 0;
    while (i < lines.length) {
      String trimmed = lines[i].strip();
      if ("---".equals(trimmed) || "...".equals(trimmed) || trimmed.startsWith("--- ")) {
        flushAll(st);
        st.stack.clear();
        i++;
      } else if (trimmed.isEmpty() || trimmed.startsWith("#")) {
        i++;
      } else {
        i = processLine(st, lines, i) + 1;
      }
    }
    flushAll(st);
  }
  private static Parsed parse(String raw) {
    int indent = raw.length() - raw.stripLeading().length();
    String rest = raw.strip();
    var listItem = false;
    while ("-".equals(rest) || rest.startsWith("- ")) {
      listItem = true;
      var after = rest.substring(1);
      indent += 1 + (after.length() - after.stripLeading().length());
      rest = after.strip();
    }
    return new Parsed(indent, rest, listItem);
  }

  private static int processLine(State st, String[] lines, int index) {
    Parsed line = parse(lines[index]);
    if (line.rest().isEmpty()) {
      if (line.listItem()) {
        flushFrom(st, line.indent());
      }
      return index;
    }
    var entry = KeyValueLines.mapping(line.rest());
    if (entry == null) {
      if (line.listItem()) {
        scalarItem(st, line.indent(), line.rest(), index + 1);
      }
      return index;
    }
    return mappingLine(st, lines, index, line, entry);
  }

  /** Ligne {@code clé: valeur} (éventuellement précédée d'un marqueur de liste). */
  private static int mappingLine(State st, String[] lines, int index, Parsed line, KeyValueLines.KeyValue entry) {
    int indent = line.indent();
    String key = unquote(entry.key().strip());
    String value = entry.value().isEmpty() ? "" : stripComment(entry.value().strip());

    flushFrom(st, line.listItem() ? indent : (indent + 1));
    popFramesFrom(st, indent);
    if (indent == 0 && "AWSTemplateFormatVersion".equals(key)) {
      st.cloudFormation = true;
    }
    if (value.isEmpty()) {
      st.stack.push(new Frame(indent, key));
      return index;
    }
    List<String> crumbs = st.crumbs();
    if (BLOCK_SCALAR.matcher(value).matches()) {
      return blockScalar(st, lines, index, indent, key, crumbs);
    }
    int lineNo = index + 1;
    if (isFlow(value)) {
      flow(st, key, value, crumbs, lineNo);
    } else {
      emitScalar(st, indent, key, unquote(value), crumbs, lineNo);
    }
    return index;
  }

  /** Retire les clés ouvertes dont l'indentation est supérieure ou égale à celle de la ligne courante. */
  private static void popFramesFrom(State st, int indent) {
    while (!st.stack.isEmpty() && st.stack.peek().indent() >= indent) {
      st.stack.pop();
    }
  }

  private static boolean isFlow(String value) {
    return (value.startsWith("{") && value.endsWith("}")) || (value.startsWith("[") && value.endsWith("]"));
  }

  private static void scalarItem(State st, int indent, String text, int lineNo) {
    while (!st.stack.isEmpty() && st.stack.peek().indent() > indent) {
      st.stack.pop();
    }
    String parentKey = st.stack.isEmpty() ? "" : st.stack.peek().key();
    List<String> crumbs = st.crumbs();
    st.out.accept(new Pair(parentKey, unquote(stripComment(text)), crumbs, lineNo));
    derived(st, unquote(stripComment(text)), crumbs, lineNo);
  }

  private static void emitScalar(State st, int indent, String key, String value, List<String> crumbs, int lineNo) {
    var pair = new Pair(key, value, crumbs, lineNo);
    st.out.accept(pair);
    derived(st, value, crumbs, lineNo);
    st.remember(indent, key, pair);
    // Paramètres CloudFormation : Parameters.<Nom>.Default
    if (st.cloudFormation && "Default".equals(key)
        && crumbs.size() == CLOUDFORMATION_PARAMETER_DEPTH && "Parameters".equals(crumbs.get(0))) {
      st.out.accept(new Pair(crumbs.get(1), value, crumbs, lineNo));
    }
  }

  /** Paires dérivées d'une valeur : {@code clé=valeur} et URI. */
  private static void derived(State st, String value, List<String> crumbs, int lineNo) {
    int eq = value.indexOf('=');
    if (eq > 0 && eq < value.length() - 1) {
      st.out.accept(new Pair(value.substring(0, eq), value.substring(eq + 1), crumbs, lineNo));
    }
    if (Patterns.looksLikeUri(value)) {
      UriPairs.extract(value, lineNo, crumbs, st.out);
    }
  }

  private static int blockScalar(State st, String[] lines, int index, int indent, String key, List<String> crumbs) {
    var text = new StringBuilder();
    int j = index + 1;
    for (; j < lines.length; j++) {
      String l = lines[j];
      if (!l.isBlank() && l.length() - l.stripLeading().length() <= indent) {
        break;
      }
      text.append(l.strip()).append('\n');
    }
    String value = text.toString().strip();
    if (!value.isEmpty()) {
      st.out.accept(new Pair(key, value, crumbs, index + 1));
    }
    return j - 1;
  }

  /** Carte ou liste de flux sur une ligne : {@code {a: b, c: d}} ou {@code [x, y]}. */
  private static void flow(State st, String key, String value, List<String> crumbs, int lineNo) {
    var inner = value.substring(1, value.length() - 1);
    boolean map = value.startsWith("{");
    for (String part : inner.split(",")) {
      String item = part.strip();
      if (!item.isEmpty()) {
        flowItem(st, map ? null : key, item, crumbs, lineNo);
      }
    }
  }

  /** Élément d'une carte de flux (clé: valeur) si {@code listKey} est nul, d'une liste de flux sinon. */
  private static void flowItem(State st, String listKey, String item, List<String> crumbs, int lineNo) {
    if (listKey != null) {
      st.out.accept(new Pair(listKey, unquote(item), crumbs, lineNo));
      return;
    }
    int colon = item.indexOf(':');
    if (colon > 0) {
      st.out.accept(new Pair(unquote(item.substring(0, colon).strip()),
        unquote(item.substring(colon + 1).strip()), crumbs, lineNo));
    }
  }

  private static void flushFrom(State st, int indent) {
    // Les cartes d'indentation supérieure ou égale sont terminées
    for (var mapping : st.takeFrom(indent)) {
      flush(st, mapping);
    }
  }

  private static void flushAll(State st) {
    flushFrom(st, 0);
  }

  private static void flush(State st, Map<String, Pair> mapping) {
    Pair value = mapping.get("value");
    Pair name = mapping.get("key");
    if (name == null) {
      name = mapping.get("name");
    }
    if (value != null && name != null) {
      st.out.accept(new Pair(name.value(), value.value(), value.breadcrumbs(), value.line()));
    }
  }

  private static String stripComment(String value) {
    if (value.startsWith("\"") || value.startsWith("'")) {
      int close = value.indexOf(value.charAt(0), 1);
      return close > 0 ? value.substring(0, close + 1) : value;
    }
    int hash = value.indexOf(" #");
    return hash >= 0 ? value.substring(0, hash).strip() : value;
  }

  private static String unquote(String value) {
    if (value.length() >= QUOTES_LENGTH && (surroundedBy(value, '"') || surroundedBy(value, '\''))) {
      return value.substring(1, value.length() - 1);
    }
    return value;
  }

  private static boolean surroundedBy(String value, char quote) {
    return value.charAt(0) == quote && value.charAt(value.length() - 1) == quote;
  }

  private record Frame(int indent, String key) {
  }

  private static final class State {
    private final Consumer<Pair> out;
    private final Deque<Frame> stack = new ArrayDeque<>();
    /** Scalaires de chaque carte ouverte, par indentation, pour détecter les paires key|name + value. */
    private final NavigableMap<Integer, Map<String, Pair>> mappings = new TreeMap<>();
    private boolean cloudFormation;

    State(Consumer<Pair> out) {
      this.out = out;
    }

    /** Retient une paire scalaire de la carte ouverte à cette indentation. */
    void remember(int indent, String key, Pair pair) {
      mappings.computeIfAbsent(indent, k -> new LinkedHashMap<>()).put(key, pair);
    }

    /** Retire et retourne, dans l'ordre des indentations, les cartes d'indentation supérieure ou égale. */
    List<Map<String, Pair>> takeFrom(int indent) {
      var tail = mappings.tailMap(indent, true);
      var taken = new ArrayList<>(tail.values());
      tail.clear();
      return taken;
    }

    List<String> crumbs() {
      List<String> keys = new ArrayList<>();
      stack.descendingIterator().forEachRemaining(f -> keys.add(f.key()));
      return keys;
    }
  }

  /** Ligne décomposée : indentation effective (après les marqueurs de liste), texte restant, marqueur de liste. */
  private record Parsed(int indent, String rest, boolean listItem) {
  }
}
