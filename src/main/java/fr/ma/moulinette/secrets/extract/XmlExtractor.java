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
import java.io.StringReader;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.List;
import java.util.Locale;
import java.util.function.Consumer;
import javax.xml.stream.XMLInputFactory;
import javax.xml.stream.XMLStreamConstants;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamReader;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * [Description XmlExtractor]
 *
 * Extracteur XML (StAX, DTD et entités externes désactivées). Formats reconnus :
 * {@code <e clé="valeur"/>}, {@code <clé>valeur</clé>}, {@code <e>clé=valeur</e>},
 * {@code <key>k</key><value>v</value>} et {@code <e name="k" value="v"/>} (Spring, Tomcat...).
 */
final class XmlExtractor implements Extractor {

  private static final Logger LOG = LoggerFactory.getLogger(XmlExtractor.class);
  @Override
  public void extract(String content, Consumer<Pair> out) {
    Deque<Element> stack = new ArrayDeque<>();
    try (var in = new StringReader(content)) {
      // Protection contre les attaques XXE : DTD et entités externes désactivées.
      // La fabrique est configurée dans la méthode qui l'utilise, ce qui permet
      // aux analyseurs de sécurité de vérifier cette protection.
      var factory = XMLInputFactory.newFactory();
      factory.setProperty(XMLInputFactory.SUPPORT_DTD, false);
      factory.setProperty(XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, false);
      factory.setProperty(XMLInputFactory.IS_REPLACING_ENTITY_REFERENCES, false);
      var r = factory.createXMLStreamReader(in);
      try {
        read(r, stack, out);
      } finally {
        // XMLStreamReader n'est pas AutoCloseable
        r.close();
      }
    } catch (XMLStreamException | RuntimeException e) {
      LOG.debug("Track Secrets: XML mal formé, lecture interrompue", e);
      // document mal formé : on conserve les paires déjà émises
    }
  }

  private static void read(XMLStreamReader r, Deque<Element> stack, Consumer<Pair> out) throws XMLStreamException {
    while (r.hasNext()) {
      switch (r.next()) {
        case XMLStreamConstants.START_ELEMENT -> start(r, stack, out);
        case XMLStreamConstants.CHARACTERS, XMLStreamConstants.CDATA -> {
          Element e = stack.peek();
          if (e != null && !e.hasChild) {
            e.text.append(r.getText());
          }
        }
        case XMLStreamConstants.END_ELEMENT -> end(stack, out);
        default -> { /* commentaires, instructions de traitement... */ }
      }
    }
  }

  private static void start(XMLStreamReader r, Deque<Element> stack, Consumer<Pair> out) {
    int line = r.getLocation().getLineNumber();
    Element parent = stack.peek();
    if (parent != null) {
      parent.hasChild = true;
    }
    var e = new Element(r.getLocalName(), line);
    stack.push(e);
    List<String> crumbs = crumbs(stack);

    String name = null;
    String value = null;
    for (var i = 0; i < r.getAttributeCount(); i++) {
      String an = r.getAttributeLocalName(i);
      String av = r.getAttributeValue(i);
      out.accept(new Pair(an, av, crumbs, line));
      if (Patterns.looksLikeUri(av)) {
        UriPairs.extract(av, line, crumbs, out);
      }
      // les autres attributs sont déjà émis tels quels plus haut
      if ("name".equals(an) || "key".equals(an)) {
        name = av;
      }
      if ("value".equals(an)) {
        value = av;
      }
    }
    if (name != null && value != null) {
      out.accept(new Pair(name, value, crumbs, line));
    }
  }

  private static void end(Deque<Element> stack, Consumer<Pair> out) {
    Element e = stack.peek();
    if (e == null) {
      return;
    }
    String text = e.text.toString().strip();
    if (!text.isEmpty()) {
      emitText(e, text, crumbs(stack), out);
    }
    stack.pop();
    Element parent = stack.peek();
    if (parent != null && !text.isEmpty()) {
      registerKeyValueChild(parent, e, text, stack, out);
    }
  }

  /** Texte d'un élément : {@code <clé>valeur</clé>}, {@code <e>clé=valeur</e>} ou URI. */
  private static void emitText(Element e, String text, List<String> crumbs, Consumer<Pair> out) {
    out.accept(new Pair(e.tag, text, crumbs, e.line));
    int eq = text.indexOf('=');
    if (eq > 0 && eq < text.length() - 1) {
      out.accept(new Pair(text.substring(0, eq), text.substring(eq + 1), crumbs, e.line));
    }
    if (Patterns.looksLikeUri(text)) {
      UriPairs.extract(text, e.line, crumbs, out);
    }
  }

  /** Format {@code <key>k</key><value>v</value>} : émet la paire dès que les deux enfants sont lus. */
  private static void registerKeyValueChild(Element parent, Element child, String text, Deque<Element> stack,
    Consumer<Pair> out) {
    if (parent.addChild(child.tag.toLowerCase(Locale.ROOT), text)) {
      out.accept(parent.takePair(crumbs(stack), child.line));
    }
  }

  private static List<String> crumbs(Deque<Element> stack) {
    List<String> tags = new ArrayList<>();
    stack.descendingIterator().forEachRemaining(e -> tags.add(e.tag));
    return tags;
  }

  private static final class Element {
    private final String tag;
    private final int line;
    private final StringBuilder text = new StringBuilder();
    private boolean hasChild;
    private String keyChild;
    private String valueChild;

    Element(String tag, int line) {
      this.tag = tag;
      this.line = line;
    }

    /** Retient le texte d'un enfant {@code key} ou {@code value} ; vrai quand la paire est complète. */
    boolean addChild(String childTag, String childText) {
      // les autres balises n'ont ni rôle de clé ni rôle de valeur
      if ("key".equals(childTag)) {
        keyChild = childText;
      }
      if ("value".equals(childTag)) {
        valueChild = childText;
      }
      return keyChild != null && valueChild != null;
    }

    /** Paire clé / valeur retenue ; l'élément est ensuite prêt à en recevoir une autre. */
    Pair takePair(List<String> crumbs, int atLine) {
      var pair = new Pair(keyChild, valueChild, crumbs, atLine);
      keyChild = null;
      valueChild = null;
      return pair;
    }
  }
}
