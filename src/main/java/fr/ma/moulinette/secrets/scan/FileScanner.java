/*
 * Copyright 2026 Laurent HADJADJ
 * Copyright Skyscanner Ltd (parties dérivées)
 * SPDX-License-Identifier: LGPL-3.0-or-later AND Apache-2.0
 *
 * Dérivé de Whispers (Skyscanner, licence Apache-2.0, texte dans
 * LICENSES/Apache-2.0.txt). Modifié : portage en Java. Voir NOTICE.
 */
package fr.ma.moulinette.secrets.scan;

import fr.ma.moulinette.secrets.engine.Detector;
import fr.ma.moulinette.secrets.engine.Finding;
import fr.ma.moulinette.secrets.engine.Pair;
import fr.ma.moulinette.secrets.extract.Extractor;
import fr.ma.moulinette.secrets.extract.ExtractorRegistry;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.regex.Pattern;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * [Description FileScanner]
 *
 * Analyse le contenu d'un fichier : extraction des couples, détection,
 * dédoublonnage par règle et ligne.
 */
public final class FileScanner {

  private static final Logger LOG = LoggerFactory.getLogger(FileScanner.class);
  private static final Pattern LINE_BREAK = Pattern.compile("\\r?\\n");

  private final Detector detector;

  public FileScanner(Detector detector) {
    this.detector = detector;
  }

  /**
   * @param relativePath chemin relatif du fichier (sert au choix de l'extracteur et à la règle sensitive-file)
   * @param content      contenu texte du fichier
   */
  public List<Finding> scan(String relativePath, String content) {
    List<Finding> findings = new ArrayList<>();
    Set<String> seen = new HashSet<>();

    // Règle fondée sur le nom du fichier
    detector.check(Pair.of("file", relativePath.replace('\\', '/'), 0)).forEach(f -> add(findings, seen, f));

    // Lignes brutes : en-têtes de clé privée dans n'importe quel fichier texte
    String[] lines = LINE_BREAK.split(content, -1);
    for (var i = 0; i < lines.length; i++) {
      final int lineNo = i + 1;
      detector.checkRawLine(lines[i], lineNo).forEach(f -> add(findings, seen, f));
    }

    Optional<Extractor> extractor = ExtractorRegistry.forFile(relativePath, content);
    if (extractor.isPresent()) {
      try {
        extractor.get().extract(content, pair -> detector.check(pair).forEach(f -> add(findings, seen, f)));
      } catch (RuntimeException | StackOverflowError e) {
        // un fichier illisible ne doit pas interrompre l'analyse ; les anomalies déjà trouvées sont conservées.
        // StackOverflowError : une ligne pathologique peut épuiser la pile des expressions régulières.
        LOG.debug("Track Secrets: extraction interrompue pour {}", relativePath, e);
      }
    }
    return findings;
  }

  private static void add(Collection<Finding> findings, Set<String> seen, Finding f) {
    if (seen.add(f.ruleKey() + ":" + f.line())) {
      findings.add(f);
    }
  }
}
