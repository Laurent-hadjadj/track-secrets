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
import java.util.function.Consumer;

/** Extrait les couples clé/valeur d'un contenu de fichier. Ne doit jamais lever d'exception à l'appelant. */
@FunctionalInterface
public interface Extractor {

  void extract(String content, Consumer<Pair> out);
}
