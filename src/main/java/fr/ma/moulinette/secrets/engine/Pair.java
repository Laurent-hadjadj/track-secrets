/*
 * Copyright 2026 Laurent HADJADJ
 * Copyright Skyscanner Ltd (parties dérivées)
 * SPDX-License-Identifier: LGPL-3.0-or-later AND Apache-2.0
 *
 * Dérivé de Whispers (Skyscanner, licence Apache-2.0, texte dans
 * LICENSES/Apache-2.0.txt). Modifié : portage en Java. Voir NOTICE.
 */
package fr.ma.moulinette.secrets.engine;

import java.util.List;

/**
 * Couple clé/valeur extrait d'un fichier.
 *
 * @param key         nom de la clé (variable, propriété, balise...) ; peut être vide
 * @param value       valeur brute
 * @param breadcrumbs chemin des clés parentes (documents structurés) ; jamais {@code null}
 * @param line        numéro de ligne (à partir de 1), ou 0 si inconnu
 */
public record Pair(String key, String value, List<String> breadcrumbs, int line) {

  // Constructeur canonique explicite plutôt que compact : la règle Creedengo GCI82 plante sur un constructeur
  // compact (IndexOutOfBoundsException dans MakeNonReassignedVariablesConstants), faute de paramètres déclarés.
  public Pair(String key, String value, List<String> breadcrumbs, int line) {
    this.key = key;
    this.value = value;
    // copie immuable
    this.breadcrumbs = breadcrumbs == null ? List.of() : List.copyOf(breadcrumbs);
    this.line = line;
  }

  public static Pair of(String key, String value, int line) {
    return new Pair(key, value, List.of(), line);
  }
}
