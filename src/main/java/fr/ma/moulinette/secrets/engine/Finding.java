/*
 * Copyright 2026 Laurent HADJADJ
 * Copyright Skyscanner Ltd (parties dérivées)
 * SPDX-License-Identifier: LGPL-3.0-or-later AND Apache-2.0
 *
 * Dérivé de Whispers (Skyscanner, licence Apache-2.0, texte dans
 * LICENSES/Apache-2.0.txt). Modifié : portage en Java. Voir NOTICE.
 */
package fr.ma.moulinette.secrets.engine;

/**
 * Secret détecté. La valeur n'est volontairement jamais conservée afin de ne pas
 * la faire fuiter dans les rapports ou les journaux.
 *
 * @param ruleKey clé de la règle SonarQube
 * @param key     nom de la clé associée à la valeur
 * @param line    numéro de ligne (à partir de 1), ou 0 si inconnu
 * @param label   nom de la règle personnalisée à l'origine de l'anomalie, ou {@code null} pour une règle intégrée
 */
public record Finding(String ruleKey, String key, int line, String label) {
}
