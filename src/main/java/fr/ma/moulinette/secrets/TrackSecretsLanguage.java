/*
 * Copyright 2026 Laurent HADJADJ
 * SPDX-License-Identifier: LGPL-3.0-or-later
 */
package fr.ma.moulinette.secrets;

import org.sonar.api.resources.AbstractLanguage;

/**
 * [Description TrackSecretsLanguage]
 *
  * Langage « virtuel » qui porte le dépôt de règles et le profil qualité.
  * Il n'a aucun suffixe de fichier :
  * le capteur analyse les fichiers de tous les langages et rapporte les anomalies
  * sur chacun d'eux.
 */
public final class TrackSecretsLanguage extends AbstractLanguage {

  public static final String KEY = "trksecrets";
  public static final String NAME = "Secrets (Track Secrets)";

  public TrackSecretsLanguage() {
    super(KEY, NAME);
  }

  @Override
  public String[] getFileSuffixes() {
    return new String[0];
  }
}
