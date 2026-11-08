/*
 * Copyright 2026 Laurent HADJADJ
 * SPDX-License-Identifier: LGPL-3.0-or-later
 */
package fr.ma.moulinette.secrets;

import javax.annotation.Nonnull;
import org.sonar.api.Plugin;

/**
 * [Description TrackSecretsPlugin]
 *
 *Point d'entrée du plugin : déclare les extensions serveur et scanner.
 */
public class TrackSecretsPlugin implements Plugin {

  @Override
  public void define(@Nonnull Context context) {
    // Côté serveur
    context.addExtension(TrackSecretsLanguage.class);
    context.addExtension(TrackSecretsRulesDefinition.class);
    context.addExtension(TrackSecretsQualityProfile.class);
    context.addExtensions(TrackSecretsProperties.definitions());

    // Côté scanner
    context.addExtension(TrackSecretsSensor.class);
  }
}
