/*
 * Copyright 2026 Laurent HADJADJ
 * SPDX-License-Identifier: LGPL-3.0-or-later
 */
package fr.ma.moulinette.secrets;

import fr.ma.moulinette.secrets.engine.RuleCatalog;
import javax.annotation.Nonnull;
import org.sonar.api.server.profile.BuiltInQualityProfilesDefinition;

/** Profil « Track Secrets » : active les règles non couvertes par le moteur natif sonar-text. */
public final class TrackSecretsQualityProfile implements BuiltInQualityProfilesDefinition {

  public static final String PROFILE_NAME = "Track Secrets";

  @Override
  public void define(@Nonnull Context context) {
    NewBuiltInQualityProfile profile = context.createBuiltInQualityProfile(PROFILE_NAME, TrackSecretsLanguage.KEY);
    profile.setDefault(true);
    RuleCatalog.defaultActiveRuleKeys()
      .forEach(key -> profile.activateRule(TrackSecretsRulesDefinition.REPOSITORY_KEY, key));
    profile.done();
  }
}
