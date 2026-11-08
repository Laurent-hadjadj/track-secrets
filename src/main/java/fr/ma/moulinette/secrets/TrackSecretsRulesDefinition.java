/*
 * Copyright 2026 Laurent HADJADJ
 * SPDX-License-Identifier: LGPL-3.0-or-later
 */
package fr.ma.moulinette.secrets;

import fr.ma.moulinette.secrets.engine.RuleCatalog;
import javax.annotation.Nonnull;
import org.sonar.api.SonarRuntime;
import org.sonar.api.server.rule.RulesDefinition;
import org.sonarsource.analyzer.commons.RuleMetadataLoader;

/**
 * [Description TrackSecretsRulesDefinition]
 *
 * Déclare le dépôt de règles et charge les métadonnées (json et html) de chaque règle.
 */
public final class TrackSecretsRulesDefinition implements RulesDefinition {

  public static final String REPOSITORY_KEY = "track-secrets";
  public static final String REPOSITORY_NAME = "Track Secrets";
  public static final String RESOURCE_BASE_PATH = "org/sonar/l10n/trksecrets/rules/trksecrets";

  private final SonarRuntime runtime;

  public TrackSecretsRulesDefinition(SonarRuntime runtime) {
    this.runtime = runtime;
  }

  @Override
  public void define(@Nonnull Context context) {
    NewRepository repository = context
      .createRepository(REPOSITORY_KEY, TrackSecretsLanguage.KEY)
      .setName(REPOSITORY_NAME);
    new RuleMetadataLoader(RESOURCE_BASE_PATH, runtime)
      .addRulesByRuleKey(repository, RuleCatalog.ruleKeys());
    repository.done();
  }
}
