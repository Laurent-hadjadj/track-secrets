/*
 * Copyright 2026 Laurent HADJADJ
 * SPDX-License-Identifier: LGPL-3.0-or-later
 */
package fr.ma.moulinette.secrets;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.RETURNS_SELF;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import fr.ma.moulinette.secrets.engine.RuleCatalog;
import java.io.File;
import java.io.IOException;
import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.sonar.api.Plugin;
import org.sonar.api.SonarEdition;
import org.sonar.api.SonarQubeSide;
import org.sonar.api.SonarRuntime;
import org.sonar.api.batch.fs.FilePredicate;
import org.sonar.api.batch.fs.FilePredicates;
import org.sonar.api.batch.fs.FileSystem;
import org.sonar.api.batch.fs.InputFile;
import org.sonar.api.batch.fs.TextRange;
import org.sonar.api.batch.rule.ActiveRule;
import org.sonar.api.batch.rule.ActiveRules;
import org.sonar.api.batch.sensor.SensorContext;
import org.sonar.api.batch.sensor.SensorDescriptor;
import org.sonar.api.batch.sensor.issue.NewIssue;
import org.sonar.api.batch.sensor.issue.NewIssueLocation;
import org.sonar.api.config.Configuration;
import org.sonar.api.rule.RuleKey;
import org.sonar.api.server.profile.BuiltInQualityProfilesDefinition;
import org.sonar.api.server.rule.RulesDefinition;
import org.sonar.api.utils.Version;

/**
 * [Description PluginTest]
 */
class PluginTest {

  private static SonarRuntime runtime() {
    SonarRuntime runtime = mock(SonarRuntime.class);
    when(runtime.getApiVersion()).thenReturn(Version.create(10, 7));
    when(runtime.getEdition()).thenReturn(SonarEdition.COMMUNITY);
    when(runtime.getSonarQubeSide()).thenReturn(SonarQubeSide.SERVER);
    return runtime;
  }

  @Test
  void plugin_declares_its_extensions() {
    Plugin.Context context = new Plugin.Context(runtime());
    new TrackSecretsPlugin().define(context);
    assertThat(context.getExtensions()).contains(TrackSecretsLanguage.class, TrackSecretsRulesDefinition.class,
      TrackSecretsQualityProfile.class, TrackSecretsSensor.class);
    assertThat(context.getExtensions()).hasSize(4 + TrackSecretsProperties.definitions().size());
  }

  @Test
  void language_has_no_suffix() {
    TrackSecretsLanguage language = new TrackSecretsLanguage();
    assertThat(language.getKey()).isEqualTo("trksecrets");
    assertThat(language.getFileSuffixes()).isEmpty();
  }

  @Test
  void every_rule_has_its_metadata() {
    RulesDefinition.Context context = new RulesDefinition.Context();
    new TrackSecretsRulesDefinition(runtime()).define(context);
    RulesDefinition.Repository repository = context.repository(TrackSecretsRulesDefinition.REPOSITORY_KEY);
    assertThat(repository).isNotNull();
    assertThat(repository.language()).isEqualTo(TrackSecretsLanguage.KEY);
    assertThat(repository.rules().stream().map(RulesDefinition.Rule::key))
      .containsExactlyInAnyOrderElementsOf(RuleCatalog.ruleKeys());
    assertThat(repository.rules()).allSatisfy(rule -> {
      assertThat(rule.name()).isNotBlank();
      assertThat(rule.htmlDescription()).isNotBlank();
      assertThat(rule.severity()).isNotBlank();
    });
  }

  @Test
  void every_rule_and_property_is_translated_in_french() throws IOException {
    var bundle = new java.util.Properties();
    try (var in = PluginTest.class.getResourceAsStream("/org/sonar/l10n/track-secrets_fr.properties")) {
      assertThat(in).isNotNull();
      bundle.load(in);
    }
    for (var ruleKey : RuleCatalog.ruleKeys()) {
      assertThat(bundle.getProperty("rule.track-secrets." + ruleKey + ".name")).as(ruleKey).isNotBlank();
      assertThat(PluginTest.class.getResource(
        "/" + TrackSecretsRulesDefinition.RESOURCE_BASE_PATH + "/" + ruleKey + "_fr.html")).as(ruleKey).isNotNull();
    }
    for (var definition : TrackSecretsProperties.definitions()) {
      assertThat(bundle.getProperty("property." + definition.key() + ".name")).as(definition.key()).isNotBlank();
      assertThat(bundle.getProperty("property." + definition.key() + ".description")).as(definition.key()).isNotBlank();
    }
  }

  @Test
  void default_profile_activates_non_overlapping_rules() {
    BuiltInQualityProfilesDefinition.Context context = new BuiltInQualityProfilesDefinition.Context();
    new TrackSecretsQualityProfile().define(context);
    BuiltInQualityProfilesDefinition.BuiltInQualityProfile profile = context.profile("trksecrets", "Track Secrets");
    assertThat(profile.isDefault()).isTrue();
    assertThat(profile.rules().stream().map(BuiltInQualityProfilesDefinition.BuiltInActiveRule::ruleKey))
      .containsExactlyInAnyOrderElementsOf(RuleCatalog.defaultActiveRuleKeys());
  }

  // --- capteur ---------------------------------------------------------------------------------------

  /** Répertoire de base du projet simulé (un répertoire existant, pour que son URI se termine par une barre). */
  private static final File BASE_DIR = new File(System.getProperty("java.io.tmpdir"));

  private record Fixture(SensorContext context, NewIssue issue, NewIssueLocation location) {
  }

  private static Fixture sensorContext(List<String> activeKeys, List<InputFile> files, Configuration config) {
    SensorContext context = mock(SensorContext.class);
    ActiveRules activeRules = mock(ActiveRules.class);
    List<ActiveRule> active = activeKeys.stream().map(k -> {
      ActiveRule r = mock(ActiveRule.class);
      when(r.ruleKey()).thenReturn(RuleKey.of(TrackSecretsRulesDefinition.REPOSITORY_KEY, k));
      return r;
    }).toList();
    when(activeRules.findByRepository(TrackSecretsRulesDefinition.REPOSITORY_KEY)).thenReturn(active);
    when(context.activeRules()).thenReturn(activeRules);
    when(context.config()).thenReturn(config);

    FileSystem fs = mock(FileSystem.class);
    FilePredicates predicates = mock(FilePredicates.class);
    FilePredicate predicate = mock(FilePredicate.class);
    when(predicates.hasType(InputFile.Type.MAIN)).thenReturn(predicate);
    when(fs.predicates()).thenReturn(predicates);
    when(fs.inputFiles(predicate)).thenReturn(files);
    when(fs.baseDir()).thenReturn(BASE_DIR);
    when(context.fileSystem()).thenReturn(fs);

    NewIssue issue = mock(NewIssue.class, RETURNS_SELF);
    NewIssueLocation location = mock(NewIssueLocation.class, RETURNS_SELF);
    when(context.newIssue()).thenReturn(issue);
    when(issue.newLocation()).thenReturn(location);
    return new Fixture(context, issue, location);
  }

  private static Configuration emptyConfig() {
    Configuration config = mock(Configuration.class);
    when(config.get(anyString())).thenReturn(Optional.empty());
    when(config.getBoolean(anyString())).thenReturn(Optional.empty());
    when(config.getInt(anyString())).thenReturn(Optional.empty());
    return config;
  }

  private static InputFile file(String path, String content) throws IOException {
    InputFile file = mock(InputFile.class);
    when(file.uri()).thenReturn(BASE_DIR.toURI().resolve(path));
    when(file.contents()).thenReturn(content);
    when(file.lines()).thenReturn(content.split("\n", -1).length);
    var range = mock(TextRange.class);
    when(file.selectLine(any(Integer.class))).thenReturn(range);
    return file;
  }

  @Test
  void sensor_reports_issues_without_leaking_the_value() throws IOException {
    Fixture f = sensorContext(List.of("hardcoded-password"),
      List.of(file("config/app.properties", "a=b\ndb.password=Sup3rS3cret!")), emptyConfig());
    new TrackSecretsSensor().execute(f.context());

    verify(f.issue(), times(1)).save();
    ArgumentCaptor<String> message = ArgumentCaptor.forClass(String.class);
    verify(f.location()).message(message.capture());
    assertThat(message.getValue()).contains("password").doesNotContain("Sup3rS3cret");
    verify(f.issue()).forRule(RuleKey.of("track-secrets", "hardcoded-password"));
  }

  @Test
  void sensor_only_runs_active_rules() throws IOException {
    Fixture f = sensorContext(List.of("hardcoded-api-key"),
      List.of(file("a.properties", "db.password=Sup3rS3cret!")), emptyConfig());
    new TrackSecretsSensor().execute(f.context());
    verify(f.issue(), never()).save();
  }

  @Test
  void sensor_skips_passwords_covered_by_language_analyzers() throws IOException {
    Fixture f = sensorContext(List.of("hardcoded-password"), List.of(
      file("src/A.java", "String password = \"Sup3rS3cret!\";"),
      file("src/main.go", "const password = \"Sup3rS3cret!\"")), emptyConfig());
    new TrackSecretsSensor().execute(f.context());
    // uniquement le fichier Go
    verify(f.issue(), times(1)).save();
  }

  @Test
  void sensor_skips_binary_and_oversized_files() throws IOException {
    Configuration config = emptyConfig();
    when(config.getInt(TrackSecretsProperties.MAX_FILE_SIZE_KB)).thenReturn(Optional.of(1));
    Fixture f = sensorContext(List.of("hardcoded-password"), List.of(
      file("a.properties", "db.password=Sup3rS3cret!\u0000"),
      file("b.properties", "x".repeat(2048) + "\ndb.password=Sup3rS3cret!")), config);
    new TrackSecretsSensor().execute(f.context());
    verify(f.issue(), never()).save();
  }

  @Test
  void sensor_does_nothing_without_active_rule() {
    Fixture f = sensorContext(List.of(), List.of(), emptyConfig());
    new TrackSecretsSensor().execute(f.context());
    verify(f.context(), never()).newIssue();
  }

  @Test
  void sensor_descriptor() {
    SensorDescriptor descriptor = mock(SensorDescriptor.class, RETURNS_SELF);
    new TrackSecretsSensor().describe(descriptor);
    verify(descriptor).name("Track Secrets");
    verify(descriptor).createIssuesForRuleRepositories("track-secrets");
  }
}
