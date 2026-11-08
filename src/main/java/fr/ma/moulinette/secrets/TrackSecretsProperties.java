/*
 * Copyright 2026 Laurent HADJADJ
 * SPDX-License-Identifier: LGPL-3.0-or-later
 */
package fr.ma.moulinette.secrets;

import fr.ma.moulinette.secrets.engine.RuleCatalog;
import java.util.List;
import org.sonar.api.PropertyType;
import org.sonar.api.config.PropertyDefinition;
import org.sonar.api.resources.Qualifiers;

/**
 * [Description TrackSecretsProperties]
 *
 * Propriétés de configuration du plugin.
 */
public final class TrackSecretsProperties {

  public static final String CATEGORY = "Track Secrets";
  public static final String EXCLUDE_KEYS = "track.secrets.exclusions.keys";
  public static final String EXCLUDE_VALUES = "track.secrets.exclusions.values";
  public static final String ENTROPY_THRESHOLD = "track.secrets.entropy.threshold";
  public static final String INCLUDE_TESTS = "track.secrets.includeTests";
  public static final String MAX_FILE_SIZE_KB = "track.secrets.maxFileSizeKb";
  public static final String SKIP_NATIVE_OVERLAP = "track.secrets.skipNativeOverlap";
  public static final String CUSTOM_RULES_PATH = "track.secrets.customRules.path";

  public static final int DEFAULT_MAX_FILE_SIZE_KB = 1024;

  // Ordre d'affichage des propriétés dans l'administration de SonarQube
  private static final int ORDER_EXCLUDED_KEYS = 1;
  private static final int ORDER_EXCLUDED_VALUES = 2;
  private static final int ORDER_ENTROPY = 3;
  private static final int ORDER_INCLUDE_TESTS = 4;
  private static final int ORDER_MAX_FILE_SIZE = 5;
  private static final int ORDER_NATIVE_OVERLAP = 6;
  private static final int ORDER_CUSTOM_RULES = 7;

  private TrackSecretsProperties() {
  }

  static List<PropertyDefinition> definitions() {
    return List.of(
      PropertyDefinition.builder(EXCLUDE_KEYS)
        .name("Additional excluded keys")
        .description("Regular expressions (one per line, case-insensitive, anchored at the start) "
          + "of key names to ignore, added to the built-in exclusions.")
        .type(PropertyType.TEXT).category(CATEGORY).onQualifiers(Qualifiers.PROJECT).index(ORDER_EXCLUDED_KEYS).build(),
      PropertyDefinition.builder(EXCLUDE_VALUES)
        .name("Additional excluded values")
        .description("Regular expressions (one per line, case-insensitive, anchored at the start) of values to ignore, "
          + "added to the built-in exclusions.")
        .type(PropertyType.TEXT).category(CATEGORY).onQualifiers(Qualifiers.PROJECT)
        .index(ORDER_EXCLUDED_VALUES).build(),
      PropertyDefinition.builder(ENTROPY_THRESHOLD)
        .name("High-entropy threshold")
        .description("Minimum Shannon entropy (bits per character) for the rule 'high-entropy-string'.")
        .type(PropertyType.FLOAT).defaultValue(String.valueOf(RuleCatalog.DEFAULT_ENTROPY_THRESHOLD))
        .category(CATEGORY).onQualifiers(Qualifiers.PROJECT).index(ORDER_ENTROPY).build(),
      PropertyDefinition.builder(INCLUDE_TESTS)
        .name("Analyze test files")
        .description("Test files are ignored by default, as test fixtures often contain fake credentials.")
        .type(PropertyType.BOOLEAN).defaultValue("false")
        .category(CATEGORY).onQualifiers(Qualifiers.PROJECT).index(ORDER_INCLUDE_TESTS).build(),
      PropertyDefinition.builder(MAX_FILE_SIZE_KB)
        .name("Maximum file size (KB)")
        .description("Larger files are skipped.")
        .type(PropertyType.INTEGER).defaultValue(String.valueOf(DEFAULT_MAX_FILE_SIZE_KB))
        .category(CATEGORY).onQualifiers(Qualifiers.PROJECT).index(ORDER_MAX_FILE_SIZE).build(),
      PropertyDefinition.builder(SKIP_NATIVE_OVERLAP)
        .name("Skip passwords already covered by the language analyzers")
        .description("Do not report 'hardcoded-password' in Java, Kotlin, C#, Python, JavaScript, TypeScript and PHP "
          + "files, where the language analyzers already provide the rule S2068.")
        .type(PropertyType.BOOLEAN).defaultValue("true")
        .category(CATEGORY).onQualifiers(Qualifiers.PROJECT).index(ORDER_NATIVE_OVERLAP).build(),
      PropertyDefinition.builder(CUSTOM_RULES_PATH)
        .name("Custom rules file")
        .description("Path (relative to the project base directory) of a .properties file defining custom rules.")
        .type(PropertyType.STRING)
        .category(CATEGORY).onQualifiers(Qualifiers.PROJECT).index(ORDER_CUSTOM_RULES).build());
  }
}
