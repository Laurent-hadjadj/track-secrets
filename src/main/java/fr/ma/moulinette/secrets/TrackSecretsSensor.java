/*
 * Copyright 2026 Laurent HADJADJ
 * SPDX-License-Identifier: LGPL-3.0-or-later
 */
package fr.ma.moulinette.secrets;

import fr.ma.moulinette.secrets.engine.CustomRules;
import fr.ma.moulinette.secrets.engine.Detector;
import fr.ma.moulinette.secrets.engine.Finding;
import fr.ma.moulinette.secrets.engine.RuleCatalog;
import fr.ma.moulinette.secrets.engine.SecretRule;
import fr.ma.moulinette.secrets.scan.FileScanner;
import java.io.IOException;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Properties;
import java.util.Set;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.sonar.api.batch.fs.FilePredicate;
import org.sonar.api.batch.fs.InputFile;
import org.sonar.api.batch.rule.ActiveRules;
import org.sonar.api.batch.sensor.Sensor;
import org.sonar.api.batch.sensor.SensorContext;
import org.sonar.api.batch.sensor.SensorDescriptor;
import org.sonar.api.batch.sensor.issue.NewIssue;
import org.sonar.api.batch.sensor.issue.NewIssueLocation;
import org.sonar.api.config.Configuration;
import org.sonar.api.rule.RuleKey;

/**
 * [Description TrackSecretsSensor]
 *
 * Analyse tous les fichiers du projet, quel que soit leur langage, et rapporte les secrets
 * en dur.
* Les valeurs détectées ne sont jamais écrites dans les messages ni dans les journaux.
*/
public final class TrackSecretsSensor implements Sensor {

  private static final Logger LOG = LoggerFactory.getLogger(TrackSecretsSensor.class);

  /** Au-delà, le nom de la clé n'est pas repris dans le message de l'anomalie. */
  private static final int MAX_KEY_LENGTH_IN_MESSAGE = 60;
  private static final Pattern LINE_BREAK = Pattern.compile("\\r?\\n");
  private static final long BYTES_PER_KB = 1024L;

  /** Extensions pour lesquelles les analyseurs de langage fournissent déjà la règle S2068. */
  private static final Set<String> S2068_EXTENSIONS = Set.of(
    "java", "kt", "kts", "cs", "py", "js", "jsx", "mjs", "cjs", "ts", "tsx", "php");

  @Override
  public void describe(SensorDescriptor descriptor) {
    descriptor.name("Track Secrets").createIssuesForRuleRepositories(TrackSecretsRulesDefinition.REPOSITORY_KEY);
  }

  @Override
  public void execute(SensorContext context) {
    Set<String> activeKeys = activeRuleKeys(context.activeRules());
    if (activeKeys.isEmpty()) {
      LOG.debug("Track Secrets: aucune règle active, analyse ignorée.");
      return;
    }
    Configuration config = context.config();
    var entropy = parseDouble(config.get(TrackSecretsProperties.ENTROPY_THRESHOLD).orElse(null),
      RuleCatalog.DEFAULT_ENTROPY_THRESHOLD);

    List<SecretRule> rules = RuleCatalog.all(entropy).stream()
      .filter(rule -> activeKeys.contains(rule.ruleKey()))
      .collect(Collectors.toCollection(ArrayList::new));
    if (activeKeys.contains(CustomRules.RULE_KEY)) {
      rules.addAll(loadCustomRules(context, config));
    }

    List<String> excludedKeys = new ArrayList<>(Detector.DEFAULT_EXCLUDED_KEYS);
    excludedKeys.addAll(lines(config.get(TrackSecretsProperties.EXCLUDE_KEYS).orElse("")));
    List<String> excludedValues = new ArrayList<>(Detector.DEFAULT_EXCLUDED_VALUES);
    excludedValues.addAll(lines(config.get(TrackSecretsProperties.EXCLUDE_VALUES).orElse("")));

    var scanner = new FileScanner(new Detector(rules, excludedKeys, excludedValues));
    boolean skipOverlap = config.getBoolean(TrackSecretsProperties.SKIP_NATIVE_OVERLAP).orElse(Boolean.TRUE);
    long maxChars = config.getInt(TrackSecretsProperties.MAX_FILE_SIZE_KB)
      .orElse(TrackSecretsProperties.DEFAULT_MAX_FILE_SIZE_KB) * BYTES_PER_KB;

    var fs = context.fileSystem();
    FilePredicate predicate = config.getBoolean(TrackSecretsProperties.INCLUDE_TESTS).orElse(Boolean.FALSE)
      ? fs.predicates().all()
      : fs.predicates().hasType(InputFile.Type.MAIN);

    var analyzed = 0;
    for (InputFile file : fs.inputFiles(predicate)) {
      if (context.isCancelled()) {
        break;
      }
      if (analyze(context, scanner, file, maxChars, skipOverlap)) {
        analyzed++;
      }
    }
    LOG.info("Track Secrets: {} fichier(s) analysé(s).", analyzed);
  }

  private static boolean analyze(
    SensorContext context, FileScanner scanner, InputFile file, long maxChars, boolean skipOverlap) {
    String content;
    try {
      content = file.contents();
    } catch (IOException | RuntimeException e) {
      LOG.debug("Track Secrets: lecture impossible de {}", file, e);
      return false;
    }
    if (content.length() > maxChars || content.indexOf('\0') >= 0) {
      // trop volumineux ou binaire
      return false;
    }
    var path = context.fileSystem().baseDir().toURI().relativize(file.uri()).getPath();
    String extension = extension(path);
    var coveredByLanguageAnalyzer = skipOverlap && S2068_EXTENSIONS.contains(extension);
    for (Finding finding : scanner.scan(path, content)) {
      if (!(coveredByLanguageAnalyzer && RuleCatalog.HARDCODED_PASSWORD.equals(finding.ruleKey()))) {
        report(context, file, finding);
      }
    }
    return true;
  }

  private static void report(SensorContext context, InputFile file, Finding finding) {
    NewIssue issue = context.newIssue()
      .forRule(RuleKey.of(TrackSecretsRulesDefinition.REPOSITORY_KEY, finding.ruleKey()));
    NewIssueLocation location = issue.newLocation().on(file).message(message(finding));
    if (finding.line() > 0 && finding.line() <= file.lines()) {
      location.at(file.selectLine(finding.line()));
    }
    issue.at(location).save();
  }

  /** Message de l'anomalie. Contient le nom de la clé mais jamais la valeur détectée. */
  static String message(Finding finding) {
    if (finding.label() != null) {
      return "Supprimez ce secret écrit en dur (règle personnalisée « " + finding.label() + " »).";
    }
    String key = finding.key();
    var text = RuleCatalog.message(finding.ruleKey());
    if (key == null || key.isBlank() || "file".equals(key) || key.length() > MAX_KEY_LENGTH_IN_MESSAGE) {
      return text;
    }
    return text + " (clé : " + key + ")";
  }

  private static Set<String> activeRuleKeys(ActiveRules activeRules) {
    return activeRules.findByRepository(TrackSecretsRulesDefinition.REPOSITORY_KEY).stream()
      .map(r -> r.ruleKey().rule())
      .collect(Collectors.toCollection(HashSet::new));
  }

  private static List<SecretRule> loadCustomRules(SensorContext context, Configuration config) {
    String configured = config.get(TrackSecretsProperties.CUSTOM_RULES_PATH).orElse("").strip();
    if (configured.isEmpty()) {
      return List.of();
    }
    var path = context.fileSystem().baseDir().toPath().resolve(configured).normalize();
    var props = new Properties();
    try (var in = Files.newInputStream(path)) {
      props.load(in);
      List<SecretRule> custom = CustomRules.parse(props);
      if (LOG.isInfoEnabled()) {
        LOG.info("Track Secrets: {} règle(s) personnalisée(s) chargée(s).", custom.size());
      }
      return custom;
    } catch (IOException | IllegalArgumentException e) {
      if (LOG.isWarnEnabled()) {
        LOG.warn("Track Secrets: règles personnalisées ignorées ({}) : {}", configured, e.getMessage());
      }
      return List.of();
    }
  }

  private static String extension(String path) {
    int dot = path.lastIndexOf('.');
    return dot < 0 ? "" : path.substring(dot + 1).toLowerCase(Locale.ROOT);
  }

  private static List<String> lines(String text) {
    return LINE_BREAK.splitAsStream(text).map(String::strip).filter(s -> !s.isEmpty()).toList();
  }

  private static double parseDouble(String value, double fallback) {
    if (value == null || value.isBlank()) {
      return fallback;
    }
    try {
      return Double.parseDouble(value.strip());
    } catch (NumberFormatException ignored) {
      LOG.warn("Track Secrets: seuil d'entropie invalide « {} », {} utilisé.", value, fallback);
      return fallback;
    }
  }
}
