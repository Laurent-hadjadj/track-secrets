/*
 * Copyright 2026 Laurent HADJADJ
 * Copyright Skyscanner Ltd (parties dérivées)
 * SPDX-License-Identifier: LGPL-3.0-or-later AND Apache-2.0
 *
 * Dérivé de Whispers (Skyscanner, licence Apache-2.0, texte dans
 * LICENSES/Apache-2.0.txt). Modifié : portage en Java. Voir NOTICE.
 */
package fr.ma.moulinette.secrets.extract;

import fr.ma.moulinette.secrets.engine.Patterns;
import fr.ma.moulinette.secrets.engine.Strings;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.function.Predicate;

/**
 * [Description ExtractorRegistry]
 *
 * Choisit l'extracteur adapté à un fichier d'après son nom (et au besoin son contenu).
 */
public final class ExtractorRegistry {

  private static final Extractor YAML = new YamlExtractor();
  private static final Extractor JSON = new JsonExtractor();
  private static final Extractor XML = new XmlExtractor();
  private static final Extractor SHELL = withUris(new ShellExtractor());
  private static final Extractor CODE = new CodeExtractor(false);
  private static final Extractor PYTHON = new CodeExtractor(true);
  private static final Extractor PROPERTIES = withUris(SimpleExtractors.PROPERTIES);
  private static final Extractor CONFIG = withUris(SimpleExtractors.CONFIG);
  private static final Extractor DOCKERFILE = withUris(SimpleExtractors.DOCKERFILE);
  /** Fichiers reconnus par leur nom entier ou par un préfixe, avant même de regarder l'extension. */
  private static final List<NameRule> NAME_RULES = List.of(
    new NameRule(ExtractorRegistry::isDockerfileName, DOCKERFILE),
    new NameRule(ExtractorRegistry::isNpmrcName, SimpleExtractors.NPMRC),
    new NameRule(ExtractorRegistry::isPypircName, SimpleExtractors.PYPIRC),
    new NameRule(ExtractorRegistry::isPipName, SimpleExtractors.PIP),
    new NameRule(ExtractorRegistry::isHtpasswdName, SimpleExtractors.HTPASSWD));

  /** Extensions de fichiers de configuration, dont certains contiennent en réalité du XML (web.config). */
  private static final Set<String> CONFIG_EXT = Set.of(
    "conf", "cfg", "config", "ini", "env", "credentials", "s3cfg", "toml");

  private static final Map<String, Extractor> BY_EXTENSION = byExtension();

  private ExtractorRegistry() {
  }

  private static boolean isNpmrcName(String name) {
    return name.startsWith(".npmrc") || name.endsWith(".npmrc");
  }

  private static boolean isPypircName(String name) {
    return name.startsWith(".pypirc") || name.endsWith(".pypirc");
  }

  private static boolean isPipName(String name) {
    return "pip.conf".equals(name) || "pip.ini".equals(name);
  }

  private static boolean isHtpasswdName(String name) {
    return name.startsWith(".htpasswd") || "htpasswd".equals(name);
  }

  private static boolean isDockerfileName(String name) {
    return name.startsWith("dockerfile") || name.endsWith(".dockerfile") || name.endsWith(".containerfile");
  }

  /** Ajoute la décomposition des URI (mot de passe, paramètres) aux extracteurs qui ne la font pas eux-mêmes. */
  private static Extractor withUris(Extractor delegate) {
    return (content, out) -> delegate.extract(content, pair -> {
      out.accept(pair);
      String value = pair.value() == null ? "" : Strings.strip(pair.value());
      if (Patterns.looksLikeUri(value)) {
        UriPairs.extract(value, pair.line(), pair.breadcrumbs(), out);
      }
    });
  }

  private static Map<String, Extractor> byExtension() {
    Map<String, Extractor> map = new HashMap<>();
    register(map, YAML, "yml", "yaml");
    register(map, JSON, "json", "jsonc");
    register(map, XML, "xml", "csproj", "vbproj", "props", "targets", "wsdl", "xhtml", "pom");
    register(map, SimpleExtractors.HTML, "html", "htm");
    register(map, PROPERTIES, "properties");
    register(map, SimpleExtractors.DOCKERCFG, "dockercfg");
    register(map, SHELL, "sh", "bash", "zsh", "ksh");
    register(map, SimpleExtractors.PLAINTEXT, "txt", "md", "rst", "adoc");
    register(map, PYTHON, "py", "py3", "pyw");
    register(map, CODE, "java", "kt", "kts", "groovy", "gradle", "scala", "js", "jsx", "mjs", "cjs", "ts", "tsx",
      "vue", "svelte", "cs", "go", "php", "rb", "swift", "rs", "dart", "lua", "pl", "ps1", "tf", "hcl", "tfvars",
      "sql", "c", "cpp", "h");
    return Map.copyOf(map);
  }

  private static void register(Map<String, Extractor> map, Extractor extractor, String... extensions) {
    for (String extension : extensions) {
      map.put(extension, extractor);
    }
  }

  /**
   * @param path    chemin relatif du fichier
   * @param content contenu (sert à reconnaître un fichier de configuration en réalité XML)
   * @return l'extracteur, ou vide si le type de fichier n'est pas pris en charge
   */
  public static Optional<Extractor> forFile(String path, String content) {
    String name = baseName(path);
    String extension = extension(name);
    return byName(name)
      .or(() -> Optional.ofNullable(BY_EXTENSION.get(extension)))
      .or(() -> byConfiguration(name, extension, content));
  }

  private static Optional<Extractor> byName(String name) {
    return NAME_RULES.stream()
      .filter(rule -> rule.matches().test(name))
      .map(NameRule::extractor)
      .findFirst();
  }

  /** Fichier de configuration (« .env », extension connue) ; certains contiennent en réalité du XML. */
  private static Optional<Extractor> byConfiguration(String name, String extension, String content) {
    if (!name.startsWith(".env") && !CONFIG_EXT.contains(extension)) {
      return Optional.empty();
    }
    return Optional.of(isXml(content) ? XML : CONFIG);
  }

  /** Nom du fichier en minuscules, sans le suffixe de gabarit ({@code .dist}, {@code .template}, {@code .tpl}). */
  private static String baseName(String path) {
    String name = path.substring(Math.max(path.lastIndexOf('/'), path.lastIndexOf('\\')) + 1).toLowerCase(Locale.ROOT);
    boolean template = name.endsWith(".dist") || name.endsWith(".template") || name.endsWith(".tpl");
    return template ? name.substring(0, name.lastIndexOf('.')) : name;
  }

  private static String extension(String name) {
    int dot = name.lastIndexOf('.');
    return dot < 0 ? "" : name.substring(dot + 1);
  }

  private static boolean isXml(String content) {
    return content.stripLeading().startsWith("<");
  }

  /** Règle de choix fondée sur le nom du fichier, en minuscules. */
  private record NameRule(Predicate<String> matches, Extractor extractor) {
  }
}
