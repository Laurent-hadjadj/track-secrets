/*
 * Copyright 2026 Laurent HADJADJ
 * SPDX-License-Identifier: LGPL-3.0-or-later
 */
package fr.ma.moulinette.secrets.scan;

import static org.assertj.core.api.Assertions.assertThat;

import fr.ma.moulinette.secrets.engine.Detector;
import fr.ma.moulinette.secrets.engine.Finding;
import fr.ma.moulinette.secrets.engine.RuleCatalog;
import java.time.Duration;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;
import org.junit.jupiter.api.Test;

/** Tests de bout en bout : contenu de fichier -> anomalies. Tous les secrets ci-dessous sont fictifs. */
class FileScannerTest {

  private static final FileScanner SCANNER = new FileScanner(
    new Detector(RuleCatalog.all(), Detector.DEFAULT_EXCLUDED_KEYS, Detector.DEFAULT_EXCLUDED_VALUES));

  /** Retourne les anomalies sous la forme {@code règle:ligne}. */
  private static Set<String> scan(String path, String content) {
    return SCANNER.scan(path, content).stream()
      .map(f -> f.ruleKey() + ":" + f.line())
      .collect(Collectors.toSet());
  }

  @Test
  void properties_file() {
    String content = String.join("\n",
      "db.password=Sup3rS3cret!",
      "db.password.ref=${DB_PASSWORD}",
      "label.password=Password",
      "msg.password=Entrez votre mot de passe",
      "# old.password=Anc1enMdp!");
    assertThat(scan("config/app.properties", content))
      .contains("hardcoded-password:1", "hardcoded-password:5")
      .doesNotContain("hardcoded-password:2", "hardcoded-password:3", "hardcoded-password:4");
  }

  @Test
  void yaml_nested_keys_and_kubernetes_env() {
    String content = String.join("\n",
      "spring:",
      "  datasource:",
      "    password: Sup3rS3cret!",
      "    url: jdbc:mysql://db:3306/app",
      "env:",
      "  - name: DB_PASSWORD",
      "    value: hunter22x",
      "  - name: LOG_LEVEL",
      "    value: debug",
      "other: {apiKey: k8Jd92LmQp0xZvB3nTa7}");
    assertThat(scan("deploy/values.yaml", content))
      .contains("hardcoded-password:3", "hardcoded-password:7", "hardcoded-api-key:10")
      .doesNotContain("hardcoded-password:9");
  }

  @Test
  void yaml_variables_and_placeholders_are_ignored() {
    String content = String.join("\n",
      "password: ${PASSWORD}",
      "token: \"{{ .Values.token }}\"",
      "secret: <your secret here>",
      "apiKey: !Ref ApiKeyParam");
    assertThat(scan("a.yml", content)).isEmpty();
  }

  @Test
  void yaml_block_scalar_private_key() {
    String content = String.join("\n",
      "tls:",
      "  key: |",
      "    -----BEGIN RSA PRIVATE KEY-----",
      "    MIIBOgIBAAJBAKj34GkxFhD90vcNLYLInFEX6Ppy1tPf9Cnzj4p4WGeKLs1Pt8Qu");
    assertThat(scan("tls.yml", content)).contains("private-key:3");
  }

  @Test
  void json_with_line_numbers() {
    String content = String.join("\n",
      "{",
      "  // commentaire",
      "  \"name\": \"demo\",",
      "  \"apiKey\": \"k8Jd92LmQp0xZvB3nTa7\",",
      "  \"auths\": { \"registry.example\": { \"auth\": \"dXNlcjpwYXNzd29yZA==\" } }",
      "}");
    assertThat(scan("config.json", content)).contains("hardcoded-api-key:4", "dockercfg-auth:5");
  }

  @Test
  void invalid_json_does_not_fail() {
    assertThat(scan("broken.json", "{\"password\": \"Sup3rS3cret!\", ")).contains("hardcoded-password:1");
  }

  @Test
  void xml_attributes_text_and_name_value() {
    String content = String.join("\n",
      "<config>",
      "  <property name=\"password\" value=\"Sup3rS3cret!\"/>",
      "  <db password=\"Sup3rS3cret!\"/>",
      "  <secret>Zp81QvLm20sk</secret>",
      "</config>");
    assertThat(scan("beans.xml", content))
      .contains("hardcoded-password:2", "hardcoded-password:3", "hardcoded-secret:4");
  }

  @Test
  void xml_with_doctype_and_entities_does_not_fail() {
    String content = "<!DOCTYPE x [<!ENTITY e SYSTEM \"file:///etc/passwd\">]>\n<a><password>Sup3rS3cret!</password></a>";
    assertThat(scan("x.xml", content)).contains("hardcoded-password:2");
  }

  @Test
  void shell_curl_and_assignments() {
    String content = String.join("\n",
      "#!/bin/sh",
      "curl -u admin:Sup3rS3cret! https://example.org/api",
      "export DB_PASSWORD=\"Sup3rS3cret!\"",
      "DB_PASSWORD=$OTHER");
    assertThat(scan("deploy.sh", content)).contains("hardcoded-password:2", "hardcoded-password:3")
      .doesNotContain("hardcoded-password:4");
  }

  @Test
  void dockerfile_env() {
    assertThat(scan("Dockerfile", "FROM alpine\nENV DB_PASSWORD=Sup3rS3cret! LANG=C\nARG API_TOKEN=k8Jd92LmQp0xZvB3nTa7"))
      .contains("hardcoded-password:2", "hardcoded-api-key:3");
  }

  @Test
  void env_and_config_files() {
    assertThat(scan(".env", "export SECRET_KEY=Zp81QvLm20skAbCdEf\nPORT=8080")).contains("hardcoded-api-key:1");
    assertThat(scan("web.config", "<?xml version=\"1.0\"?>\n<a><add key=\"password\" value=\"Sup3rS3cret!\"/></a>"))
      .contains("hardcoded-password:2");
  }

  @Test
  void source_code_in_several_languages() {
    assertThat(scan("A.java", "class A {\n  String password = \"Sup3rS3cret!\";\n  void f() { c.setPassword(\"Sup3rS3cret!\"); }\n}"))
      .contains("hardcoded-password:2", "hardcoded-password:3");
    assertThat(scan("main.go", "const apiKey = \"k8Jd92LmQp0xZvB3nTa7\"")).contains("hardcoded-api-key:1");
    assertThat(scan("a.php", "<?php\ndefine('DB_PASSWORD', 'Sup3rS3cret!');\n$cfg['password'] = 'Sup3rS3cret!';"))
      .contains("hardcoded-password:2", "hardcoded-password:3");
    assertThat(scan("a.py", "conn = connect(password=\"Sup3rS3cret!\")\nos.environ.get(\"DB_PASSWORD\", \"Sup3rS3cret!\")"))
      .contains("hardcoded-password:1", "hardcoded-password:2");
    assertThat(scan("a.ts", "const config = { password: 'Sup3rS3cret!' };")).contains("hardcoded-password:1");
    assertThat(scan("main.tf", "resource \"x\" \"y\" {\n  password = \"Sup3rS3cret!\"\n}")).contains("hardcoded-password:2");
    assertThat(scan("a.java", "String password = System.getenv(\"DB_PASSWORD\");")).doesNotContain("hardcoded-password:1");
    assertThat(scan("a.java", "String password = \"\";")).doesNotContain("hardcoded-password:1");
  }

  @Test
  void known_formats_anywhere_in_code() {
    String stripe = "sk_" + "live_" + "0123456789abcdefghijklmn";
    String slack = "https://hooks." + "slack.com/services/T00000000/B00000000/abcdEFGHijklMNOPqrstUVWX";
    String github = "gh" + "p_" + "0123456789abcdefghijklmnopqrstuvwxyz";
    assertThat(scan("a.js", "send(\"" + stripe + "\");")).contains("service-token:1");
    assertThat(scan("a.js", "post(\"" + slack + "\");")).contains("hardcoded-webhook:1");
    assertThat(scan("a.js", "const t = '" + github + "';")).contains("github-token:1");
    assertThat(scan("a.java", "String id = \"AKIAIOSFODNN7EXAMPLE\";")).contains("aws-access-key-id:1");
  }

  @Test
  void github_installation_token_is_recognized() {
    // jeton d'installation de GitHub App : ghs_<identifiant>_<JWT> (valeur fictive, assemblée pour ne pas alerter)
    String token = "gh" + "s_15368_" + "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9" + "." + "eyJhaWQiOjE1MzY4LCJhdWQiOiIvdHdpcnAi"
      + "." + "abcdefghijklmnopqrstuvwxyzABCDEFGH0123";
    assertThat(scan("a.js", "const t = '" + token + "';")).contains("github-token:1");
  }

  @Test
  void uri_with_credentials() {
    assertThat(scan("a.java", "String url = \"jdbc:mysql://app:Sup3rS3cret!@db:3306/x\";")).contains("hardcoded-password:1");
    assertThat(scan("notes.txt", "see https://user:Sup3rS3cret!@host.example/path")).contains("hardcoded-password:1");
  }

  @Test
  void uri_with_credentials_for_any_scheme() {
    assertThat(scan("main.go", "const u = \"postgres://app:Sup3rS3cret!@db:5432/x\"")).contains("hardcoded-password:1");
    assertThat(scan("a.yml", "broker: amqp://guest:Sup3rS3cret!@mq:5672/")).contains("hardcoded-password:1");
    assertThat(scan("a.properties", "cache.url=redis://:Sup3rS3cret!@cache:6379")).contains("hardcoded-password:1");
    assertThat(scan("a.properties", "db.url=mongodb://app@db:27017/x")).doesNotContain("hardcoded-password:1");
  }

  @Test
  void private_key_header_in_any_file() {
    assertThat(scan("keys/id_rsa", "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXk=")).contains("private-key:1");
    assertThat(scan("cert.pem", "-----BEGIN CERTIFICATE-----\nMIIB")).doesNotContain("private-key:1");
  }

  @Test
  void npmrc_pypirc_htpasswd_pip() {
    assertThat(scan(".npmrc", "//registry.npmjs.org/:_authToken=abcDEF123456xyz")).contains("npmrc-auth-token:1");
    assertThat(scan(".pypirc", "[pypi]\npassword = pypi-AgEIcHlwaS5vcmcA")).contains("pypirc-password:2");
    assertThat(scan(".htpasswd", "admin:$apr1$9Qh3abcd$XyZ")).contains("htpasswd-hash:1");
    assertThat(scan("pip.conf", "[global]\nindex-url = https://u:Sup3rS3cret!@pypi.example/simple"))
      .contains("pip-password:2");
  }

  @Test
  void high_entropy_string() {
    assertThat(scan("a.java", "String s = \"x9Fq2LmZ7vB1nTa8KcR4wYd6Ee5Hj3\";")).contains("high-entropy-string:1");
    assertThat(scan("a.java", "String s = \"ThisIsAVeryLongDescriptiveIdentifierName\";")).doesNotContain("high-entropy-string:1");
  }

  @Test
  void python_dangerous_function_and_html_comment() {
    assertThat(scan("a.py", "import os\nos.system(cmd)")).contains("dangerous-function:2");
    assertThat(scan("a.html", "<p>x</p>\n<!-- admin / admin -->")).contains("comment-leak:2");
  }

  @Test
  void sensitive_file_by_name() {
    assertThat(scan("conf/server.jks", "x")).contains("sensitive-file:0");
    assertThat(scan("src/Main.java", "class A {}")).doesNotContain("sensitive-file:0");
  }

  @Test
  void a_rule_is_reported_once_per_line() {
    List<Finding> findings = SCANNER.scan("A.java", "String password = \"Sup3rS3cret!\"; String other = password == \"Sup3rS3cret!\";");
    assertThat(findings.stream().filter(f -> "hardcoded-password".equals(f.ruleKey()))).hasSize(1);
  }

  @Test
  void regression_false_positives_seen_on_real_projects() {
    // identifiant en minuscules séparé par des tirets : pas une clé d'API
    assertThat(scan("R.java", "public static final String REPOSITORY_KEY = \"track-logger-method\";"))
      .doesNotContain("hardcoded-api-key:1");
    // chaînes de configuration d'outil : pas une chaîne à forte entropie
    assertThat(scan("settings.json", "{\"allow\": [\"Bash(mvn -o test 2>&1 | grep Tests)\", \"Read(//c/environnement/a1b2/**)\"]}"))
      .isEmpty();
    // une valeur reconnue par une règle précise n'est pas aussi signalée par l'entropie
    assertThat(SCANNER.scan(".htpasswd", "admin:$apr1$9Qh3abcdXyZ0123456789abcdefghijk").stream()
      .filter(f -> f.line() > 0).map(Finding::ruleKey))
      .containsExactly("htpasswd-hash");
  }

  @Test
  void very_long_string_literals_do_not_overflow_the_stack() {
    String longLiteral = "a".repeat(9_000);
    assertThat(scan("A.java", "String s = \"" + longLiteral + "\"; String apiKey = \"k8Jd92LmQp0xZvB3nTa7\";"))
      .contains("hardcoded-api-key:1");
    // 1 500 séquences d'échappement dans un même littéral
    String escapes = "a\\\"b".repeat(1_500);
    assertThat(scan("B.java", "String s = \"" + escapes + "\"; String apiKey = \"k8Jd92LmQp0xZvB3nTa7\";"))
      .contains("hardcoded-api-key:1");
  }

  @Test
  void unclosed_quotes_in_shell_and_dockerfile_are_tolerated() {
    assertThat(scan("x.sh", "export A=\"unterminated\nDB_PASSWORD=Sup3rS3cret!")).contains("hardcoded-password:2");
    assertThat(scan("Dockerfile", "ENV K=\"abc\nENV DB_PASSWORD=Sup3rS3cret!")).contains("hardcoded-password:2");
  }

  @Test
  void json_with_a_byte_order_mark_and_xml_with_name_value_still_work() {
    assertThat(scan("c.json", "﻿{\"password\": \"Sup3rS3cret!\"}")).contains("hardcoded-password:1");
    assertThat(scan("c.xml", "<c><add key=\"password\" value=\"Sup3rS3cret!\"/></c>")).contains("hardcoded-password:1");
  }

  @Test
  void code_literals_with_apostrophes_escapes_and_several_per_line() {
    // une élision dans un commentaire (« don't ») ne doit pas masquer le littéral qui suit
    assertThat(scan("a.go", "// don't leak: password = \"Sup3rS3cret!\" isn't ok")).contains("hardcoded-password:1");
    // un guillemet échappé dans un littéral précédent
    assertThat(scan("b.go", "var a = \"x\\\"y\"; var password = \"Sup3rS3cret!\"")).contains("hardcoded-password:1");
    // clé entre guillemets dans une carte, plusieurs paires sur la même ligne
    assertThat(scan("c.js", "const c = {\"other\": \"x\", \"apiKey\": \"k8Jd92LmQp0xZvB3nTa7\"}")).contains("hardcoded-api-key:1");
    // accès par crochets (PHP) et littéral non fermé qui ne doit rien casser
    assertThat(scan("d.php", "$cfg['password'] = 'Sup3rS3cret!';")).contains("hardcoded-password:1");
    assertThat(scan("e.java", "String s = \"non fermé")).isNotNull();
  }

  @Test
  void uri_scheme_validation() {
    assertThat(scan("a.properties", "u=jdbc:mysql://app:Sup3rS3cret!@db/x")).contains("hardcoded-password:1");
    assertThat(scan("b.properties", "u=svn+ssh://app:Sup3rS3cret!@host/x")).contains("hardcoded-password:1");
    assertThat(scan("c.properties", "u=1http://app:Sup3rS3cret!@host/x")).doesNotContain("hardcoded-password:1");
    assertThat(scan("d.properties", "u=http:://app:Sup3rS3cret!@host/x")).doesNotContain("hardcoded-password:1");
  }

  @Test
  void unknown_file_types_are_not_parsed() {
    assertThat(scan("image.png", "password=Sup3rS3cret!")).isEmpty();
  }

  @Test
  void findings_never_carry_the_value() {
    SCANNER.scan("a.properties", "db.password=Sup3rS3cret!").forEach(f -> assertThat(f.toString()).doesNotContain("Sup3rS3cret"));
  }

  @Test
  void pathological_lines_are_scanned_in_linear_time() {
    // Ces lignes mettaient plusieurs secondes avec une expression régulière à retour arrière (ReDoS)
    var spaces = "a" + " ".repeat(200_000);
    var tabs = "a" + "	".repeat(200_000);
    var openQuote = "\"" + "a b ".repeat(50_000);
    for (String content : List.of(spaces, tabs, openQuote)) {
      org.junit.jupiter.api.Assertions.assertTimeout(Duration.ofSeconds(2), () -> scan("a.yaml", content));
      org.junit.jupiter.api.Assertions.assertTimeout(Duration.ofSeconds(2), () -> scan("a.properties", content));
      org.junit.jupiter.api.Assertions.assertTimeout(Duration.ofSeconds(2), () -> scan("Dockerfile", "ENV " + content));
    }
  }

  @Test
  void yaml_mapping_edge_cases() {
    assertThat(scan("a.yaml", "\"db_password\": Sup3rS3cret!x9")).isNotEmpty();
    assertThat(scan("a.yaml", "password:Sup3rS3cret!x9")).isEmpty();
    assertThat(scan("a.yaml", "password : Sup3rS3cret!x9")).isNotEmpty();
    assertThat(scan("a.yaml", "- password: Sup3rS3cret!x9")).isNotEmpty();
  }
}
