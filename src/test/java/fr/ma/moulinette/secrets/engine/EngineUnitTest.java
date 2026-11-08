/*
 * Copyright 2026 Laurent HADJADJ
 * SPDX-License-Identifier: LGPL-3.0-or-later
 */
package fr.ma.moulinette.secrets.engine;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.io.StringReader;
import java.util.List;
import java.util.Properties;
import org.junit.jupiter.api.Test;

/**
 * [Description EngineUnitTest]
 */
class EngineUnitTest {

  private static final Detector DETECTOR = new Detector(RuleCatalog.all(),
    Detector.DEFAULT_EXCLUDED_KEYS, Detector.DEFAULT_EXCLUDED_VALUES);

  @Test
  void strip_and_simple() {
    assertThat(Strings.strip("  'abc' \n")).isEqualTo("abc");
    assertThat(Strings.strip(null)).isEmpty();
    assertThat(Strings.simple("My-Key.Name\\")).isEqualTo("my_key_name");
  }

  @Test
  void similarity_matches_levenshtein_ratio() {
    assertThat(Strings.similarity("password", "password")).isEqualTo(1.0);
    assertThat(Strings.similarity("abc", "xyz")).isZero();
    assertThat(Strings.similarity("api_key", "apikey")).isEqualTo(1.0);
    // ratio("abcd", "abxd") = 2 * 3 / 8
    assertThat(Strings.similarity("abcd", "abxd")).isEqualTo(0.75);
  }

  @Test
  void luhn_and_entropy_and_function() {
    assertThat(Strings.luhn("4111111111111111")).isTrue();
    assertThat(Strings.luhn("4111111111111112")).isFalse();
    assertThat(Strings.luhn("")).isFalse();
    assertThat(Strings.entropy("aaaa")).isZero();
    assertThat(Strings.entropy("abcd")).isEqualTo(2.0);
    assertThat(Strings.isFunction("f(a(b))")).isTrue();
    assertThat(Strings.isFunction("f(a")).isFalse();
    assertThat(Strings.isQuoted("'x'")).isTrue();
  }

  @Test
  void static_value_filter() {
    assertThat(DETECTOR.isStatic("password", "hunter22x")).isTrue();
    assertThat(DETECTOR.isStatic("password", "$PASSWORD")).isFalse();
    assertThat(DETECTOR.isStatic("password", "${PASSWORD}")).isFalse();
    assertThat(DETECTOR.isStatic("password", "%PASSWORD%")).isFalse();
    assertThat(DETECTOR.isStatic("password", "{{ pwd }}")).isFalse();
    assertThat(DETECTOR.isStatic("password", "<password>")).isFalse();
    assertThat(DETECTOR.isStatic("password", "null")).isFalse();
    assertThat(DETECTOR.isStatic("password", "/etc/passwd")).isFalse();
    assertThat(DETECTOR.isStatic("password", "C:\\secrets\\pwd")).isFalse();
    assertThat(DETECTOR.isStatic("password", "true")).isFalse();
    assertThat(DETECTOR.isStatic("password", "DB_PASSWORD")).isFalse();
    assertThat(DETECTOR.isStatic("publicKey", "hunter22x")).isFalse();
    assertThat(DETECTOR.isStatic("x", "data:image/png;base64,AAAA")).isFalse();
  }

  @Test
  void aws_and_card_rules() {
    assertThat(keys("id", "AKIAIOSFODNN7EXAMPLE")).contains("aws-access-key-id");
    assertThat(keys("aws_secret", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY")).contains("aws-secret-access-key");
    assertThat(keys("aws_name", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY")).doesNotContain("aws-secret-access-key");
    assertThat(keys("card", "4111111111111111")).contains("credit-card-number");
    assertThat(keys("card", "4111111111111112")).doesNotContain("credit-card-number");
  }

  @Test
  void placeholder_similar_to_key_is_ignored() {
    assertThat(keys("apiKey", "apikey_placeholder_value")).isEmpty();
  }

  @Test
  void custom_rules_are_parsed() throws Exception {
    Properties p = new Properties();
    p.load(new StringReader("rule.mon-jeton.value=^MJ[A-Z0-9]{10}$\nrule.mon-jeton.minlen=12\nrule.autre.key=^internal_token$"));
    List<SecretRule> rules = CustomRules.parse(p);
    assertThat(rules).hasSize(2).allSatisfy(r -> assertThat(r.ruleKey()).isEqualTo("custom-secret"));
    Detector d = new Detector(rules, List.of(), List.of());
    assertThat(d.check(Pair.of("x", "MJABCDEFGH12", 3))).singleElement().satisfies(f -> {
      assertThat(f.label()).isEqualTo("mon-jeton");
      assertThat(f.line()).isEqualTo(3);
    });
    assertThat(d.check(Pair.of("x", "MJABCDEF", 3))).isEmpty();
  }

  @Test
  void invalid_custom_rules_are_rejected() {
    Properties bad = new Properties();
    bad.setProperty("rule.a.value", "([");
    assertThatThrownBy(() -> CustomRules.parse(bad)).isInstanceOf(IllegalArgumentException.class);
    Properties empty = new Properties();
    empty.setProperty("rule.b.minlen", "3");
    assertThatThrownBy(() -> CustomRules.parse(empty)).hasMessageContaining("'b'");
  }

  @Test
  void catalog_is_consistent() {
    assertThat(RuleCatalog.all().stream().map(SecretRule::ruleKey).distinct())
      .allSatisfy(k -> assertThat(RuleCatalog.ruleKeys()).contains(k));
    assertThat(RuleCatalog.defaultActiveRuleKeys()).doesNotContain("aws-access-key-id", "private-key", "github-token");
    assertThat(RuleCatalog.ruleKeys()).allSatisfy(k -> assertThat(RuleCatalog.message(k)).isNotBlank());
  }

  private static List<String> keys(String key, String value) {
    return DETECTOR.check(Pair.of(key, value, 1)).stream().map(Finding::ruleKey).toList();
  }

  @Test
  void paths_are_recognised_without_regex() {
    assertThat(Patterns.isPath("/etc/passwd")).isTrue();
    assertThat(Patterns.isPath("../conf/app")).isTrue();
    assertThat(Patterns.isPath("C:\\Users\\me")).isTrue();
    assertThat(Patterns.isPath("file:/tmp/x")).isTrue();
    assertThat(Patterns.isPath("Sup3rS3cret!")).isFalse();
    assertThat(Patterns.isPath("")).isFalse();
  }
}
