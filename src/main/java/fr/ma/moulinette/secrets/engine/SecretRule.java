/*
 * Copyright 2026 Laurent HADJADJ
 * Copyright Skyscanner Ltd (parties dérivées)
 * SPDX-License-Identifier: LGPL-3.0-or-later AND Apache-2.0
 *
 * Dérivé de Whispers (Skyscanner, licence Apache-2.0, texte dans
 * LICENSES/Apache-2.0.txt). Modifié : portage en Java. Voir NOTICE.
 */
package fr.ma.moulinette.secrets.engine;

/**
 * [Description SecretRule]
 *
 * Règle déclarative de détection. Plusieurs {@code SecretRule} peuvent partager la même
 * clé de règle SonarQube (ex. les trois types de webhooks).
 */
public final class SecretRule {

  private final String ruleKey;
  private final FieldSpec keySpec;
  private final FieldSpec valueSpec;
  private final double similar;
  private final boolean rawLine;
  private final String label;

  private SecretRule(Builder b) {
    this.label = b.label;
    this.ruleKey = b.ruleKey;
    this.keySpec = b.keySpec;
    this.valueSpec = b.valueSpec;
    this.similar = b.similar;
    this.rawLine = b.rawLine;
  }

  public static Builder builder(String ruleKey) {
    return new Builder(ruleKey);
  }

  public String ruleKey() {
    return ruleKey;
  }

  /** Nom de la règle personnalisée, ou {@code null} pour une règle intégrée. */
  public String label() {
    return label;
  }

  /** Vrai si la règle s'applique aussi à chaque ligne brute du fichier (ex. en-tête de clé privée). */
  public boolean isRawLine() {
    return rawLine;
  }

  /** Applique la règle à un couple clé/valeur normalisé. */
  boolean matches(String key, String value) {
    if (similar >= 0 && Strings.similarity(key, value) >= similar) {
      // la valeur ressemble trop à la clé : espace réservé
      return false;
    }
    if (keySpec != null && !keySpec.matches(key)) {
      return false;
    }
    return valueSpec == null || valueSpec.matches(value);
  }

  /** Applique la règle (valeur seule) à une ligne brute. */
  boolean matchesRawLine(String line) {
    return rawLine && valueSpec != null && valueSpec.matches(line);
  }

  public static final class Builder {
    private final String ruleKey;
    private FieldSpec keySpec;
    private FieldSpec valueSpec;
    private double similar = -1;
    private boolean rawLine;
    private String label;

    private Builder(String ruleKey) {
      this.ruleKey = ruleKey;
    }

    /** Nom affiché dans le message d'une règle personnalisée. */
    public Builder label(String name) {
      this.label = name;
      return this;
    }

    public Builder key(FieldSpec spec) {
      this.keySpec = spec;
      return this;
    }

    public Builder value(FieldSpec spec) {
      this.valueSpec = spec;
      return this;
    }

    /** Ignore le couple si la similarité clé/valeur atteint ce seuil. */
    public Builder similar(double threshold) {
      this.similar = threshold;
      return this;
    }

    public Builder rawLine() {
      this.rawLine = true;
      return this;
    }

    public SecretRule build() {
      return new SecretRule(this);
    }
  }
}
