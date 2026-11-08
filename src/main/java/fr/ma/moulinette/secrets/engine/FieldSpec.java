/*
 * Copyright 2026 Laurent HADJADJ
 * Copyright Skyscanner Ltd (parties dérivées)
 * SPDX-License-Identifier: LGPL-3.0-or-later AND Apache-2.0
 *
 * Dérivé de Whispers (Skyscanner, licence Apache-2.0, texte dans
 * LICENSES/Apache-2.0.txt). Modifié : portage en Java. Voir NOTICE.
 */
package fr.ma.moulinette.secrets.engine;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.regex.Pattern;

/**
 * [Description FieldSpec]
 *
 * Contraintes portant sur la clé ou sur la valeur d'un couple (équivalent d'un bloc
 * {@code key:} ou {@code value:} d'une règle Whispers). Toutes les contraintes
 * renseignées doivent être satisfaites.
 */
public final class FieldSpec {

  /** Espacements ASCII admis : tabulation, saut de ligne, retour chariot, tabulation verticale, saut de page. */
  private static final String WHITESPACE = "\t\n\r\013\f";

  private Pattern regex;
  private int minLen = -1;
  private Boolean base64;
  private boolean ascii;
  private Boolean uri;
  private boolean luhn;
  private double minEntropy = -1;

  private FieldSpec() {
  }

  public static FieldSpec create() {
    return new FieldSpec();
  }

  /** Expression régulière ancrée en début de texte (comme {@code re.match}), sensible à la casse. */
  public FieldSpec regex(String expression) {
    this.regex = Pattern.compile(expression);
    return this;
  }

  /** Comme {@link #regex(String)}, sans tenir compte de la casse. */
  public FieldSpec regexIgnoreCase(String expression) {
    this.regex = Pattern.compile(expression, Pattern.CASE_INSENSITIVE);
    return this;
  }

  public FieldSpec minLen(int length) {
    this.minLen = length;
    return this;
  }

  /** La valeur doit (ou ne doit pas) ressembler à du base64. */
  public FieldSpec expectBase64(boolean expected) {
    this.base64 = expected;
    return this;
  }

  /** Le contenu (décodé si {@link #expectBase64(boolean)} est vrai) ne contient que de l'ASCII imprimable. */
  public FieldSpec onlyAscii() {
    this.ascii = true;
    return this;
  }

  /** La valeur doit (ou ne doit pas) ressembler à une URI. */
  public FieldSpec expectUri(boolean expected) {
    this.uri = expected;
    return this;
  }

  /** La valeur doit être un numéro valide selon l'algorithme de Luhn. */
  public FieldSpec requireLuhn() {
    this.luhn = true;
    return this;
  }

  /** Entropie de Shannon minimale (bits par caractère). */
  public FieldSpec minEntropy(double threshold) {
    this.minEntropy = threshold;
    return this;
  }

  boolean matches(String text) {
    return text != null && matchesLengthAndRegex(text) && matchesEncoding(text) && matchesValue(text);
  }

  private boolean matchesLengthAndRegex(String text) {
    // évaluation paresseuse : l'expression régulière n'est testée que si la longueur minimale est atteinte
    return (minLen < 0 || text.length() >= minLen) && (regex == null || regex.matcher(text).lookingAt());
  }

  /** Contraintes sur la forme de la valeur : base64, ASCII, URI. */
  private boolean matchesEncoding(String text) {
    return !differs(base64, Patterns.BASE64.matcher(text).matches())
      && (!ascii || isPrintableAscii(decodeIfBase64(text)))
      && !differs(uri, Patterns.looksLikeUri(decodeIfBase64(text)));
  }

  /** Contraintes sur le contenu de la valeur : numéro de Luhn, entropie. */
  private boolean matchesValue(String text) {
    return (!luhn || Strings.luhn(text)) && (minEntropy < 0 || Strings.entropy(text) >= minEntropy);
  }

  /** Vrai si une contrainte tri-état est définie et que la valeur observée la contredit. */
  private static boolean differs(Boolean expected, boolean actual) {
    return expected != null && expected != actual;
  }

  private String decodeIfBase64(String text) {
    if (!Boolean.TRUE.equals(base64)) {
      return text;
    }
    // Patterns.BASE64 garantit un alphabet et un bourrage valides : le décodage ne peut pas échouer
    if (!Patterns.BASE64.matcher(text).matches()) {
      return "\u0000";
    }
    return new String(Base64.getDecoder().decode(text), StandardCharsets.ISO_8859_1);
  }

  private static boolean isPrintableAscii(String data) {
    for (var i = 0; i < data.length(); i++) {
      var c = data.charAt(i);
      boolean printable = (c >= 0x20 && c < 0x7F) || WHITESPACE.indexOf(c) >= 0;
      if (!printable) {
        return false;
      }
    }
    return true;
  }
}
