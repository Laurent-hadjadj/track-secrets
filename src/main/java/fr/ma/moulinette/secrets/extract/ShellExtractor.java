/*
 * Copyright 2026 Laurent HADJADJ
 * Copyright Skyscanner Ltd (parties dérivées)
 * SPDX-License-Identifier: LGPL-3.0-or-later AND Apache-2.0
 *
 * Dérivé de Whispers (Skyscanner, licence Apache-2.0, texte dans
 * LICENSES/Apache-2.0.txt). Modifié : portage en Java. Voir NOTICE.
 */
package fr.ma.moulinette.secrets.extract;

import fr.ma.moulinette.secrets.engine.Pair;
import fr.ma.moulinette.secrets.engine.Strings;
import java.util.List;
import java.util.function.Consumer;
import java.util.regex.Pattern;

/**
 * [Description ShellExtractor]
 *
 * Scripts shell : affectations {@code KEY=valeur} et identifiants passés à {@code curl}.
 */
final class ShellExtractor implements Extractor {

  private static final Pattern ASSIGNMENT_KEY = Pattern.compile("^[A-Za-z_][\\w.\\-]*$");
  private static final Pattern COMMENT_MARKER = Pattern.compile("^#+\\s*");
  private static final List<String> CURL_COMBINED = List.of("-u", "--user", "-U", "--proxy-user", "-E", "--cert");
  private static final List<String> CURL_SINGLE = List.of("--tlspassword", "--proxy-tlspassword");

  @Override
  public void extract(String content, Consumer<Pair> out) {
    String[] lines = Lines.of(content);
    var command = new StringBuilder();
    var startLine = 0;
    for (var i = 0; i < lines.length; i++) {
      String line = lines[i].strip();
      if (command.isEmpty()) {
        startLine = i + 1;
      }
      boolean commented = line.startsWith("#");
      // un secret commenté reste une fuite
      if (commented) {
        line = COMMENT_MARKER.matcher(line).replaceFirst("").replace("'", "\\'").replace("\"", "\\\"");
      }
      // commande continuée sur la ligne suivante
      if (!commented && line.endsWith("\\")) {
        command.append(line, 0, line.length() - 1).append(' ');
      } else {
        command.append(line);
        handle(command.toString(), startLine, out);
        command.setLength(0);
      }
    }
  }

  private static void handle(String commandLine, int line, Consumer<Pair> out) {
    List<String> cmd = ShellWords.split(commandLine);
    if (cmd.isEmpty()) {
      return;
    }
    if ("curl".equalsIgnoreCase(cmd.get(0))) {
      curl(cmd, line, out);
    }
    for (String item : cmd) {
      int eq = item.indexOf('=');
      if (eq > 0 && ASSIGNMENT_KEY.matcher(item.substring(0, eq)).matches()) {
        out.accept(Pair.of(item.substring(0, eq), item.substring(eq + 1), line));
      }
    }
  }

  private static void curl(List<String> cmd, int line, Consumer<Pair> out) {
    for (String indicator : CURL_COMBINED) {
      int idx = cmd.indexOf(indicator);
      if (idx >= 0 && idx + 1 < cmd.size()) {
        var credentials = Strings.strip(cmd.get(idx + 1));
        int colon = credentials.indexOf(':');
        if (colon >= 0) {
          out.accept(Pair.of("cURL_Password", credentials.substring(colon + 1), line));
        }
      }
    }
    for (String indicator : CURL_SINGLE) {
      int idx = cmd.indexOf(indicator);
      if (idx >= 0 && idx + 1 < cmd.size()) {
        out.accept(Pair.of("cURL_Password", Strings.strip(cmd.get(idx + 1)), line));
      }
    }
  }
}
