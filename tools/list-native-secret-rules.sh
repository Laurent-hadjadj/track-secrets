#!/usr/bin/env bash
# Copyright 2026 Laurent HADJADJ
# SPDX-License-Identifier: LGPL-3.0-or-later
# Liste les familles de secrets détectées par le moteur natif sonar-text d'un serveur
# SonarQube, puis les règles de Track Secrets, pour contrôler la couverture après
# une montée de version.
#
# Usage : tools/list-native-secret-rules.sh <répertoire lib/extensions de SonarQube>
set -euo pipefail

EXT_DIR="${1:?Usage: $0 <répertoire lib/extensions de SonarQube>}"
JAR="$(ls "$EXT_DIR"/sonar-text-plugin-*.jar 2>/dev/null | head -1 || true)"
if [ -z "$JAR" ]; then
  echo "sonar-text-plugin introuvable dans $EXT_DIR" >&2
  exit 1
fi

HERE="$(cd "$(dirname "$0")/.." && pwd)"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

echo "== Moteur natif : $(basename "$JAR")"
unzip -q -o "$JAR" 'org/sonar/l10n/secrets/rules/secrets/*.json' -d "$TMP"
grep -h -o '"title": *"[^"]*"' "$TMP"/org/sonar/l10n/secrets/rules/secrets/*.json \
  | sed -e 's/"title": *"//' -e 's/"$//' | sort -u | sed 's/^/  - /'

echo
echo "== Règles de Track Secrets"
for f in "$HERE"/src/main/resources/org/sonar/l10n/trksecrets/rules/trksecrets/*.json; do
  key="$(basename "$f" .json)"
  title="$(grep -h -o '"title": *"[^"]*"' "$f" | sed -e 's/"title": *"//' -e 's/"$//')"
  echo "  - $key : $title"
done

echo
echo "Comparer les deux listes : une famille native absente de Track Secrets est normalement"
echo "couverte par sonar-text ; une règle Track Secrets qui recoupe le natif doit rester inactive."
