# Licence : motif et portée

> [!CAUTION]
> Cette note explique la licence de **Track Secrets**, ce qu'elle couvre et ce qu'elle ne couvre pas.\
> Le texte qui fait foi est celui du fichier [`LICENSE`](LICENSE).

## 1️⃣ En bref

| Élément | Licence |
| --- | --- |
| Code original du plugin | **GNU Lesser General Public License, version 3 ou ultérieure** (`LGPL-3.0-or-later`) |
| Parties dérivées de Whispers et de Sonar Secrets | contenu d'origine sous **Apache License 2.0**, modifié et distribué dans l'œuvre combinée sous LGPL 3.0 ou ultérieure (`LGPL-3.0-or-later AND Apache-2.0`) |
| Documentation (`README.md`, le dossier `docs/`) | [CC BY-SA 4.0](docs/LICENSE.md) |
| Composants tiers embarqués ou utilisés | leur propre licence (voir [`NOTICE`](NOTICE)) |

Ce projet n'a jamais été publié sous une autre licence.

## 2️⃣ Pourquoi ce choix

L'objectif est de **garantir que le plugin reste ouvert** : que chacun puisse l'utiliser, l'étudier, le modifier et le partager, et que personne ne puisse le fermer. C'est ce que fait une licence à copyleft.

La **LGPL 3.0** a été préférée à la GPL ou à l'AGPL parce que c'est la licence de l'écosystème SonarQube : SonarQube Community Build, son API de plugins et la bibliothèque `sonar-analyzer-commons` embarquée dans le jar sont sous LGPL. Elle protège le plugin lui-même sans empêcher son usage avec d'autres logiciels, y compris non libres.

## 3️⃣ Ce que cela signifie pour vous

Vous pouvez :

- utiliser le plugin, **y compris dans un cadre commercial**, avec n'importe quelle édition de SonarQube ;
- l'étudier, le modifier, le redistribuer ;
- le revendre ou l'inclure dans une distribution, en respectant la licence.

Vous devez, si vous le diffusez (modifié ou non) :

- conserver les mentions de copyright et de licence, ainsi que le fichier `NOTICE`, et joindre les textes de licence (le jar du plugin les embarque dans `META-INF/`) ;
- indiquer vos modifications ;
- publier le code source de vos **modifications du plugin** sous la même licence (LGPL 3.0 ou ultérieure) ; les parties issues de Whispers et de Sonar Secrets gardent en plus leur licence Apache 2.0.

Vous n'avez **aucune obligation** si vous utilisez le plugin tel quel, ni pour les logiciels que vous utilisez avec lui.

## 4️⃣ Portée

**Parties dérivées d'Apache 2.0.** Whispers et Sonar Secrets (Skyscanner) sont sous licence Apache 2.0, qui autorise la réutilisation dans une œuvre distribuée sous d'autres conditions, à condition de conserver leurs mentions de copyright, d'indiquer les modifications et de joindre le texte de la licence ([`LICENSES/Apache-2.0.txt`](LICENSES/Apache-2.0.txt)). Cette licence est compatible avec la LGPL 3.0. Les fichiers concernés portent l'en-tête `LGPL-3.0-or-later AND Apache-2.0`, et la liste détaillée des éléments repris est dans [`NOTICE`](NOTICE).

**En-têtes des fichiers.** Chaque fichier source porte un en-tête `SPDX-License-Identifier`. Les fichiers qui ne peuvent pas en porter (métadonnées de règles `.json` et `.html`, fichiers de configuration) sont sous la licence du dépôt (LGPL 3.0 ou ultérieure), et la documentation `.md` sous CC BY-SA 4.0.

**Composants embarqués.** Le jar embarque `sonar-analyzer-commons` (SonarSource, LGPL 3.0), dont le code source est public : <https://github.com/SonarSource/sonar-analyzer-commons>.

**Versions dérivées.** Une version dérivée, y compris maintenue par une organisation, reste soumise à cette licence pour la part qui en provient, sauf accord écrit du titulaire des droits.

## 5️⃣ Questions fréquentes

- **Puis-je l'utiliser dans mon entreprise, y compris à titre commercial ?** Oui. Si vous ne le modifiez pas, vous n'avez aucune obligation particulière.
- **Puis-je le modifier pour mon usage ?** Oui. Vous n'avez d'obligation que si vous diffusez votre version modifiée à d'autres.
- **Puis-je l'utiliser avec un SonarQube dont la licence n'est pas libre ?** Oui, c'est le but du choix de la LGPL.
- **Puis-je reprendre une partie du moteur dans mon propre logiciel ?** Oui, en respectant la LGPL pour cette partie : vos modifications des fichiers repris restent sous LGPL, et les fichiers marqués Apache-2.0 gardent aussi cette licence. Votre propre code n'est pas concerné s'il se contente d'utiliser le plugin.
- **Puis-je le revendre ?** Oui, en respectant la licence.
- **J'ai un doute sur mon cas.** Ouvrez un ticket sur le dépôt. Ce document est une explication, pas un avis juridique : le texte du fichier `LICENSE` fait foi.

## 6️⃣ Documents liés

- [`LICENSE`](LICENSE) : texte de la LGPL 3.0 (elle renvoie à la GPL 3.0, dont le texte est dans [`LICENSES/GPL-3.0.txt`](LICENSES/GPL-3.0.txt)).
- [`LICENSES/Apache-2.0.txt`](LICENSES/Apache-2.0.txt) : licence des parties dérivées de Whispers et de Sonar Secrets.
- [`LICENSES/CC-BY-SA-4.0.txt`](LICENSES/CC-BY-SA-4.0.txt) : licence de la documentation.
- [`NOTICE`](NOTICE) : attributions et composants tiers.
- [`docs/LICENSE.md`](docs/LICENSE.md) : licence de la documentation.
