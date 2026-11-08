# Qualité du code : choix retenus

> [!NOTE]
> Ce document explique comment les alertes SonarQube sont traitées dans ce projet et justifie chaque choix.\
> Il reprend l'analyse du 8 novembre 2026 (297 anomalies, 116 règles différentes).

## 1️⃣ Principe

Pour chaque règle qui signale le code, on se pose une seule question : **la règle est-elle légitime ?**

| Réponse | Traitement |
| --- | --- |
| **Oui** | On la **respecte** : on corrige le code. |
| **Non**, parce qu'elle ne s'applique plus à du code moderne, qu'elle fait double emploi avec une autre, ou que l'outil se trompe | On **l'exclut du profil SonarQube**. |

On n'ajoute **pas** de `@SuppressWarnings` pour contourner une règle : cela laisse une règle sans objet active, encombre le code et se trouve sanctionné par la règle S1309 (« tracer chaque usage de `@SuppressWarnings` »).

Une règle qui ne vaut pas la peine d'être respectée ne vaut pas la peine d'être supprimée vingt fois.

Deux critères objectifs aident à trancher :

- l'appartenance au profil recommandé de SonarSource (« Sonar way ») : ses règles sont légitimes par principe ;
- la version de Java visée (17) : les règles qui réclament des fonctionnalités de Java 21 ou plus ne s'appliquent pas.

## 2️⃣ Priorité aux règles SonarQube

Quand une règle SonarQube et une règle d'un autre outil (PMD, Checkstyle, fb-contrib, Creedengo) contrôlent la **même chose**, on garde celle de SonarQube et on exclut l'autre. Les raisons :

- le profil de SonarSource est maintenu avec le serveur et ne dépend d'aucun plugin tiers à mettre à jour ;
- ses règles sont paramétrables depuis l'interface (c'est le cas de S3578) ;
- deux outils qui signalent la même chose comptent le même défaut deux fois.

La colonne « Équivalent SonarQube » du tableau des exclusions indique quelle règle de SonarQube reprend le contrôle. Une règle d'un autre outil n'est conservée que si SonarQube n'a rien d'équivalent. Les règles de **sécurité** de FindSecBugs sont une exception d'usage : on les garde en complément, car un second regard coûte peu.

## 3️⃣ Niveaux de sévérité

On traite les anomalies **BLOCKER**, **CRITICAL** (haute), **MAJOR** (moyenne) et **MINOR** (basse). Les anomalies **INFO** sont traitées au mieux : on les corrige quand c'est simple, sans en faire un objectif.

| Règle | Anomalies | Décision |
| --- | ---: | --- |
| `track-logger-method:track-debug-method` | 5 | CONSERVER |
| `fb-contrib:STT_STRING_PARSING_A_FIELD` | 3 | EXCLURE |
| `fb-contrib:OCP_OVERLY_CONCRETE_COLLECTION_PARAMETER` | 2 | EXCLURE |
| `track-logger-method:track-info-method` | 2 | CONSERVER |
| `track-logger-method:track-warn-method` | 2 | CONSERVER |
| `java:S923` | 1 | EXCLURE |
| `fb-contrib:CE_CLASS_ENVY` | 1 | EXCLURE |
| `java:S6212` | 0 | CORRIGÉ |
| `fb-contrib:LSC_LITERAL_STRING_COMPARISON` | 0 | CORRIGÉ |
| `fb-contrib:OCP_OVERLY_CONCRETE_PARAMETER` | 0 | CORRIGÉ |
| `fb-contrib:MOM_MISLEADING_OVERLOAD_MODEL` | 0 | CORRIGÉ |
| `java:S1309` | 0 | CONSERVER |
| `findbugs:EI_EXPOSE_REP` | 0 | CORRIGÉ |

## 4️⃣ Bilan

| Décision | Règles | Anomalies |
| --- | ---: | ---: |
| Corrigé | 59 | 17 |
| À corriger (prochaine passe) | 0 | 0 |
| Exclure du profil Sonar | 49 | 271 |
| Conserver avec un paramètre | 1 | 0 |
| Conserver | 7 | 9 |

## 5️⃣ Complexité : S3776 et S1541

Ces deux règles mesurent la complexité d'une méthode, **différemment**. Elles ne sont pas un doublon l'une de l'autre.

| | S1541, complexité cyclomatique (McCabe) | S3776, complexité cognitive (SonarSource) |
| --- | --- | --- |
| Question posée | Combien de chemins d'exécution indépendants ? Donc combien de tests au minimum ? | Quel effort pour **comprendre** la méthode ? |
| `if`, boucle, `catch` | +1 chacun | +1 chacun, **plus l'imbrication** (un `if` dans un `for` coûte plus) |
| `switch` à 20 cas | +20 | +1 |
| `a && b && c` | +3 | +1 |
| Seuil par défaut | 10 | 15 |
| Dans le « Sonar way » | non | oui |

Elles se rejoignent sur le code très ramifié, et divergent sur deux cas : un `switch` ou une suite de gardes à plat (S1541 pénalise, S3776 non) et un code peu ramifié mais profondément imbriqué (S3776 pénalise davantage).

Sur ce projet, six méthodes dépassaient S3776 et quatre dépassaient seulement S1541 (11 à 13). Les deux règles sont conservées ; toutes les méthodes concernées ont été découpées.

À l'inverse, **PMD** recalcule les mêmes mesures avec son propre outil (`CyclomaticComplexity` `CognitiveComplexity`) : c'est là que se trouve le véritable doublon.

## 6️⃣ Règles à exclure du profil SonarQube

49 règles ne sont pas légitimes pour ce projet. Elles sont à désactiver dans le profil qualité, **sans toucher au code**. Si le profil sert aussi d'autres projets, le copier d'abord dans un profil dédié aux projets personnels.

| Règle | Anomalies | Équivalent SonarQube | Raison |
| --- | ---: | --- | --- |
| `creedengo-java:GCI67` | 57 | aucun | `++i` ou `i++` : aucun effet sur du code compilé puis optimisé par le JIT. |
| `pmd:CommentDefaultAccessModifier` | 27 | aucun | Exige un commentaire `/* default */` : convention PMD rare, qui ne vient d'aucune norme Java. |
| `java:S5867` | 24 | aucun | Les expressions du projet sont volontairement ASCII (noms de variables, formats de jetons) : l'équivalence Unicode demandée changerait le sens des motifs. À exclure dans le profil dédié à ces projets. |
| `creedengo-java:GCI3` | 22 | aucun | Micro-optimisation sans effet mesurable (taille d'une collection ou d'un tableau lue dans une boucle). |
| `pmd:AvoidLiteralsInIfCondition` | 21 | `java:S109` | Doublon de S109, que l'on respecte (règle SonarQube préférée à PMD). |
| `pmd:AvoidFieldNameMatchingMethodName` | 18 | aucun | Les accesseurs d'un `record` portent le nom du champ par construction. |
| `creedengo-java:GCI76` | 12 | aucun | Les collections statiques du projet sont des constantes immuables (`List.of`, `Set.of`, `Map.copyOf`) ; la règle vise l'état statique modifiable. |
| `pmd:AvoidDuplicateLiterals` | 10 | aucun | Dans un test, répéter la donnée d'entrée rend le cas lisible. |
| `creedengo-java:GCI69` | 9 | aucun | Micro-optimisation sans effet mesurable. |
| `pmd:TooManyMethods` | 8 | aucun | Seuil arbitraire sur le nombre de méthodes. |
| `pmd:AvoidInstantiatingObjectsInLoops` | 6 | aucun | Heuristique de performance obsolète : le ramasse-miettes alloue les objets de courte durée à un coût quasi nul. |
| `creedengo-java:GCI2` | 6 | aucun | Redondant avec les règles de complexité (S3776). |
| `creedengo-java:GCI32` | 5 | aucun | Micro-optimisation sans effet mesurable (taille initiale des `StringBuilder`). |
| `pmd:AvoidCatchingGenericException` | 4 | aucun | Les extracteurs attrapent `RuntimeException` à la frontière pour qu'un fichier illisible n'interrompe pas l'analyse : choix voulu et documenté. |
| `pmd:UseConcurrentHashMap` | 4 | aucun | Cartes locales à un seul thread : aucune concurrence. |
| `java:S2972` | 3 | aucun | Métrique de taille : la lisibilité est déjà mesurée par S3776. |
| `creedengo-java:GCI77` | 3 | `java:S4248` | Faux positif : les expressions de `FieldSpec.regex` et des exclusions utilisateur sont fournies à l'exécution ; elles ne peuvent pas être des constantes. S4248 reste appliquée ailleurs. |
| `fb-contrib:STT_STRING_PARSING_A_FIELD` | 3 | aucun | Préférence de style sur l'analyse d'un champ. |
| `java:S2211` | 3 | aucun | Impose de typer explicitement les paramètres des lambdas, à l'inverse de l'inférence de type de Java 8+. |
| `pmd:NullAssignment` | 2 | aucun | `null` documenté comme « absence » dans de petites méthodes privées. |
| `fb-contrib:OCP_OVERLY_CONCRETE_COLLECTION_PARAMETER` | 2 | `java:S1319` | Le seul cas restant est le composant d'un `record` (`Pair.breadcrumbs`) : le constructeur canonique impose le type du composant ; équivalent SonarQube S1319 respecté ailleurs. |
| `pmd:ShortMethodName` | 2 | aucun | `of` est le nom idiomatique d'une fabrique statique. |
| `pmd:AvoidStringBufferField` | 2 | aucun | Objet de courte durée : pas de risque de fuite mémoire. |
| `pmd:CyclomaticComplexity` | 2 | `java:S1541` | Même mesure que S1541 (complexité cyclomatique), calculée par un second outil : la signaler deux fois n'apporte rien. |
| `pmd:GodClass` | 2 | aucun | Heuristique de métriques, sans seuil défendable ici. |
| `checkstyle:coding.UnusedLambdaParameterShouldBeUnnamedCheck` | 1 | aucun | Même raison : Java 21 et suivants. |
| `pmd:FieldDeclarationsShouldBeAtStartOfClass` | 1 | `java:S1213` | Doublon de S1213. |
| `checkstyle:coding.UnusedCatchParameterShouldBeUnnamedCheck` | 1 | aucun | Variables sans nom : fonctionnalité de Java 21 (JEP 443) ; ce projet vise Java 17. |
| `java:S923` | 1 | aucun | Fonctions à nombre variable d'arguments : les varargs sont un idiome normal de Java (`String.format`, `List.of`). |
| `java:S138` | 1 | aucun | Métrique de taille : la lisibilité est déjà mesurée par S3776. |
| `java:S1711` | 1 | aucun | `Extractor` est un concept du domaine, plus lisible qu'un `BiConsumer<String, Consumer<Pair>>`. |
| `checkstyle:naming.GoogleNonConstantFieldNameCheck` | 1 | aucun | Règle propre au guide de style de Google, non adopté. |
| `java:S1151` | 1 | aucun | Métrique de taille : la lisibilité est déjà mesurée par S3776. |
| `pmd:UselessParentheses` | 1 | aucun | Parenthèses de clarté volontaires dans les expressions booléennes. |
| `pmd:CouplingBetweenObjects` | 1 | aucun | Métrique appliquée à une classe de test. |
| `pmd:TooManyStaticImports` | 1 | aucun | Les tests importent statiquement les assertions : usage normal. |
| `pmd:ExcessiveImports` | 1 | aucun | Seuil arbitraire sur le nombre d'imports. |
| `fb-contrib:CE_CLASS_ENVY` | 1 | aucun | Heuristique appliquée à une méthode de test. |
| `pmd:UnitTestShouldIncludeAssert` | 1 | aucun | Les vérifications Mockito (`verify`) ne sont pas reconnues comme des assertions. |
| `pmd:ShortVariable` | 0 | aucun | Convention de nommage qui ne vient pas de Java : `s`, `m`, `e`, `c`, `i` sont idiomatiques pour des portées de quelques lignes. |
| `checkstyle:coding.AvoidInlineConditionalsCheck` | 0 | `java:S1774` | Doublon de S1774 : même signal, même décision (voir S1774 et ARCHITECTURE.md §4.10). |
| `java:S1774` | 0 | aucun | Interdit tous les ternaires, y compris ceux qui sont plus clairs qu'un `if / else`. Le garde-fou est assuré par S3358 (imbrication), S3776 (complexité cognitive) et la règle 15 d'ARCHITECTURE.md (§4.10), vérifiée en revue. |
| `pmd:LawOfDemeter` | 0 | aucun | Faux positifs systématiques avec les API fluides, les flux et les accesseurs de `record`. |
| `checkstyle:coding.MissingNullCaseInSwitchCheck` | 0 | aucun | Filtrage par motifs de Java 21 ; ce projet vise Java 17. |
| `pmd:UnnecessaryImport` | 0 | aucun | Doublon de S1128 (règle SonarQube préférée à PMD). |
| `pmd:MethodNamingConventions` | 0 | `java:S3578` | Même contrôle que S3578, mais ses motifs sont plus rigides. Priorité aux règles SonarQube. |
| `pmd:CognitiveComplexity` | 0 | `java:S3776` | Même mesure que S3776 (complexité cognitive), calculée par un second outil. |
| `pmd:NPathComplexity` | 0 | `java:S1541` | Compte les chemins d'exécution comme S1541, avec un seuil (200) différent : même signal. |
| `pmd:ConfusingTernary` | 0 | aucun | Préférence de style sur le sens des conditions. |

### Liste à copier

```text
checkstyle:com.puppycrawl.tools.checkstyle.checks.coding.AvoidInlineConditionalsCheck
checkstyle:com.puppycrawl.tools.checkstyle.checks.coding.MissingNullCaseInSwitchCheck
checkstyle:com.puppycrawl.tools.checkstyle.checks.coding.UnusedCatchParameterShouldBeUnnamedCheck
checkstyle:com.puppycrawl.tools.checkstyle.checks.coding.UnusedLambdaParameterShouldBeUnnamedCheck
checkstyle:com.puppycrawl.tools.checkstyle.checks.naming.GoogleNonConstantFieldNameCheck
creedengo-java:GCI2
creedengo-java:GCI3
creedengo-java:GCI32
creedengo-java:GCI67
creedengo-java:GCI69
creedengo-java:GCI76
creedengo-java:GCI77
fb-contrib:CE_CLASS_ENVY
fb-contrib:OCP_OVERLY_CONCRETE_COLLECTION_PARAMETER
fb-contrib:STT_STRING_PARSING_A_FIELD
java:S1151
java:S138
java:S1711
java:S1774
java:S2211
java:S2972
java:S5867
java:S923
pmd:AvoidCatchingGenericException
pmd:AvoidDuplicateLiterals
pmd:AvoidFieldNameMatchingMethodName
pmd:AvoidInstantiatingObjectsInLoops
pmd:AvoidLiteralsInIfCondition
pmd:AvoidStringBufferField
pmd:CognitiveComplexity
pmd:CommentDefaultAccessModifier
pmd:ConfusingTernary
pmd:CouplingBetweenObjects
pmd:CyclomaticComplexity
pmd:ExcessiveImports
pmd:FieldDeclarationsShouldBeAtStartOfClass
pmd:GodClass
pmd:LawOfDemeter
pmd:MethodNamingConventions
pmd:NPathComplexity
pmd:NullAssignment
pmd:ShortMethodName
pmd:ShortVariable
pmd:TooManyMethods
pmd:TooManyStaticImports
pmd:UnitTestShouldIncludeAssert
pmd:UnnecessaryImport
pmd:UseConcurrentHashMap
pmd:UselessParentheses
```

## 7️⃣ Règles légitimes, déjà corrigées

| Règle | Anomalies | Raison |
| --- | ---: | --- |
| `java:S1142` | 5 | Respectée : 5 méthodes ramenées à 3 `return` au plus (méthodes extraites, valeur de retour unique). |
| `java:S909` | 4 | Respectée : les 4 `continue` sont remplacés par des conditions positives (`if` / `else`). |
| `java:S9391` | 4 | Respectée : les boucles de filtrage et de transformation deviennent des flux. |
| `xml:S1120` | 2 | `pom.xml` mis en forme : un élément par ligne, indentation cohérente. |
| `xml:S2321` | 2 | Blocs `<goals>` du `pom.xml` répartis sur plusieurs lignes. |
| `checkstyle:design.InnerTypeLastCheck` | 0 | Types imbriqués placés en fin de classe. Ce n'est pas un doublon de S1213 (ordre des champs, constructeurs, méthodes) : SonarQube n'a pas d'équivalent, la règle est peu coûteuse à respecter (4 fichiers). |
| `java:S6212` | 0 | Adopté (Java 10+) : toutes les déclarations signalées sont converties en `var`. |
| `java:S2039` | 0 | Rendre les champs des classes imbriquées `private` : la classe englobante y accède de toute façon. |
| `pmd:AssignmentInOperand` | 0 | Même traitement que S881. |
| `java:S2325` | 0 | Méthodes qui n'utilisent pas l'instance : les rendre `static`. |
| `java:S881` | 0 | Séparer les incréments des expressions. |
| `java:S1941` | 0 | Rapprocher la déclaration des variables de leur premier usage. |
| `java:S8786` | 0 | Expressions à retour arrière remplacées par des analyses linéaires (`KeyValueLines`, `Patterns.isPath`) ou réécrites sans ambiguïté (YAML). |
| `java:S864` | 0 | Ajouter des parenthèses lorsque `&&` et `\|\|` sont mélangés. |
| `java:S1228` | 0 | Ajouter un `package-info.java` à chaque package. |
| `java:S1166` | 0 | Les exceptions avalées volontairement (fichier mal formé) doivent être journalisées au niveau DEBUG plutôt qu'ignorées en silence. |
| `pmd:LinguisticNaming` | 0 | Constructeurs fluides renommés `expectBase64`, `onlyAscii`, `expectUri`, `requireLuhn` : « is » est réservé aux booléens. |
| `fb-contrib:LSC_LITERAL_STRING_COMPARISON` | 0 | Même correction que S1132. |
| `pmd:LiteralsFirstInComparisons` | 0 | Même correction que S1132. |
| `pmd:EmptyCatchBlock` | 0 | Même traitement que S1166. |
| `java:S125` | 0 | Retirer le code mis en commentaire. |
| `java:S4248` | 0 | Les expressions régulières sont précompilées en constantes. |
| `java:S1874` | 0 | `InputFile.relativePath()` remplacé par `uri()` relativisé au répertoire de base du projet. |
| `java:S1128` | 0 | Imports inutilisés retirés. |
| `pmd:LooseCoupling` | 0 | `NavigableMap` et `SortedSet` à la place de `TreeMap` et `TreeSet`. |
| `java:S1132` | 0 | Littéral en premier dans les comparaisons : protège contre les `null`. |
| `pmd:UnnecessaryBoxing` | 0 | Retirer le boxing explicite inutile. |
| `java:S1067` | 0 | Expressions à plus de 3 opérateurs découpées en méthodes ou prédicats nommés. |
| `java:S2384` | 0 | Membre modifiable stocké ou retourné directement : même risque que `EI_EXPOSE_REP`, à traiter par copie défensive. |
| `checkstyle:HexLiteralCaseCheck` | 0 | Littéral hexadécimal en majuscules. |
| `java:S1213` | 0 | Ordre des membres : constantes, champs, constructeurs, méthodes. |
| `xml:S103` | 0 | Lignes de plus de 120 caractères du `pom.xml`. |
| `fb-contrib:OCP_OVERLY_CONCRETE_PARAMETER` | 0 | Paramètres typés par l'interface la plus générale (`Collection`). |
| `java:S2301` | 0 | Paramètre booléen « sélecteur » du constructeur de `CodeExtractor` à remplacer par deux fabriques nommées. |
| `fb-contrib:MOM_MISLEADING_OVERLOAD_MODEL` | 0 | Méthode privée renommée `isPrintableAscii` : plus de surcharge trompeuse. |
| `java:S5411` | 0 | `FieldSpec` n'utilise plus un `Boolean` objet comme condition. |
| `pmd:UseLocaleWithCaseConversions` | 0 | Même traitement que S1449. |
| `java:S1449` | 0 | Utiliser une locale explicite pour les conversions de casse. |
| `java:S4838` | 0 | Itérer sur le type réel de la collection. |
| `java:S7158` | 0 | Utiliser `isEmpty()` ou `isBlank()`. |
| `java:S135` | 0 | Même principe que S909 : pas plus d'une rupture de boucle ; non signalée actuellement. |
| `pmd:AvoidReassigningLoopVariables` | 0 | Même correction que S127. |
| `java:S127` | 0 | Les boucles qui modifiaient leur compteur sont des boucles `while`. |
| `java:S9016` | 0 | Mock créé dans une variable locale avant l'appel à `thenReturn()`. |
| `java:S109` | 0 | Nombres magiques nommés par des constantes (longueurs, groupes de capture, seuils, facteurs de l'algorithme de Luhn...). |
| `java:S139` | 0 | Commentaires de fin de ligne à placer au-dessus du code. |
| `java:S103` | 0 | Lignes de plus de 120 caractères à couper. |
| `java:S1541` | 0 | Conservée. Elle mesure le nombre de chemins d'exécution (donc de tests nécessaires), ce que S3776 ne mesure pas. Les 4 méthodes signalées (`FieldSpec.matches`, `Patterns.isScheme`, `UriPairs.extract`, `XmlExtractor.end`) sont découpées sous le seuil de 10. |
| `pmd:GuardLogStatement` | 0 | Légitime quand les arguments du message sont évalués avant l'appel (`custom.size()`, `e.getMessage()`) : gardes `isInfoEnabled()` ajoutées côté capteur, et dans les extracteurs l'exception elle-même est passée au journal (aucune évaluation anticipée). |
| `fb-contrib:CLI_CONSTANT_LIST_INDEX` | 0 | `ENV A 1` est lu par une expression à deux groupes nommés plutôt que par des indices de tableau constants. |
| `java:S5843` | 0 | Les expressions trop complexes sont découpées en motifs courts, appliqués à un contexte borné. |
| `findsecbugs:REDOS` | 0 | Les expressions qui portaient sur le contenu des chaînes sont remplacées par un analyseur linéaire (`CodeExtractor`) et une validation de schéma sans expression régulière (`Patterns.looksLikeUri`). Les quantificateurs possessifs supprimaient déjà le risque réel, mais FindSecBugs ne les reconnaît pas : seule la suppression de l'expression satisfait aussi l'outil. |
| `java:S3776` | 0 | Conservée : c'est la règle de lisibilité du « Sonar way ». Six méthodes ont été ramenées sous le seuil de 15 ; plus aucune alerte. |
| `java:S5612` | 0 | Les extracteurs écrits comme lambdas de 20 lignes sont des méthodes nommées. |
| `java:S134` | 0 | Imbrication réduite (méthodes extraites). |
| `findbugs:EI_EXPOSE_REP` | 0 | `Pair` conserve une copie immuable de la liste de fil d'Ariane. |
| `java:S126` | 0 | `switch` avec `default` à la place d'un `else if` sans `else`. |
| `findsecbugs:XXE_XMLSTREAMREADER` | 0 | La fabrique XML est configurée (DTD et entités externes désactivées) dans la méthode qui l'utilise, ce que l'outil peut vérifier. |
| `fb-contrib:FCCD_FIND_CLASS_CIRCULAR_DEPENDENCY` | 0 | Dépendance circulaire entre `ShellExtractor` et `SimpleExtractors` supprimée (classes `ShellWords` et `Lines`). |

## 8️⃣ Règles légitimes, à corriger à la prochaine passe

| Règle | Anomalies | Raison |
| --- | ---: | --- |

## 9️⃣ Règles conservées avec un paramètre

| Règle | Anomalies | Raison |
| --- | ---: | --- |
| `java:S3578` | 0 | Règle conservée, avec le paramètre `format` réglé sur `^[a-z][a-zA-Z0-9]*(_[a-zA-Z0-9]+)*$` : camelCase et snake_case admis, majuscule initiale et `_` doublés refusés. Vérifié sur les 49 tests du projet : 0 refus, alors que le format d'origine `^test[A-Z][a-zA-Z0-9]*$` les refuse tous. |

## 🔟 Règles conservées

| Règle | Anomalies | Raison |
| --- | ---: | --- |
| `track-logger-method:track-debug-method` | 5 | Règles de l'autre plugin de l'auteur : elles mesurent l'usage des journaux, sans qualifier un défaut. |
| `track-logger-method:track-info-method` | 2 | Même raison. |
| `track-logger-method:track-warn-method` | 2 | Même raison. |
| `creedengo-java:GCI82` | 0 | Règle exacte (ce ne sont pas des faux positifs) mais sans effet mesurable : le compilateur traite déjà les variables effectivement finales comme telles, et le projet utilise `var`. Elle plante en outre sur les constructeurs compacts de `record`. Conservée dans le profil ; exclusion ciblée sur le projet par `sonar.issue.ignore.multicriteria` dans le `pom.xml`, commentée, plutôt que des centaines de `@SuppressWarnings` (S1309). |
| `java:S2698` | 0 | Règle conservée dans le profil (légitime pour les assertions JUnit nues). Avec AssertJ, l'échec décrit déjà valeurs attendue et observée : exclusion ciblée sur `src/test/**` par `sonar.issue.ignore.multicriteria` dans le `pom.xml`, commentée, plutôt qu'un `@SuppressWarnings` par classe. |
| `fb-contrib:NAB_NEEDLESS_BOOLEAN_CONSTANT_CONVERSION` | 0 | Règle conservée dans le profil (le boxage dans une boucle est un vrai défaut). Exclusion ciblée sur `XmlExtractor` par `sonar.issue.ignore.multicriteria` : les trois `setProperty(..., false)` de la protection XXE doivent garder le littéral `false` pour que FindSecBugs la vérifie ; `Boolean.FALSE` la masquerait. La sécurité prime, pour un gain nul (`Boolean.valueOf(false)` est une constante). |
| `java:S1309` | 0 | Politique de traçabilité des `@SuppressWarnings`. Le code n'en contient plus aucun : les 23 alertes venaient des suppressions GCI82, retirées. |

## 🔟+1️⃣ Enseignements de la première analyse

- **FindSecBugs ne comprend pas les quantificateurs possessifs.** Le risque de ReDoS réel avait disparu, mais l'outil a signalé huit expressions de plus. La vraie réponse a été de ne plus appliquer d'expression régulière au contenu des chaînes : un analyseur linéaire est plus sûr, plus rapide, et satisfait l'outil.
- **Creedengo GCI82 plante sur les `record` à constructeur compact.** `Pair` utilise donc un constructeur canonique explicite. Le bogue est à signaler au projet Creedengo.
- **`@SuppressWarnings` n'est pas gratuit** : les 23 suppressions de GCI82 ont créé 23 alertes S1309. Exclure la règle est la bonne méthode.
- **Les outils se contredisent parfois** : fb-contrib réclame `Boolean.TRUE`, FindSecBugs exige un `false` littéral pour reconnaître la protection XXE. On suit l'outil de sécurité et on exclut la règle de style.

## 🔟+2️⃣ En cas de nouvelle alerte

1. La règle est-elle dans le « Sonar way » ? Si oui, on corrige.
2. Sinon, la règle améliore-t-elle réellement la lisibilité, la sécurité ou la fiabilité de **ce** code ? Si oui, on corrige.
3. Sinon, on l'exclut du profil et on l'ajoute au tableau ci-dessus avec sa raison.
