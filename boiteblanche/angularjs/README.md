# Principales zones à risque de sécurité dans AngularJS (Quick Win)

## 1. Cross-Site Scripting (XSS)
- **CVEs associées**: CVE-2022-25869, CVE-2020-7676, CVE-2019-14863
- **Description**: Mauvaise gestion de la désinfection des entrées utilisateur ou du contenu HTML dynamique, permettant l’exécution de code malveillant dans le navigateur de la victime.
- **Versions vulnérables**: 
  - CVE-2022-25869 : toutes versions (XSS via interpolation dans <textarea> sur IE)
  - CVE-2020-7676 : < 1.8.0 (XSS via parsing HTML, balises <option> dans <select>)
  - CVE-2019-14863 : < 1.5.0-beta.0 (XSS via échappement de contexte)
- **Exemple de code vulnérable**:
  ```
  <div ng-bind-html="userContent"></div>
  ```
  - Si `userContent` contient `<img src=x onerror=alert(1)>`, cela déclenche un XSS.
- **Correctif approprié**:
  - Toujours utiliser `$sanitize` ou `DomSanitizer` pour tout contenu HTML dynamique.
  - Mettre à jour AngularJS vers la version la plus récente possible (idéalement migrer vers Angular moderne, car AngularJS est en EOL)[4][7][8].

## 2. Mauvaise désinfection des attributs HTML (srcset)
- **CVEs associées**: CVE-2024-8372, CVE-2024-8373
- **Description**: Mauvaise désinfection de l’attribut `srcset` dans les balises `<img>` ou `<source>`, permettant de contourner les restrictions de sources d’images et de réaliser du content spoofing ou XSS.
- **Versions vulnérables**: 
  - CVE-2024-8372 : ≥ 1.3.0-rc.4
  - CVE-2024-8373 : toutes versions
- **Exemple de code vulnérable**:
  ```
  <img ng-srcset="{{userSrcset}}">
  ```
  - Un attaquant peut injecter une valeur malveillante dans `userSrcset`.
- **Correctif approprié**:
  - Aucun correctif officiel (AngularJS est EOL).
  - Filtrer et valider strictement les valeurs injectées dans les attributs HTML sensibles[4][5].

## 3. Regular Expression Denial of Service (ReDoS)
- **CVEs associées**: CVE-2023-26118, CVE-2023-26117, CVE-2023-26116, CVE-2024-21490, CVE-2022-25844
- **Description**: Utilisation de regex non sécurisées dans certains services ou directives, permettant à un attaquant de provoquer un déni de service via des entrées spécialement conçues.
- **Versions vulnérables**: 
  - CVE-2023-26118 : ≥ 1.4.9 (input[url])
  - CVE-2023-26117 : ≥ 1.0.0 ($resource)
  - CVE-2023-26116 : ≥ 1.2.21 (angular.copy)
  - CVE-2024-21490 : ≥ 1.3.0 (ng-srcset)
  - CVE-2022-25844 : ≥ 1.7.0 (locale personnalisée)
- **Exemple de code vulnérable**:
  ```
  angular.copy(userInput, {});
  ```
  - `userInput` peut contenir une chaîne provoquant un backtracking catastrophique.
- **Correctif approprié**:
  - Mettre à jour vers la dernière version disponible.
  - Ne jamais traiter directement des entrées utilisateur avec des fonctions utilisant des regex non maîtrisées[4].

## 4. Prototype Pollution
- **CVE associée**: CVE-2019-10768
- **Description**: La fonction `merge()` pouvait être utilisée pour modifier le prototype global via un payload `__proto__`, ouvrant la voie à des attaques avancées.
- **Versions vulnérables**: < 1.7.9
- **Exemple de code vulnérable**:
  ```
  angular.merge({}, JSON.parse(userInput));
  ```
  - `userInput` : `{"__proto__": {"admin": true}}`
- **Correctif approprié**:
  - Mettre à jour vers 1.7.9+
  - Ne jamais merger d’objets issus d’entrées utilisateur sans validation[4].

## 5. Fin de support & correctifs impossibles
- **Description**: AngularJS est EOL (End-of-Life) depuis 2022, aucun correctif de sécurité officiel n’est publié.
- **Correctif approprié**:
  - Migrer vers Angular moderne (`@angular/core`) ou utiliser un support commercial tiers si migration impossible[2][3][4].

