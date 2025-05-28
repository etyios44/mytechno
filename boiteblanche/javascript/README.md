# Principales zones à risque de sécurité dans JavaScript (Quick Win)

## 1. Cross-Site Scripting (XSS)
- **CVEs associées**: CVE-2024-26141, CVE-2023-26115, CVE-2022-25869
- **Description**: Exécution de scripts malveillants dans le navigateur d’un utilisateur via l’injection de contenu non filtré dans le DOM.
- **Versions vulnérables**: Toutes versions si le code n’est pas protégé contre l’injection.
- **Exemple de code vulnérable**:
  ```
  // Insertion directe de données utilisateur dans le DOM
  document.getElementById('output').innerHTML = userInput;
  ```
- **Correctif approprié**:
  - Toujours échapper ou désinfecter les données avant l’insertion dans le DOM.
  - Utiliser `textContent` au lieu de `innerHTML` quand c’est possible.

## 2. Prototype Pollution
- **CVEs associées**: CVE-2024-26138, CVE-2023-26136, CVE-2019-10744
- **Description**: Un attaquant peut modifier le prototype d’objets globaux, impactant la logique applicative ou introduisant des failles XSS/RCE.
- **Versions vulnérables**: Dépend des librairies utilisées (lodash < 4.17.21, jQuery < 3.5.0, etc.)
- **Exemple de code vulnérable**:
  ```
  // Fusion d’objets sans filtre
  Object.assign({}, JSON.parse(userInput));
  // userInput : {"__proto__": {"isAdmin": true}}
  ```
- **Correctif approprié**:
  - Filtrer les clés spéciales comme `__proto__`, `constructor`, `prototype` avant toute fusion d’objets.
  - Mettre à jour toutes les librairies tierces.

## 3. Exécution de code arbitraire (RCE côté serveur Node.js)
- **CVEs associées**: CVE-2024-26137, CVE-2023-23920, CVE-2022-21824
- **Description**: Utilisation dangereuse de fonctions comme `eval`, `Function`, ou désérialisation non sécurisée, permettant l’exécution de code arbitraire.
- **Versions vulnérables**: Toutes versions si le code utilise des fonctions d’exécution dynamique sans contrôle.
- **Exemple de code vulnérable**:
  ```
  // Évaluation de code utilisateur
  eval(userInput);
  ```
- **Correctif approprié**:
  - Ne jamais utiliser `eval` ou `Function` sur des données non fiables.
  - Privilégier des alternatives sûres ou des parsers dédiés.

## 4. Fuite de données sensibles
- **CVEs associées**: CVE-2024-26139, CVE-2023-26114
- **Description**: Exposition de données sensibles via le stockage non sécurisé (localStorage, cookies non sécurisés) ou la mauvaise gestion des accès.
- **Versions vulnérables**: Toutes versions si le stockage et la gestion des accès ne sont pas maîtrisés.
- **Exemple de code vulnérable**:
  ```
  // Stockage de données sensibles côté client
  localStorage.setItem('token', jwtToken);
  ```
- **Correctif approprié**:
  - Ne jamais stocker d’informations sensibles dans le stockage local ou les cookies non sécurisés.
  - Utiliser `HttpOnly` pour les cookies de session.
