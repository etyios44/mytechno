# Quick win – Principales zones à risque de sécurité en JavaScript

## 1. Cross-Site Scripting (XSS)
- **Description** : Injection de scripts dans le DOM via des entrées utilisateur non échappées.
- **Version vulnérable** : Toutes (navigateur, Node.js, frameworks JS).
- **Exemple vulnérable**
  ```
  document.body.innerHTML = userInput;
  // userInput = "<img src=x onerror=alert(1)>"
  ```
- **Correctif approprié**
  - Toujours échapper/saniter les entrées utilisateur avant insertion dans le DOM :
    ```
    element.textContent = userInput;
    ```
  - Utiliser des librairies de templating sécurisées (ex : React, Vue, Handlebars).

## 2. Injection de code via eval, Function, setTimeout, setInterval
- **Description** : Exécution dynamique de code à partir de chaînes issues de l’utilisateur.
- **Version vulnérable** : Toutes.
- **Exemple vulnérable**
  ```
  eval(userInput);
  setTimeout(userInput, 1000);
  let f = new Function(userInput);
  ```
- **Correctif approprié**
  - Ne jamais utiliser `eval`, `Function`, `setTimeout`/`setInterval` avec du code utilisateur.
  - Préférer des alternatives sûres (JSON.parse, fonctions natives, etc.).

## 3. Injections dans les requêtes HTTP (fetch, XMLHttpRequest)
- **Description** : Construction d’URLs ou de requêtes avec des entrées utilisateur non validées, menant à des attaques SSRF, CSRF ou fuite de données.
- **Version vulnérable** : Toutes.
- **Exemple vulnérable**
  ```
  fetch("/api/" + userInput);
  ```
- **Correctif approprié**
  - Valider et filtrer les paramètres utilisés dans les URLs ou les requêtes.
  - Utiliser des listes blanches et encoder les paramètres.

## 4. Injections dans les templates (client ou serveur)
- **Description** : Utilisation de moteurs de templates non sécurisés ou de variables non échappées dans les vues.
- **Version vulnérable** : Toutes.
- **Exemple vulnérable**
  ```
  template = "<div>" + userInput + "</div>";
  ```
- **Correctif approprié**
  - Utiliser des moteurs de templates qui échappent par défaut (React, Mustache, Handlebars).
  - Toujours insérer les variables via des méthodes sûres.

## 5. Désérialisation non sécurisée (Node.js)
- **Description** : Désérialisation d’objets à partir de données non fiables, menant à l’exécution de code arbitraire.
- **Version vulnérable** : Toutes versions Node.js.
- **Exemple vulnérable**
  ```
  let obj = eval("(" + userInput + ")");
  ```
- **Correctif approprié**
  - Utiliser `JSON.parse` sur des données validées :
    ```
    let obj = JSON.parse(userInput);
    ```

## 6. Stockage local non sécurisé (localStorage, sessionStorage, cookies)
- **Description** : Stockage de données sensibles en clair côté client, exposé au XSS.
- **Version vulnérable** : Toutes.
- **Exemple vulnérable**
  ```
  localStorage.setItem("token", userToken);
  ```
- **Correctif approprié**
  - Ne jamais stocker d’informations sensibles côté client.
  - Utiliser des cookies HTTPOnly/Secure pour les tokens.

## 7. Absence de Content Security Policy (CSP)
- **Description** : L’absence de CSP permet l’exécution de scripts injectés même si le code JS est protégé.
- **Version vulnérable** : Toutes.
- **Exemple vulnérable**
  - Aucun header CSP défini.
- **Correctif approprié**
  - Définir une politique CSP restrictive :
    ```
    Content-Security-Policy: default-src 'self'; script-src 'self'
    ```
