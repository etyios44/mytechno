# Quick win – Principales zones à risque de sécurité en AngularJS

## 1. Cross-Site Scripting (XSS) via templates
- **Description** : Injection de scripts malicieux dans les vues via des expressions Angular non échappées.
- **Version vulnérable** : Toutes, surtout < 1.6.0.
- **Exemple vulnérable**
  ```
  <div ng-bind-html="userInput"></div>
  // userInput = '<img src=x onerror=alert(1)>'
  ```
- **Correctif approprié**
  - Utiliser `ng-bind` ou l’échappement automatique :
    ```
    <div>{{ userInput }}</div>
    ```
  - N’utiliser `$sce.trustAsHtml` que sur du contenu validé/sûr.
  - Mettre à jour AngularJS vers la dernière version 1.x.

## 2. Exécution de code arbitraire via $eval/$parse
- **Description** : Utilisation de `$eval` ou `$parse` sur des entrées utilisateur, permettant l’exécution de code arbitraire.
- **Version vulnérable** : Toutes, surtout < 1.6.x.
- **Exemple vulnérable**
  ```
  $scope.userExpression = $location.search().exp;
  $scope.result = $scope.$eval($scope.userExpression);
  // ?exp=alert(1)
  ```
- **Correctif approprié**
  - Ne jamais utiliser `$eval` ou `$parse` sur des données utilisateur.
  - Restreindre les expressions autorisées par une validation stricte.

## 3. Inclusion de templates non filtrés (ng-include)
- **Description** : Inclusion dynamique de templates via des URLs contrôlées par l’utilisateur.
- **Version vulnérable** : Toutes.
- **Exemple vulnérable**
  ```
  <div ng-include="templateUrl"></div>
  // templateUrl = 'http://malicious.site/evil.html'
  ```
- **Correctif approprié**
  - Restreindre les URLs autorisées via `$sceDelegateProvider.resourceUrlWhitelist`.
  - Ne jamais laisser l’utilisateur choisir librement l’URL d’un template.

## 4. Filtres personnalisés non sécurisés
- **Description** : Création de filtres AngularJS qui n’échappent pas la sortie, permettant l’injection HTML/JS.
- **Version vulnérable** : Toutes.
- **Exemple vulnérable**
  ```
  app.filter('unsafe', function($sce) {
    return function(val) { return $sce.trustAsHtml(val); };
  });
  <div ng-bind-html="userInput | unsafe"></div>
  ```
- **Correctif approprié**
  - Toujours échapper les sorties de filtres personnalisés.
  - Utiliser `$sce.trustAsHtml` uniquement sur du contenu validé.

## 5. Utilisation de versions AngularJS obsolètes
- **Description** : Versions non maintenues exposées à des failles XSS et sandbox bypass.
- **Version vulnérable** : < 1.7.x (fin de support officiel en 2022).
- **Exemple vulnérable**
  - Utilisation de AngularJS 1.2.x, 1.3.x, 1.4.x, etc.
- **Correctif approprié**
  - Mettre à jour vers AngularJS 1.8.x ou migrer vers Angular moderne.
  - Appliquer les correctifs de sécurité publiés.

## 6. Absence de Content Security Policy (CSP)
- **Description** : L’absence de CSP permet l’exécution de scripts injectés même si AngularJS filtre certaines attaques.
- **Version vulnérable** : Toutes.
- **Exemple vulnérable**
  - Aucune politique CSP définie dans les headers HTTP.
- **Correctif approprié**
  - Définir une politique CSP restrictive :
    ```
    Content-Security-Policy: default-src 'self'; script-src 'self'
    ```

## 7. Manque de validation côté client
- **Description** : Absence de validation des entrées utilisateur dans les formulaires ou lors de la manipulation de données.
- **Version vulnérable** : Toutes.
- **Exemple vulnérable**
  ```
  <input ng-model="userInput">
  // Aucun contrôle sur le format ou la longueur
  ```
- **Correctif approprié**
  - Utiliser les directives de validation AngularJS (`ng-pattern`, `ng-minlength`, etc.).
  - Valider également côté serveur.
