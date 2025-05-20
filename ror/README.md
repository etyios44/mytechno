# Quick win – Principales zones à risque de sécurité en Ruby on Rails (RoR)

## 1. Injection SQL
- **Description** : Construction de requêtes SQL en interpolant des entrées utilisateur, permettant l’injection SQL.
- **Version vulnérable** : Toutes, surtout avant Rails 4.
- **Exemple vulnérable**
  ```
  User.where("email = '#{params[:email]}'").first
  ```
- **Correctif approprié**
  - Utiliser les requêtes paramétrées d’ActiveRecord :
    ```
    User.where(email: params[:email]).first
    ```

## 2. Cross-Site Scripting (XSS)
- **Description** : Affichage de données utilisateur non échappées dans les vues, permettant l’injection de scripts.
- **Version vulnérable** : Toutes.
- **Exemple vulnérable**
  ```
  <%= params[:user_input] %>
  ```
- **Correctif approprié**
  - Utiliser l’échappement automatique de Rails :
    ```
    <%= h(params[:user_input]) %>
    ```
  - Ou laisser Rails échapper par défaut (sauf si `raw` ou `html_safe` est utilisé).

## 3. Injection de commandes système
- **Description** : Utilisation de méthodes système (`system`, ```
- **Version vulnérable** : Toutes.
- **Exemple vulnérable**
  ```
  system("ls #{params[:dir]}")
  ```
- **Correctif approprié**
  - Ne jamais passer d’entrée utilisateur à des commandes système.
  - Si nécessaire, valider et échapper avec `Shellwords.escape`.

## 4. Désérialisation non sécurisée (YAML, Marshal)
- **Description** : Désérialisation de données non fiables, menant à l’exécution de code arbitraire.
- **Version vulnérable** : Toutes.
- **Exemple vulnérable**
  ```
  YAML.load(params[:data])
  ```
- **Correctif approprié**
  - Utiliser `YAML.safe_load` pour parser uniquement des classes autorisées :
    ```
    YAML.safe_load(params[:data])
    ```

## 5. Mass Assignment (attributs non protégés)
- **Description** : Mise à jour de plusieurs attributs via des paramètres non filtrés, menant à la modification de champs sensibles.
- **Version vulnérable** : Avant Rails 4 (protection par `attr_accessible`).
- **Exemple vulnérable**
  ```
  User.new(params[:user])
  ```
- **Correctif approprié**
  - Utiliser le strong parameters :
    ```
    User.new(params.require(:user).permit(:email, :name))
    ```

## 6. CSRF (Cross-Site Request Forgery)
- **Description** : Absence de protection CSRF dans les formulaires ou les requêtes AJAX.
- **Version vulnérable** : Toutes si la protection CSRF est désactivée.
- **Exemple vulnérable**
  - Formulaire sans jeton CSRF :
    ```
    <form action="/users" method="post">
    ```
- **Correctif approprié**
  - Utiliser les helpers Rails pour les formulaires :
    ```
    <%= form_for @user do |f| %>
    ```
  - Vérifier que la protection CSRF est activée dans `ApplicationController`.

## 7. Absence de Content Security Policy (CSP)
- **Description** : L’absence de CSP permet l’exécution de scripts injectés même si le code est protégé côté serveur.
- **Version vulnérable** : Toutes.
- **Exemple vulnérable**
  - Aucun header CSP défini.
- **Correctif approprié**
  - Définir une politique CSP dans `config/initializers/content_security_policy.rb` :
    ```
    Rails.application.config.content_security_policy do |policy|
      policy.default_src :self
      policy.script_src :self
    end
    ```
