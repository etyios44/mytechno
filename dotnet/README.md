# Principales zones à risque de sécurité en .NET – Quick wins

## Injection SQL
- Description : Entrées utilisateur non filtrées utilisées dans des requêtes SQL, permettant à un attaquant de manipuler ou d’extraire des données sensibles.
- Version vulnérable : Toutes versions .NET utilisant des requêtes SQL dynamiques sans paramétrage.
- Exemple de code vulnérable :
    - ```
      var query = $"SELECT * FROM Users WHERE Name = '{userInput}'";
      var cmd = new SqlCommand(query, connection);
      ```
- Correctif approprié :
    - Utiliser des requêtes paramétrées :
      ```
      var cmd = new SqlCommand("SELECT * FROM Users WHERE Name = @name", connection);
      cmd.Parameters.AddWithValue("@name", userInput);
      ```

## XSS (Cross-Site Scripting)
- Description : Inclusion de données non fiables dans une page web sans validation/échappement, permettant l’injection de scripts malveillants.
- Version vulnérable : Toutes versions d’applications web .NET affichant des données utilisateur sans encodage.
- Exemple de code vulnérable :
    - ```
      <div>@Model.UserComment</div>
      ```
- Correctif approprié :
    - Encoder systématiquement les sorties :
      ```
      <div>@Html.Encode(Model.UserComment)</div>
      ```

## CSRF (Cross-Site Request Forgery)
- Description : Exploitation de la confiance d’un site envers le navigateur de l’utilisateur pour exécuter des actions non autorisées.
- Version vulnérable : Toutes versions d’applications web .NET sans protection anti-CSRF.
- Exemple de code vulnérable :
    - Formulaire sans token anti-CSRF :
      ```
      <form action="/Account/Update" method="post">
        <!-- pas de token -->
      </form>
      ```
- Correctif approprié :
    - Utiliser les tokens anti-CSRF de .NET :
      ```
      @Html.AntiForgeryToken()
      ```

## Path Traversal (Injection de chemin de fichier)
- Description : Utilisation d’entrées utilisateur pour accéder à des fichiers arbitraires, pouvant entraîner la divulgation ou la modification de données sensibles.
- Version vulnérable : Toutes versions .NET manipulant des chemins de fichiers à partir d’entrées utilisateur sans validation.
- Exemple de code vulnérable :
    - ```
      var filePath = "uploads/" + userInput;
      System.IO.File.ReadAllText(filePath);
      ```
- Correctif approprié :
    - Valider et restreindre les chemins :
      ```
      var safeFileName = Path.GetFileName(userInput);
      var filePath = Path.Combine("uploads", safeFileName);
      ```

## Élévation de privilèges via RefreshSignInAsync
- Description : Faible validation dans la méthode `RefreshSignInAsync` d’ASP.NET Core, permettant à un attaquant de s’authentifier en tant qu’un autre utilisateur.
- Versions vulnérables :
    - ASP.NET Core 9.0.2 et antérieures
    - ASP.NET Core 8.0.13 et antérieures
    - ASP.NET Core 2.3.0 et antérieures
    - .NET 6 utilisant ASP.NET Core Identity
- Exemple de code vulnérable :
    - ```
      await signInManager.RefreshSignInAsync(otherUser);
      ```
- Correctif approprié :
    - Mettre à jour vers la version corrigée d’ASP.NET Core (>= 9.0.3, >= 8.0.14)
    - Vérifier que `RefreshSignInAsync` n’est appelé que pour l’utilisateur authentifié :
      ```
      await signInManager.RefreshSignInAsync(User);
      ```
