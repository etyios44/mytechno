# Principales zones à risque de sécurité dans .NET (Quick Win)

## 1. Exécution de code à distance (RCE)
- **CVEs associées**: CVE-2024-30105, CVE-2024-35264, CVE-2024-38081, CVE-2020-0603, CVE-2020-0605, CVE-2020-0606
- **Description**: Vulnérabilités permettant à un attaquant d’exécuter du code arbitraire via des objets malveillants, fichiers spécialement conçus ou mauvaise gestion de la mémoire.
- **Versions vulnérables**:
  - .NET 8.0 < 8.0.7
  - ASP.NET Core 9.0.2 et versions antérieures, 8.0.13 et antérieures, 2.3.0 et antérieures
  - .NET Framework 2.0 SP2 < 2.0.50727.8977, 3.0 SP2 < 2.0.50727.8977, 3.5/4.7.2 < 10.0.10240.20710, 4.8 < 4.8.4739.04, etc.[1][6]
- **Exemple de code vulnérable**:
  ```
  // Exemple générique : désérialisation sans validation
  var obj = JsonConvert.DeserializeObject(userInput);
  ```
  - Si `userInput` est contrôlé par l’attaquant, il peut injecter un objet malveillant.
- **Correctif approprié**:
  - Mettre à jour .NET/.NET Core/.NET Framework vers la dernière version corrigée[1][6].
  - Ne jamais désérialiser des données non fiables sans validation stricte.
  - Appliquer les correctifs de sécurité Microsoft dès publication.

## 2. Élévation de privilèges (EoP)
- **CVEs associées**: CVE-2025-24070, CVE-2014-0253, CVE-2014-0257
- **Description**: Failles permettant à un attaquant d’obtenir des privilèges supérieurs, souvent via une mauvaise gestion de l’authentification ou des sessions.
- **Versions vulnérables**:
  - ASP.NET Core 9.0.2 et versions antérieures, 8.0.13 et antérieures, 2.3.0 et antérieures, .NET 6 avec ASP.NET Core Identity[5]
  - .NET Framework 1.0 SP3, 2.0 SP2, 3.5, 3.5.1, 4, 4.5, 4.5.1[7]
- **Exemple de code vulnérable**:
  ```
  // Utilisation incorrecte de RefreshSignInAsync
  await signInManager.RefreshSignInAsync(anotherUser);
  ```
  - Un attaquant peut usurper l’identité d’un autre utilisateur si la validation est insuffisante.
- **Correctif approprié**:
  - Mettre à jour ASP.NET Core et .NET Framework.
  - Vérifier que RefreshSignInAsync ne peut être appelée que pour l’utilisateur authentifié[5].

## 3. Déni de service (DoS)
- **CVEs associées**: CVE-2024-21312, CVE-2024-43484, CVE-2014-0295
- **Description**: Vulnérabilités permettant à un attaquant de provoquer un crash ou une saturation du service, souvent via des requêtes ou des fichiers malveillants.
- **Versions vulnérables**:
  - .NET Framework 2.0 SP2, 3.5, 3.5.1, 4, 4.5, 4.5.1[7]
  - .NET Framework versions antérieures à celles corrigées en 2024[3][4]
- **Exemple de code vulnérable**:
  ```
  // Traitement sans limitation de taille
  var data = await Request.Body.ReadAsync(buffer, 0, buffer.Length);
  ```
  - Un attaquant peut envoyer un flux massif et saturer la mémoire.
- **Correctif approprié**:
  - Mettre à jour avec les correctifs Microsoft.
  - Implémenter des limites de taille et des contrôles sur les entrées utilisateur[3][4].

## 4. Atteinte à la confidentialité des données
- **CVEs associées**: CVE-2015-1648
- **Description**: Fuite de données sensibles via une mauvaise gestion des accès ou des failles dans le framework.
- **Versions vulnérables**:
  - .NET Framework 1.1 SP1, 2.0 SP2, 3.5, 3.5.1, 4.5, 4.5.1, 4.5.2[8]
- **Exemple de code vulnérable**:
  ```
  // Mauvaise gestion des droits d'accès
  var secret = File.ReadAllText("C:\\SensitiveData\\secret.txt");
  ```
  - Si l’accès n’est pas restreint, un attaquant peut lire des fichiers sensibles.
- **Correctif approprié**:
  - Mettre à jour .NET Framework.
  - Restreindre les accès aux fichiers et ressources sensibles[8].
