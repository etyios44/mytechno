# Principales zones à risque de sécurité dans PHP (Quick Win)

## 1. Exécution de code à distance (RCE)
- **CVEs associées**: CVE-2024-4577, CVE-2025-1217, CVE-2024-11235, CVE-2025-1736, CVE-2025-1734, CVE-2025-1861, CVE-2025-1219
- **Description**: Failles permettant à un attaquant d’exécuter des commandes ou du code arbitraire sur le serveur via des requêtes spécialement conçues, souvent en exploitant des conversions de caractères, des paramètres non filtrés ou des fonctions dangereuses.
- **Versions vulnérables**:
  - PHP 8.1.x < 8.1.32
  - PHP 8.2.x < 8.2.28
  - PHP 8.3.x < 8.3.19
  - PHP 8.4.x < 8.4.5
- **Exemple de code vulnérable**:
  ```
  // Utilisation non sécurisée de paramètres dans une commande système
  $output = shell_exec($_GET['cmd']);
  ```
- **Correctif approprié**:
  - Mettre à jour PHP vers la dernière version corrigée.
  - Ne jamais passer de paramètres utilisateurs à des fonctions système sans validation stricte.
  - Désactiver les fonctions dangereuses (`shell_exec`, `system`, etc.) si non nécessaires.

## 2. Déni de service (DoS)
- **Description**: Vulnérabilités permettant à un attaquant de saturer les ressources du serveur, de provoquer un crash ou une indisponibilité via des requêtes volumineuses ou malveillantes.
- **Versions vulnérables**: 
  - PHP 8.1.x < 8.1.32
  - PHP 8.2.x < 8.2.28
  - PHP 8.3.x < 8.3.19
  - PHP 8.4.x < 8.4.5
- **Exemple de code vulnérable**:
  ```
  // Traitement sans limitation de taille
  $data = file_get_contents('php://input');
  ```
- **Correctif approprié**:
  - Mettre à jour PHP.
  - Limiter la taille des requêtes et des fichiers uploadés (paramètres `post_max_size`, `upload_max_filesize`).
  - Implémenter des contrôles sur les entrées utilisateur.

## 3. Atteinte à la confidentialité des données
- **Description**: Fuites d’informations sensibles via des erreurs de configuration, des variables d’environnement exposées, ou une mauvaise gestion des accès.
- **Versions vulnérables**: 
  - PHP 8.1.x < 8.1.32
  - PHP 8.2.x < 8.2.28
  - PHP 8.3.x < 8.3.19
  - PHP 8.4.x < 8.4.5
- **Exemple de code vulnérable**:
  ```
  // Affichage d'informations sensibles en cas d'erreur
  ini_set('display_errors', 1);
  ```
- **Correctif approprié**:
  - Mettre à jour PHP.
  - Désactiver l’affichage des erreurs en production (`display_errors = Off`).
  - Restreindre l’accès aux fichiers de configuration et aux logs.

## 4. Contournement de la politique de sécurité
- **Description**: Failles permettant à un attaquant de contourner les mécanismes d’authentification ou d’autorisation, souvent via des sessions mal gérées ou des contrôles d’accès insuffisants.
- **Versions vulnérables**: 
  - PHP 8.1.x < 8.1.32
  - PHP 8.2.x < 8.2.28
  - PHP 8.3.x < 8.3.19
  - PHP 8.4.x < 8.4.5
- **Exemple de code vulnérable**:
  ```
  // Session non sécurisée
  session_start();
  // Pas de validation de l'utilisateur authentifié
  ```
- **Correctif approprié**:
  - Mettre à jour PHP.
  - Régénérer l’identifiant de session lors d’actions critiques.
  - Utiliser les flags `HttpOnly` et `Secure` pour les cookies de session.
  - Restreindre l’accès aux pages sensibles aux utilisateurs authentifiés.

