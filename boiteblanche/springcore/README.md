## Spring Core

- Spring Core : Principales zones à risque de sécurité
  - Désérialisation non sécurisée
    - CVE-2024-38820
      - Description : Désérialisation non sécurisée pouvant permettre une exécution de code à distance
      - Versions vulnérables : Spring Framework 5.x et 6.x (avant correctif de novembre 2024)
      - Exemple de code vulnérable :
        ```
        ObjectInputStream ois = new ObjectInputStream(inputStream);
        Object obj = ois.readObject();
        ```
      - Correctif : Ne jamais désérialiser des objets non fiables ; utiliser des formats sûrs comme JSON ou YAML avec des parseurs sécurisés[5][6]
  - Traversée de chemin (Path Traversal)
    - CVE-2024-38819
      - Description : Un attaquant peut accéder à des fichiers sensibles via des chemins manipulés
      - Versions vulnérables : 5.x et 6.x (avant correctif de 2024)
      - Exemple de code vulnérable :
        ```
        String file = request.getParameter("file");
        FileInputStream fis = new FileInputStream("/data/" + file);
        ```
      - Correctif : Valider et normaliser les chemins, interdire les séquences `../`[5]
  - Contournement d’authentification (Authentication Bypass)
    - CVE-2024-38821
      - Description : Bypass des contrôles d’accès basés sur les rôles via une mauvaise configuration
      - Versions vulnérables : 5.x et 6.x (avant correctif de 2024)
      - Exemple de code vulnérable :
        ```
        @PreAuthorize("hasRole('USER')")
        public void doAction() { ... }
        ```
        (si la configuration de sécurité est incomplète)
      - Correctif : Revue complète de la configuration de sécurité et mise à jour vers une version corrigée[5]
  - Expression SpEL non filtrée (Denial of Service)
    - CVE-2023-20863
      - Description : SpEL mal filtrée pouvant provoquer un déni de service
      - Versions vulnérables : < 5.2.24, < 5.3.27, < 6.0.8
      - Exemple de code vulnérable :
        ```
        ExpressionParser parser = new SpelExpressionParser();
        parser.parseExpression(userInput).getValue();
        ```
      - Correctif : Mettre à jour Spring Core et ne jamais parser d’input utilisateur sans filtrage[6]
  - DoS via Spring MVC / WebFlux
    - CVE-2024-22233, CVE-2023-34053
      - Description : Requêtes HTTP spécialement forgées pouvant causer un DoS
      - Versions vulnérables :
        - CVE-2024-22233 : 6.0.15, 6.1.2
        - CVE-2023-34053 : 6.0.0–6.0.13
      - Exemple de code vulnérable :
        ```
        // Aucune protection spécifique contre des requêtes volumineuses ou malformées
        ```
      - Correctif : Mettre à jour Spring Framework, limiter la taille des requêtes, activer les protections DoS[6]
  - Fuite d’information (Information Disclosure)
    - CVE-2024-38828
      - Description : Risque de fuite de données sensibles via des erreurs ou logs non filtrés
      - Versions vulnérables : 5.x et 6.x (avant correctif de 2024)
      - Exemple de code vulnérable :
        ```
        logger.error("Erreur : " + exception);
        ```
      - Correctif : Masquer les détails sensibles dans les logs et messages d’erreur[5]
