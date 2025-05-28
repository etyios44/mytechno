# Spring boot

- Payloads d’injection endpoints Spring Boot (boîte blanche)
  - CVE-2024-38807 (Contournement de la politique de sécurité)
    - Description : Un attaquant peut contourner la politique de sécurité et accéder à des endpoints protégés via une manipulation des requêtes HTTP.
    - Versions vulnérables : 
      - 2.7.x < 2.7.22
      - 3.0.x < 3.0.17
      - 3.1.x < 3.1.13
      - 3.2.x < 3.2.9
      - 3.3.x < 3.3.3[2][4]
    - Exemple de code vulnérable :
      ```
      @RestController
      public class AdminController {
          @GetMapping("/admin")
          public String admin() { return "admin"; }
      }
      ```
      (Endpoint censé être protégé par une configuration de sécurité)
    - Payload boîte blanche :
      - Requête HTTP manipulée :
        ```
        GET /admin HTTP/1.1
        X-Forwarded-For: 127.0.0.1
        ```
      - Permet de contourner certains contrôles d’accès mal configurés.
    - Correctif :
      - Mettre à jour Spring Boot à une version corrigée
      - Vérifier la configuration des proxies et des headers de confiance[2][4]
  - CVE-2024-38816 (Corruption mémoire)
    - Description : Corruption mémoire pouvant mener à des crashs ou à l’exécution de code.
    - Versions vulnérables : Spring Boot 2.7.x, 3.x (avant correctif 2024)
    - Exemple de code vulnérable :
      ```
      // Utilisation de composants natifs sans validation des entrées
      ```
    - Payload boîte blanche :
      - Envoyer des données malformées dans les paramètres natifs (ex : uploads binaires)
    - Correctif :
      - Mettre à jour Spring Boot à la version corrigée[4]
  - CVE-2024-38819 (Path Traversal)
    - Description : Accès non autorisé à des fichiers sensibles via la manipulation du chemin dans une requête.
    - Versions vulnérables : Spring Boot 2.7.x, 3.x (avant correctif 2024)
    - Exemple de code vulnérable :
      ```
      @GetMapping("/files")
      public byte[] getFile(@RequestParam String path) throws IOException {
          return Files.readAllBytes(Paths.get("/data/" + path));
      }
      ```
    - Payload boîte blanche :
      - Requête HTTP :
        ```
        GET /files?path=../../../../etc/passwd
        ```
      - Permet de lire des fichiers arbitraires sur le serveur.
    - Correctif :
      - Valider et normaliser les chemins utilisateurs
      - Mettre à jour Spring Boot à la version corrigée[4]
  - CVE-2024-38820 (Désérialisation non sécurisée)
    - Description : Désérialisation d’objets non fiables menant à une exécution de code arbitraire.
    - Versions vulnérables : Spring Boot 2.7.x, 3.x (avant correctif 2024)
    - Exemple de code vulnérable :
      ```
      @PostMapping("/deserialize")
      public void deserialize(@RequestBody byte[] data) throws Exception {
          ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data));
          Object obj = ois.readObject();
      }
      ```
    - Payload boîte blanche :
      - Envoyer un objet Java sérialisé malveillant dans le corps de la requête.
    - Correctif :
      - Ne jamais désérialiser d’objets non fiables
      - Mettre à jour Spring Boot à la version corrigée[4]
  - CVE-2024-38828 (Fuite d’information)
    - Description : Risque de fuite de données sensibles via des messages d’erreur ou des logs non filtrés.
    - Versions vulnérables : Spring Boot 2.7.x, 3.x (avant correctif 2024)
    - Exemple de code vulnérable :
      ```
      @ExceptionHandler(Exception.class)
      public String handle(Exception e) {
          return e.toString();
      }
      ```
    - Payload boîte blanche :
      - Provoquer une erreur avec une requête malformée pour obtenir des informations sensibles dans la réponse.
    - Correctif :
      - Masquer les détails sensibles dans les messages d’erreur
      - Mettre à jour Spring Boot à la version corrigée[4]
