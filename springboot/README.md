# Quick win – Principales zones à risque d’injection en Spring Boot

## 1. Injection SQL
- **Description** : Construction de requêtes SQL en concaténant des entrées utilisateur, permettant l’injection SQL.
- **Exemple vulnérable**
  ```
  String sql = "SELECT * FROM users WHERE email = '" + email + "'";
  Statement st = conn.createStatement();
  ResultSet rs = st.executeQuery(sql);
  ```
- **Correctif approprié**
  ```
  // Avec Spring Data JPA
  @Query("SELECT u FROM User u WHERE u.email = :email")
  User findByEmail(@Param("email") String email);
  // Ou avec JDBC
  PreparedStatement ps = conn.prepareStatement("SELECT * FROM users WHERE email = ?");
  ps.setString(1, email);
  ResultSet rs = ps.executeQuery();
  ```

## 2. Injection de commandes système (RCE)
- **Description** : Exécution de commandes système avec des entrées utilisateur, menant à l’exécution de code arbitraire.
- **Exemple vulnérable**
  ```
  Runtime.getRuntime().exec(request.getParameter("cmd"));
  ```
- **Correctif approprié**
  - Ne jamais utiliser d’entrée utilisateur dans des commandes système.
  - Préférer les méthodes Java natives ou valider strictement les arguments autorisés.

## 3. XSS (Cross-Site Scripting)
- **Description** : Affichage de données utilisateur non échappées dans les vues (Thymeleaf, JSP…), permettant l’injection de scripts côté client.
- **Exemple vulnérable**
  ```
  <span th:text="${userInput}"></span>
  ```
- **Correctif approprié**
  - Utiliser l’échappement automatique de Thymeleaf ou du moteur de template.
  - Ne jamais désactiver l’échappement des variables dans les vues.

## 4. Endpoints Actuator exposés
- **Description** : Endpoints Actuator exposés sans authentification, permettant la fuite de données sensibles ou l’injection.
- **Exemple vulnérable**
  - `/actuator/env` ou `/actuator/gateway/routes` accessibles publiquement
- **Correctif approprié**
  ```
  management.endpoints.web.exposure.include=health,info
  management.endpoint.env.enabled=false
  ```
  - Protéger l’accès par authentification et firewall.

## 5. Injection XML (XXE)
- **Description** : Traitement non sécurisé de fichiers XML permettant l’injection d’entités externes (XXE).
- **Exemple vulnérable**
  ```
  DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
  DocumentBuilder db = dbf.newDocumentBuilder();
  Document doc = db.parse(uploadedXml);
  ```
- **Correctif approprié**
  ```
  dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
  dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);
  dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
  ```

## 6. Désérialisation non sécurisée
- **Description** : Désérialisation d’objets à partir de données non fiables, menant à des attaques d’exécution de code.
- **Exemple vulnérable**
  ```
  ObjectInputStream ois = new ObjectInputStream(inputStream);
  Object obj = ois.readObject();
  ```
- **Correctif approprié**
  - N’acceptez jamais des objets sérialisés non authentifiés.
  - Privilégiez des formats comme JSON avec validation stricte des schémas.

## 7. Absence de validation des entrées
- **Description** : Absence de contrôle sur le type, la longueur, le format ou la plage des données utilisateur.
- **Exemple vulnérable**
  ```
  public void setName(String name) { this.name = name; }
  ```
- **Correctif approprié**
  ```
  @NotEmpty(message = "Name cannot be empty")
  private String name;
  ```

## 8. Privilèges excessifs du compte base de données
- **Description** : Utiliser un compte DBA ou root augmente l’impact d’une injection SQL.
- **Exemple vulnérable**
  - Connexion DB avec un compte administrateur
- **Correctif approprié**
  - Utiliser un compte DB avec droits strictement nécessaires (lecture/écriture uniquement sur les tables requises).
