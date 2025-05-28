# Principales zones à risque de sécurité dans Java (Quick Win)

## 1. Exécution de code arbitraire à distance (RCE)
- **CVEs associées**: CVE-2024-54508, CVE-2024-54502, CVE-2024-47544, CVE-2025-24150, CVE-2025-24813
- **Description**: Failles permettant à un attaquant d’exécuter du code arbitraire à distance, souvent via la désérialisation non sécurisée d’objets ou des vulnérabilités dans le serveur d’application.
- **Versions vulnérables**:
  - Java SE 8, 11, 17, 21, 24 (certaines mises à jour)
  - Tomcat 9, 10, 11 (certaines versions)
- **Exemple de code vulnérable**:
  ```
  // Désérialisation d’un objet non fiable
  ObjectInputStream in = new ObjectInputStream(request.getInputStream());
  Object obj = in.readObject();
  ```
- **Correctif approprié**:
  - Mettre à jour Java SE, Tomcat et toutes les dépendances à la dernière version corrigée.
  - Éviter la désérialisation d’objets non fiables.
  - Désactiver la fonctionnalité d’écriture du servlet par défaut Tomcat si non utilisée.

## 2. Déni de service (DoS)
- **CVEs associées**: CVE-2024-47545, CVE-2024-54505, CVE-2024-44187
- **Description**: Vulnérabilités permettant à un attaquant de provoquer un crash ou une saturation de la JVM ou du serveur via des entrées spécialement conçues.
- **Versions vulnérables**:
  - Java SE 8, 11, 17, 21, 24 (certaines mises à jour)
- **Exemple de code vulnérable**:
  ```
  // Traitement sans limitation de taille
  byte[] data = new byte[request.getContentLength()];
  request.getInputStream().read(data);
  ```
- **Correctif approprié**:
  - Mettre à jour Java SE.
  - Implémenter des contrôles de taille et de validation sur toutes les entrées utilisateur.

## 3. Atteinte à la confidentialité des données
- **CVEs associées**: CVE-2024-47546, CVE-2024-44244, CVE-2025-0509, CVE-2025-21502
- **Description**: Fuites d’informations sensibles via des failles dans la gestion des accès, des erreurs de configuration ou des vulnérabilités dans la JVM.
- **Versions vulnérables**:
  - Java SE 8, 11, 17, 21, 24 (certaines mises à jour)
- **Exemple de code vulnérable**:
  ```
  // Accès non restreint à des fichiers sensibles
  String secret = new String(Files.readAllBytes(Paths.get("/etc/passwd")));
  ```
- **Correctif approprié**:
  - Mettre à jour Java SE.
  - Restreindre les accès aux fichiers et ressources sensibles.
  - Appliquer le principe du moindre privilège.

## 4. Atteinte à l’intégrité des données
- **CVEs associées**: CVE-2024-47597, CVE-2025-24162, CVE-2025-21587
- **Description**: Possibilité pour un attaquant de modifier ou de corrompre des données, souvent via des failles dans la gestion des sessions ou des accès concurrents.
- **Versions vulnérables**:
  - Java SE 8, 11, 17, 21, 24 (certaines mises à jour)
- **Exemple de code vulnérable**:
  ```
  // Mauvaise gestion de la synchronisation
  public class Counter {
      private int count = 0;
      public void increment() { count++; }
  }
  ```
- **Correctif approprié**:
  - Mettre à jour Java SE.
  - Utiliser des structures thread-safe ou synchroniser l’accès aux ressources critiques.

