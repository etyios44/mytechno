## Spintg boot

- Spring Boot Security Risk Areas
  - Endpoint Exposure & Authorization
    - CVE-2025-22235
      - Description: Utilisation de `EndpointRequest.to()` sur un endpoint désactivé ou non exposé crée un matcher sur `null/**`, exposant potentiellement des chemins non protégés
      - Versions vulnérables: 2.7.x < 2.7.25, 3.1.x < 3.1.16, 3.2.x < 3.2.14, 3.3.x < 3.3.11, 3.4.x < 3.4.5
      - Exemple de code vulnérable:
        ```
        http.securityMatcher(EndpointRequest.to("nonExposedEndpoint"))
            .authorizeRequests().anyRequest().hasRole("ADMIN");
        ```
      - Correctif: Mettre à jour Spring Boot à la version corrigée ou s'assurer que les endpoints référencés sont activés et exposés[1][2]
  - Bypass d’authentification sur les méthodes
    - CVE-2025-41232
      - Description: Les annotations de sécurité sur des méthodes privées ne sont pas prises en compte, permettant un contournement de l'autorisation
      - Versions vulnérables: Spring Security avec `@EnableMethodSecurity(mode=ASPECTJ)` et `spring-security-aspects`
      - Exemple de code vulnérable:
        ```
        @PreAuthorize("hasRole('ADMIN')")
        private void sensitiveOperation() { ... }
        ```
      - Correctif: Déplacer les annotations sur des méthodes publiques ou mettre à jour Spring Security[3][4]
    - CVE-2025-22223
      - Description: Les annotations de sécurité sur des types ou méthodes paramétrés peuvent être ignorées, entraînant un contournement d'autorisation
      - Versions vulnérables: 6.4.x < 6.4.4
      - Exemple de code vulnérable:
        ```
        @PreAuthorize("hasRole('ADMIN')")
        public <T> void genericMethod(T param) { ... }
        ```
      - Correctif: Mettre à jour Spring Security à 6.4.4 ou supérieur[7]
  - Fuite de secrets via Spring Cloud Config
    - CVE-2025-22232
      - Description: Bypass d’authentification via la réutilisation du premier Vault token reçu, exposant les secrets à d’autres clients
      - Versions vulnérables: 2.2.0–2.2.8, 3.0.0–3.0.7, 3.1.0–3.1.9, 4.0.0–4.0.5, 4.1.0–4.1.5, 4.2.0
      - Exemple de code vulnérable:
        ```
        # Pas de code spécifique, vulnérabilité liée à la gestion des headers X-Config-Token
        ```
      - Correctif: Mettre à jour Spring Cloud Config à une version corrigée (≥ 3.1.12 NES) ou appliquer les mitigations proposées[5]
  - Vulnérabilité Tomcat (FileStore / DefaultServlet)
    - CVE-2025-24813
      - Description: Exploitation possible via DefaultServlet (PUT partiels) et FileStore (désérialisation de fichiers .session), menant à une exécution de code arbitraire
      - Versions vulnérables: Tomcat 10.1.24 (inclus dans Spring Boot 3.3.0)
      - Exemple de configuration vulnérable:
        ```
        server.servlet.register-default-servlet=true
        readonly=false
        <Manager className="org.apache.catalina.session.PersistentManager">
          <Store className="org.apache.catalina.session.FileStore"/>
        </Manager>
        ```
      - Correctif: Mettre à jour Tomcat/Spring Boot, désactiver la persistance de session par fichier, et ne pas exposer DefaultServlet en écriture[6]
