# TOMCAT

- Payloads d’injection endpoints Tomcat (boîte blanche)
  - CVE-2020-1938 (Ghostcat)
    - Description : Lecture et écriture de fichiers arbitraires via le protocole AJP, permettant le déploiement d’un webshell ou l’accès à des fichiers sensibles.
    - Versions vulnérables : Tomcat 6, 7, 8, 9 (avant correctif de février 2020)
    - Exemples de code/configuration vulnérable :
      ```
      <Connector port="8009" protocol="AJP/1.3" redirectPort="8443" />
      ```
      (AJP activé sans restriction d’accès)
    - Wordlist de payloads :
      - Inclusion locale de fichiers :
        ```
        /WEB-INF/web.xml
        /META-INF/context.xml
        /etc/passwd
        ```
      - Injection de webshell via POST AJP :
        ```
        POST /;file=webshell.jsp
        ```
    - Correctif approprié :
      - Désactiver AJP ou restreindre l’accès à l’interface AJP aux IPs de confiance
      - Mettre à jour Tomcat à une version corrigée
  - CVE-2017-12617 (Upload JSP via PUT)
    - Description : Possibilité d’uploader un fichier JSP (webshell) via la méthode HTTP PUT si l’option est activée.
    - Versions vulnérables : Tomcat 7.0.0 à 7.0.81 (mode non sécurisé, PUT activé)
    - Exemples de configuration vulnérable :
      ```
      <servlet>
        <servlet-name>default</servlet-name>
        <servlet-class>org.apache.catalina.servlets.DefaultServlet</servlet-class>
        <init-param>
          <param-name>readonly</param-name>
          <param-value>false</param-value>
        </init-param>
      </servlet>
      ```
    - Wordlist de payloads :
      - Requête PUT :
        ```
        PUT /shell.jsp HTTP/1.1
        [code JSP ici]
        ```
      - Accès au shell :
        ```
        GET /shell.jsp
        ```
    - Correctif approprié :
      - Désactiver la méthode PUT sur le DefaultServlet
      - Mettre à jour Tomcat à une version corrigée
  - CVE-2020-9484 (Session Persistence File Deserialization)
    - Description : Exécution de code via désérialisation de sessions si la persistance est activée et des objets non fiables sont présents.
    - Versions vulnérables : Tomcat 7.0.0 à 7.0.104, 8.5.0 à 8.5.54, 9.0.0.M1 à 9.0.34
    - Exemples de configuration vulnérable :
      ```
      <Manager className="org.apache.catalina.session.PersistentManager">
        <Store className="org.apache.catalina.session.FileStore"/>
      </Manager>
      ```
    - Wordlist de payloads :
      - Sérialisation d’un objet malveillant dans une session, puis redémarrage du serveur pour forcer la désérialisation
    - Correctif approprié :
      - Désactiver la persistance de session par fichier
      - Mettre à jour Tomcat à une version corrigée
  - CVE-2016-8745 (Path Traversal)
    - Description : Traversée de répertoire via des chemins manipulés dans les requêtes HTTP, permettant d’accéder à des fichiers sensibles.
    - Versions vulnérables : Tomcat 7.0.0 à 7.0.72, 8.0.0.RC1 à 8.0.38, 8.5.0 à 8.5.6, 9.0.0.M1 à 9.0.0.M13
    - Exemples de code vulnérable :
      ```
      // Accès direct à des fichiers sans normalisation du chemin
      ```
    - Wordlist de payloads :
      - `GET /..;/WEB-INF/web.xml`
      - `GET /%2e%2e/WEB-INF/web.xml`
      - `GET /..%5cWEB-INF/web.xml`
    - Correctif approprié :
      - Mettre à jour Tomcat à une version corrigée
      - Toujours valider et normaliser les chemins d’accès aux fichiers
  - CVE-2023-46589 (Information Disclosure via Error Message)
    - Description : Fuite d’informations sensibles via des messages d’erreur détaillés accessibles à l’utilisateur.
    - Versions vulnérables : Tomcat 8.5.0 à 8.5.96, 9.0.0.M1 à 9.0.85, 10.1.0-M1 à 10.1.18, 11.0.0-M1 à 11.0.0-M14
    - Exemples de code vulnérable :
      ```
      // Aucune gestion personnalisée des erreurs
      ```
    - Wordlist de payloads :
      - Provoquer une erreur 500 ou 404 pour afficher des détails internes
    - Correctif approprié :
      - Personnaliser les pages d’erreur
      - Mettre à jour Tomcat à une version corrigée
