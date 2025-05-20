# Principales zones à risque de sécurité en Node.js – Quick wins

## Injection SQL
- CVE associées : CVE-2019-10758, CVE-2017-16082 (modules mysql, sequelize, etc.)
- Description : Entrées utilisateur insérées directement dans des requêtes SQL, permettant à un attaquant de manipuler ou d’extraire des données.
- Version vulnérable : Toutes versions de Node.js utilisant des requêtes SQL dynamiques sans paramétrage.
- Exemple de code vulnérable :
    - ```
      const query = `SELECT * FROM users WHERE username = '${userInput}'`;
      db.query(query, (err, result) => { ... });
      ```
- Correctif approprié :
    - Utiliser des requêtes paramétrées :
      ```
      const query = "SELECT * FROM users WHERE username = ?";
      db.query(query, [userInput], (err, result) => { ... });
      ```

## Command Injection
- CVE associées : CVE-2017-5941, CVE-2021-22960 (child_process, divers modules)
- Description : Entrées utilisateur utilisées dans des commandes système, permettant l’exécution de commandes arbitraires.
- Version vulnérable : Toutes versions de Node.js utilisant `child_process.exec` ou similaire sans validation.
- Exemple de code vulnérable :
    - ```
      const { exec } = require('child_process');
      exec('ping ' + userInput, (err, stdout, stderr) => { ... });
      ```
- Correctif approprié :
    - Utiliser `execFile` ou passer les arguments sous forme de tableau :
      ```
      const { execFile } = require('child_process');
      execFile('ping', [userInput], (err, stdout, stderr) => { ... });
      ```

## XSS (Cross-Site Scripting)
- CVE associées : CVE-2019-17495, CVE-2017-16137 (modules de templates ou frameworks)
- Description : Affichage de données utilisateur non filtrées dans des pages web, permettant l’injection de scripts malveillants.
- Version vulnérable : Toutes versions de frameworks web Node.js (Express, etc.) sans encodage des sorties.
- Exemple de code vulnérable :
    - ```
      res.send(`<div>${req.query.msg}</div>`);
      ```
- Correctif approprié :
    - Échapper les sorties ou utiliser un moteur de template sécurisé :
      ```
      res.render('comment', { msg: req.query.msg });
      // Les moteurs comme Pug/EJS échappent les variables par défaut
      ```

## Désérialisation non sécurisée (eval, JSON.parse sur données non fiables)
- CVE associées : CVE-2017-5941, CVE-2019-10744 (modules divers, vulnérabilités dans l’usage de eval/Function)
- Description : Utilisation de `eval` ou de désérialisation sur des entrées non fiables, permettant l’exécution de code arbitraire.
- Version vulnérable : Toutes versions utilisant `eval`, `Function`, ou `JSON.parse` sur des données non sûres.
- Exemple de code vulnérable :
    - ```
      eval(req.body.code);
      ```
- Correctif approprié :
    - Ne jamais utiliser `eval` sur des entrées utilisateur, préférer des parsers sûrs :
      ```
      // Éviter complètement eval
      ```

## Path Traversal
- CVE associées : CVE-2017-14849, CVE-2018-15664 (modules Express, serve-static, etc.)
- Description : Utilisation d’entrées utilisateur pour accéder à des fichiers arbitraires, pouvant entraîner la divulgation ou la modification de données sensibles.
- Version vulnérable : Toutes versions manipulant des chemins de fichiers à partir d’entrées utilisateur sans validation.
- Exemple de code vulnérable :
    - ```
      const fs = require('fs');
      fs.readFile('uploads/' + req.query.file, (err, data) => { ... });
      ```
- Correctif approprié :
    - Valider et restreindre les chemins :
      ```
      const path = require('path');
      const safeName = path.basename(req.query.file);
      fs.readFile(path.join('uploads', safeName), (err, data) => { ... });
      ```
