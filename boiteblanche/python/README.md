# Principales zones à risque de sécurité dans Python (Quick Win)

## 1. Exécution de code à distance (RCE)
- **CVEs associées**: CVE-2024-0450, CVE-2023-24329, CVE-2023-40217
- **Description**: Failles permettant à un attaquant d’exécuter du code arbitraire, souvent via l’utilisation dangereuse de fonctions comme `eval`, `exec`, ou la désérialisation non sécurisée.
- **Versions vulnérables**: 
  - Python 3.7.x < 3.7.17
  - Python 3.8.x < 3.8.17
  - Python 3.9.x < 3.9.17
  - Python 3.10.x < 3.10.12
  - Python 3.11.x < 3.11.4
- **Exemple de code vulnérable**:
  ```
  # Utilisation dangereuse d'eval sur une entrée utilisateur
  user_input = request.args.get("expr")
  result = eval(user_input)
  ```
- **Correctif approprié**:
  - Mettre à jour Python vers la dernière version corrigée.
  - Ne jamais utiliser `eval` ou `exec` sur des données non fiables.
  - Privilégier des alternatives sûres comme `ast.literal_eval` pour évaluer des expressions simples.

## 2. Désérialisation non sécurisée
- **Description**: Utilisation de modules comme `pickle` ou `yaml.load` sur des données non maîtrisées, menant à l’exécution de code arbitraire.
- **Versions vulnérables**: Toutes versions si le code utilise `pickle` ou `yaml.load` sur des entrées non fiables.
- **Exemple de code vulnérable**:
  ```
  import pickle
  data = pickle.loads(user_input)
  ```
- **Correctif approprié**:
  - Ne jamais désérialiser des données non fiables avec `pickle` ou `yaml.load`.
  - Utiliser des alternatives sûres (`json`, `yaml.safe_load`).

## 3. Injection de commandes système
- **Description**: Passage de données non filtrées à des fonctions comme `os.system`, `subprocess`, ou `popen`, permettant l’exécution de commandes arbitraires.
- **Versions vulnérables**: Toutes versions si le code utilise ces fonctions sans validation.
- **Exemple de code vulnérable**:
  ```
  import os
  os.system("ping " + user_input)
  ```
- **Correctif approprié**:
  - Toujours valider et filtrer les entrées utilisateur.
  - Privilégier l’utilisation de listes d’arguments avec `subprocess.run` et éviter `shell=True`.

## 4. Fuite de données sensibles
- **Description**: Fuites d’informations via des erreurs de configuration, l’affichage de variables d’environnement ou la mauvaise gestion des logs.
- **Versions vulnérables**: Toutes versions si la gestion des erreurs ou des logs n’est pas maîtrisée.
- **Exemple de code vulnérable**:
  ```
  import traceback
  try:
      # code
  except Exception as e:
      print(traceback.format_exc())
  ```
- **Correctif approprié**:
  - Ne jamais afficher de traces complètes ou de variables sensibles en production.
  - Configurer les logs pour masquer les données critiques.

## 5. Déni de service (DoS)
- **Description**: Vulnérabilités permettant à un attaquant de provoquer une saturation mémoire ou CPU, par exemple via des regex non sécurisées ou des boucles infinies.
- **Versions vulnérables**: Toutes versions si le code n’est pas protégé.
- **Exemple de code vulnérable**:
  ```
  import re
  re.match(user_input, "A" * 1000000)
  ```
- **Correctif approprié**:
  - Limiter la taille des entrées utilisateur.
  - Utiliser des regex sûres et éviter les patterns susceptibles de provoquer du backtracking excessif.

