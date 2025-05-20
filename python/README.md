# Principales zones à risque de sécurité en Django – Quick wins

## Injection SQL
- CVE associées : CVE-2019-19844, CVE-2019-14234, CVE-2019-14235
- Description : Entrées utilisateur insérées directement dans des requêtes SQL, permettant à un attaquant de manipuler ou d’extraire des données.
- Version vulnérable : Toutes versions utilisant des requêtes SQL brutes sans paramétrage.
- Exemple de code vulnérable :
    - ```
      from django.db import connection
      cursor = connection.cursor()
      cursor.execute(f"SELECT * FROM users WHERE username = '{user_input}'")
      ```
- Correctif approprié :
    - Utiliser des requêtes paramétrées :
      ```
      cursor.execute("SELECT * FROM users WHERE username = %s", [user_input])
      ```
    - Privilégier l’ORM Django pour éviter l’injection SQL.

## XSS (Cross-Site Scripting)
- CVE associées : CVE-2022-34265, CVE-2021-33203, CVE-2021-35042
- Description : Affichage de données utilisateur non filtrées dans les templates, permettant l’injection de scripts malveillants.
- Version vulnérable : Toutes versions affichant des données non échappées dans les templates ou utilisant `mark_safe` sans contrôle.
- Exemple de code vulnérable :
    - ```
      {{ user_input|safe }}
      ```
- Correctif approprié :
    - Ne pas utiliser `safe` sur des données utilisateur.
    - Laisser Django échapper automatiquement les variables :
      ```
      {{ user_input }}
      ```

## CSRF (Cross-Site Request Forgery)
- CVE associées : CVE-2015-8213, CVE-2018-14574
- Description : Exploitation de la confiance d’un site envers le navigateur de l’utilisateur pour exécuter des actions non autorisées.
- Version vulnérable : Toutes versions de Django sans protection CSRF sur les vues POST.
- Exemple de code vulnérable :
    - Formulaire sans token CSRF :
      ```
      <form method="post">
        <!-- pas de {% csrf_token %} -->
      </form>
      ```
- Correctif approprié :
    - Toujours inclure `{% csrf_token %}` dans les formulaires POST :
      ```
      <form method="post">
        {% csrf_token %}
        ...
      </form>
      ```
    - Utiliser le décorateur `@csrf_protect` sur les vues sensibles.

## Path Traversal
- CVE associées : CVE-2019-14232, CVE-2019-14233
- Description : Utilisation d’entrées utilisateur pour accéder à des fichiers arbitraires, pouvant entraîner la divulgation ou la modification de données sensibles.
- Version vulnérable : Toutes versions manipulant des chemins de fichiers à partir d’entrées utilisateur sans validation.
- Exemple de code vulnérable :
    - ```
      with open('uploads/' + user_input, 'r') as f:
          data = f.read()
      ```
- Correctif approprié :
    - Valider et restreindre les chemins :
      ```
      import os
      safe_name = os.path.basename(user_input)
      with open(os.path.join('uploads', safe_name), 'r') as f:
          data = f.read()
      ```

## Désérialisation non sécurisée (pickle, YAML)
- CVE associées : CVE-2017-12794, CVE-2018-14574
- Description : Utilisation de `pickle` ou de `yaml.load` sur des entrées non fiables, permettant l’exécution de code arbitraire.
- Version vulnérable : Toutes versions utilisant `pickle.loads()` ou `yaml.load()` sur des données non sûres.
- Exemple de code vulnérable :
    - ```
      import pickle
      data = pickle.loads(user_input)
      ```
- Correctif approprié :
    - Éviter `pickle` pour les données non fiables, préférer `json` ou `yaml.safe_load` :
      ```
      import json
      data = json.loads(user_input)
      ```
      ou
      ```
      import yaml
      data = yaml.safe_load(user_input)
      ```
---

# Principales zones à risque de sécurité en Flask – Quick wins

## Open Redirect (Redirection non sécurisée)
- CVE associées : CVE-2023-49438, CVE-2021-23385, CVE-2020-28724
- Description : Un attaquant peut rediriger un utilisateur vers un site malveillant en manipulant le paramètre `next` sur les routes /login ou /register.
- Version vulnérable : Flask-Security-Too ≤ 5.3.2, Flask-Security (non maintenu), werkzeug < 0.11.6
- Exemple de code vulnérable :
    - ```
      @app.route('/login')
      def login():
          next_url = request.args.get('next')
          return redirect(next_url or url_for('index'))
      ```
- Correctif approprié :
    - Valider que le paramètre `next` est une URL interne ou relative :
      ```
      from urllib.parse import urlparse, urljoin

      def is_safe_url(target):
          ref_url = urlparse(request.host_url)
          test_url = urlparse(urljoin(request.host_url, target))
          return test_url.scheme in ('http', 'https') and ref_url.netloc == test_url.netloc

      @app.route('/login')
      def login():
          next_url = request.args.get('next')
          if not is_safe_url(next_url):
              next_url = url_for('index')
          return redirect(next_url)
      ```
    - Utiliser une version corrigée de Flask-Security-Too (≥ 5.4)[2][3][4][6][8][9].

## Déni de service via JSON malformé
- CVE associée : CVE-2018-1000656
- Description : Une vérification insuffisante des arguments JSON peut provoquer un déni de service si des données JSON malformées sont envoyées.
- Version vulnérable : Flask 0.12.3 et certains produits dérivés utilisant cette version.
- Exemple de code vulnérable :
    - ```
      @app.route('/api', methods=['POST'])
      def api():
          data = request.get_json(force=True)
          # Traitement sans gestion d’erreur
      ```
- Correctif approprié :
    - Toujours valider et gérer les erreurs lors du parsing JSON :
      ```
      @app.route('/api', methods=['POST'])
      def api():
          try:
              data = request.get_json(force=True)
          except Exception:
              abort(400)
      ```
    - Mettre à jour Flask vers une version corrigée[1].

## Log Injection (Flask-CORS)
- CVE associée : CVE-2024-1681
- Description : Un attaquant peut injecter des séquences spéciales dans les logs (CRLF injection) via des requêtes spécialement forgées, ce qui peut compromettre l'intégrité des journaux.
- Version vulnérable : Flask-CORS avant la version corrigée (vérifier la version selon le contexte d’utilisation).
- Exemple de code vulnérable :
    - ```
      from flask_cors import CORS
      app = Flask(__name__)
      CORS(app)
      # Aucun contrôle sur les logs en mode debug
      ```
- Correctif approprié :
    - Mettre à jour Flask-CORS vers une version corrigée.
    - Éviter d’activer le mode debug en production et filtrer les entrées utilisateur dans les logs[5].

## CSRF (Cross-Site Request Forgery)
- CVE associées : (voir Flask-Security-Too changelog, vulnérabilités sur /login et qrcode)
- Description : Absence de protection CSRF sur les formulaires POST, permettant à un attaquant de forger des requêtes au nom de la victime.
- Version vulnérable : Applications Flask sans extension CSRF ou avec une configuration incorrecte.
- Exemple de code vulnérable :
    - ```
      @app.route('/update', methods=['POST'])
      def update():
          # Traitement sans vérification CSRF
      ```
- Correctif approprié :
    - Utiliser Flask-WTF et ajouter le champ CSRF dans les formulaires :
      ```
      from flask_wtf import FlaskForm
      class MyForm(FlaskForm):
          ...
      ```
    - Vérifier que la clé secrète est bien configurée et que le token CSRF est inclus dans chaque formulaire[4].

## Path Traversal
- CVE associées : (non spécifiques à Flask mais courantes dans les applications web)
- Description : Utilisation d’entrées utilisateur pour accéder à des fichiers arbitraires, pouvant entraîner la divulgation ou la modification de données sensibles.
- Version vulnérable : Toutes versions manipulant des chemins de fichiers à partir d’entrées utilisateur sans validation.
- Exemple de code vulnérable :
    - ```
      @app.route('/files')
      def files():
          filename = request.args.get('file')
          with open('uploads/' + filename) as f:
              return f.read()
      ```
- Correctif approprié :
    - Valider et restreindre les chemins :
      ```
      import os
      filename = os.path.basename(request.args.get('file'))
      with open(os.path.join('uploads', filename)) as f:
          return f.read()
      ```
