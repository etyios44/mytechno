# Sécurité Java : Injection SQL

## 1. Version Java ou JDBC obsolète
- Utiliser une version ancienne expose à des failles connues
  - ❌ Utilisation d’une vieille JVM ou d’un driver JDBC non maintenu
  - ✅ Mettre à jour Java et JDBC dès qu’un correctif de sécurité est publié

## 2. Requêtes SQL dynamiques (concaténation)
- Concaténer des chaînes avec des entrées utilisateur permet l’injection SQL
  - ❌
    ```
    String sql = "SELECT * FROM users WHERE id = " + request.getParameter("id");
    Statement st = con.createStatement();
    ResultSet rs = st.executeQuery(sql);
    ```
  - ✅
    ```
    PreparedStatement ps = con.prepareStatement("SELECT * FROM users WHERE id = ?");
    ps.setInt(1, Integer.parseInt(request.getParameter("id")));
    ResultSet rs = ps.executeQuery();
    ```

## 3. Absence de validation des entrées utilisateur
- Accepter des entrées sans contrôle de type ou de format
  - ❌
    ```
    String id = request.getParameter("id");
    ```
  - ✅
    ```
    int id = Integer.parseInt(request.getParameter("id"));
    // ou valider avec une regex ou une liste blanche
    ```

## 4. Utilisation de Statement au lieu de PreparedStatement
- `Statement` ne protège pas contre l’injection SQL
  - ❌
    ```
    Statement st = con.createStatement();
    st.execute("DELETE FROM users WHERE name = '" + name + "'");
    ```
  - ✅
    ```
    PreparedStatement ps = con.prepareStatement("DELETE FROM users WHERE name = ?");
    ps.setString(1, name);
    ps.execute();
    ```

## 5. Absence de validation par liste blanche
- Ne pas restreindre les valeurs attendues augmente le risque
  - ❌
    ```
    String role = request.getParameter("role");
    ```
  - ✅
    ```
    String role = request.getParameter("role");
    if (!role.matches("admin|user|guest")) {
        throw new IllegalArgumentException();
    }
    ```

## 6. Privilèges excessifs du compte base de données
- Un compte DB trop permissif aggrave l’impact d’une injection
  - ❌ Connexion avec un compte DBA
  - ✅ Utiliser un compte avec des droits strictement nécessaires (lecture seule si possible)

## 7. Utilisation d’ORM sans précaution
- Même avec un ORM, la concaténation dans les requêtes reste dangereuse
  - ❌
    ```
    session.createQuery("from User where name = '" + name + "'");
    ```
  - ✅
    ```
    session.createQuery("from User where name = :name").setParameter("name", name);
    ```

## 8. Procédures stockées non paramétrées
- Les procédures stockées utilisant la concaténation sont vulnérables
  - ❌
    ```
    CallableStatement cs = con.prepareCall("CALL getUser('" + userInput + "')");
    ```
  - ✅
    ```
    CallableStatement cs = con.prepareCall("CALL getUser(?)");
    cs.setString(1, userInput);
    ```
