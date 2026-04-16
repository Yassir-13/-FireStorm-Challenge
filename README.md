# Firestorm

**Auteur :** Yassir Nacir 
**Categorie :** Mobile / Android Reverse Engineering  
**Difficulte :** Medium  
**Flag :** `PWNSEC{C0ngr4ts_Th4t_w45_4N_345y_P4$$w0rd_t0_G3t!!!_0R_!5_!t???}`

---

## Description

L'application **Firestorm** (`com.pwnsec.firestorm`) est un APK Android challenge propose par PwnSec. L'objectif est de recuperer un flag stocke dans une base de donnees Firebase, protege derriere une authentification dont le mot de passe est construit dynamiquement a l'execution.

---

## Outils utilises

| Outil | Usage |
|---|---|
| **jadx / apktool** | Decompilation de l'APK |
| **Frida 17.9.1** | Dynamic instrumentation (hooking Java) |
| **Android Emulator (AVD 5554)** | Execution de l'APK |
| **Python + pyrebase** | Connexion Firebase & recuperation du flag |
| **ADB** | Communication avec l'emulateur |

---

## Etape 1 — Analyse statique de l'APK

### 1.1 Decompilation

On decompile l'APK avec **jadx** (ou apktool) pour inspecter le code source Java et les ressources.

L'application au lancement affiche un fond d'ecran avec le meme "Always has been" — indice que tout est deja en place, il faut juste le trouver.

![Screenshot_2026-04-14_183445](Screenshot_2026-04-14_183445.png)

### 1.2 Inspection du Manifest

Dans `AndroidManifest.xml`, on identifie l'activite principale :

![Screenshot_2026-04-15_143931](Screenshot_2026-04-15_143931.png)

```xml
<activity
    android:name="com.pwnsec.firestorm.MainActivity"
    android:exported="true">
    <intent-filter>
        <action android:name="android.intent.action.MAIN"/>
        <category android:name="android.intent.category.LAUNCHER"/>
    </intent-filter>
</activity>
```

**Point cle :** `android:exported="true"` — l'activite est accessible directement, ce qui facilite l'instrumentation Frida.

### 1.3 Ressources strings.xml

Dans les ressources decompilees, on trouve les identifiants Firebase directement exposes :

![Screenshot_2026-04-15_144425](Screenshot_2026-04-15_144425.png)

```xml
<string name="google_api_key">AIzaSyAXsK0qsx4RuLSA9C8IPSWd0eQ67HVHuJY</string>
<string name="google_app_id">1:692664198166:android:505d0780d7d630846dc137</string>
<string name="google_crash_reporting_api_key">AIzaSyAXsK0qsx4RuLSA9C8IPSWd0eQ67HVHuJY</string>
```

On releve egalement plusieurs strings nommees de maniere suggestive :

```
R.string.Friday_Night
R.string.Author
R.string.JustRandomString
R.string.URL
R.string.IDKMaybethepasswordpassowrd
R.string.Token
```

### 1.4 Analyse de la methode Password()

Dans `MainActivity`, on trouve la methode suivante :

![Screenshot_2026-04-15_143940](Screenshot_2026-04-15_143940.png)

```java
public String Password() {
    StringBuilder sb = new StringBuilder();
    String string  = getString(R.string.Friday_Night);
    String string2 = getString(R.string.Author);
    String string3 = getString(R.string.JustRandomString);
    String string4 = getString(R.string.URL);
    String string5 = getString(R.string.IDKMaybethepasswordpassowrd);
    String string6 = getString(R.string.Token);

    sb.append(string.substring(5, 9));
    sb.append(string4.substring(1, 6));
    sb.append(string2.substring(2, 6));
    sb.append(string5.substring(5, 8));
    sb.append(string3);
    sb.append(string6.substring(18, 26));

    return generateRandomString(String.valueOf(sb));
}

public native String generateRandomString(String str);
```

**Observations :**
- Le mot de passe est construit en concatenant des sous-chaines de plusieurs strings.
- Il est ensuite passe a une methode native (`generateRandomString`) chargee depuis une librairie `.so`.
- Il est impossible de reconstituer le mot de passe par analyse statique seule sans evaluer les valeurs reelles des strings et la logique native.

---

## Etape 2 — Instrumentation dynamique avec Frida

### 2.1 Objectif

Plutot que de reverser la librairie native, on appelle directement `Password()` depuis une instance vivante de `MainActivity` via Frida.

### 2.2 Script Frida (frida_firestorm.js)

![Screenshot_2026-04-15_144035](Screenshot_2026-04-15_144035.png)

```javascript
Java.perform(function() {

    function getPassword() {
        console.log("[*] Debut de la recherche d'instances de MainActivity...");

        Java.choose('com.pwnsec.firestorm.MainActivity', {

            onMatch: function(instance) {
                console.log("[+] MainActivity instance trouvee : " + instance);

                try {
                    var pass = instance.Password();
                    console.log("[+] Mot de passe Firebase genere : " + pass);
                } catch (e) {
                    console.log("[-] Erreur lors de l'appel de Password() : " + e);
                }
            },

            onComplete: function() {
                console.log("[*] Recherche des instances terminee.");
            }
        });
    }

    console.log("[*] Script charge. Attente de 3 secondes avant execution...");
    setTimeout(getPassword, 3000);
});
```

### 2.3 Execution

![Screenshot_2026-04-15_144057](Screenshot_2026-04-15_144057.png)

```bash
frida -U -f com.pwnsec.firestorm -l frida_firestorm.js
```

### 2.4 Resultat

```
Connected to Android Emulator 5554 (id=emulator-5554)
Spawned `com.pwnsec.firestorm`. Resuming main thread!
[*] Script charge. Attente de 3 secondes avant execution...
[*] Debut de la recherche d'instances de MainActivity...
[+] MainActivity instance trouvee : com.pwnsec.firestorm.MainActivity@73a629e
[+] Mot de passe Firebase genere : C7_dotpsC7t7f_._In_i.IdttpaofoaIIdIdnndIfC
[*] Recherche des instances terminee.
```

Mot de passe recupere : `C7_dotpsC7t7f_._In_i.IdttpaofoaIIdIdnndIfC`

---

## Etape 3 — Connexion Firebase & recuperation du flag

### 3.1 Script Python (get_flag.py)

![Screenshot_2026-04-15_144211](Screenshot_2026-04-15_144211.png)

```python
import pyrebase

config = {
    "apiKey": "AIzaSyAXsK0qsx4RuLSA9C8IPSWd0eQ67HVHuJY",
    "authDomain": "firestorm-9d3db.firebaseapp.com",
    "databaseURL": "https://firestorm-9d3db-default-rtdb.firebaseio.com",
    "storageBucket": "firestorm-9d3db.appspot.com",
    "projectId": "firestorm-9d3db"
}

firebase = pyrebase.initialize_app(config)
auth = firebase.auth()

email    = "TK757567@pwnsec.xyz"
password = "C7_dotpsC7t7f_._In_i.IdttpaofoaIIdIdnndIfC"

user = auth.sign_in_with_email_and_password(email, password)
print("Connexion reussie. Token obtenu.")

db = firebase.database()

flag_data = db.get(user['idToken'])
print("FLAG recupere :")
print(flag_data.val())
```

### 3.2 Execution et flag

![Screenshot_2026-04-15_144220](Screenshot_2026-04-15_144220.png)

---

## Flag

```
PWNSEC{C0ngr4ts_Th4t_w45_4N_345y_P4$$w0rd_t0_G3t!!!_0R_!5_!t???}
```

---

## Resume de la chaine d'exploitation

```
APK Decompilation
       |
       v
Analyse AndroidManifest.xml   -->  Identification de MainActivity
       |
       v
Analyse strings.xml            -->  Credentials Firebase + noms des strings
       |
       v
Analyse methode Password()     -->  Logique de construction du mot de passe
       |                            (substring concatenation + native method)
       v
Frida Dynamic Instrumentation  -->  Appel direct de Password() sur instance live
       |                            --> mot de passe : C7_dotpsC7t7f_._In_i.IdttpaofoaIIdIdnndIfC
       v
pyrebase Firebase Auth         -->  sign_in_with_email_and_password()
       |
       v
Firebase Realtime Database     -->  db.get(idToken) --> FLAG
```

---

## Points cles

- La methode native `generateRandomString` rend l'analyse purement statique insuffisante — Frida est la solution elegante.
- Le timeout de 3 secondes dans le script Frida est crucial : il laisse le temps a la librairie `.so` d'etre chargee avant d'appeler `Password()`.
- `Java.choose()` parcourt le heap JVM pour trouver une instance vivante de la classe, sans avoir a hooker le constructeur.
- Les credentials Firebase etaient directement accessibles dans les ressources de l'APK sans aucune obfuscation.
