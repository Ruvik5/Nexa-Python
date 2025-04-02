# 🔍 MITRE ATT&CK

## 🎯 Nom de la technique : Gather Victim Org Information (T1591)
🔗 [MITRE ATT&CK - T1591](https://attack.mitre.org/techniques/T1591/)

### 📌 Sous-techniques :
- **T1591.001** - [Determine Physical Locations](https://attack.mitre.org/techniques/T1591/001/)
- **T1591.002** - [Business Relationships](https://attack.mitre.org/techniques/T1591/002/)
- **T1591.003** - [Identify Business Tempo](https://attack.mitre.org/techniques/T1591/003/)
- **T1591.004** - [Identify Roles](https://attack.mitre.org/techniques/T1591/004/)

### 🎭 Tactique : Reconnaissance

## 📝 Description

Les adversaires peuvent recueillir des informations sur l'organisation de la victime qui peuvent être utilisées lors du ciblage. Ces informations peuvent inclure une variété de détails, notamment :
- 📌 Noms des divisions/départements
- 📌 Spécificités des opérations commerciales
- 📌 Rôles et responsabilités des employés clés

Les attaquants peuvent obtenir ces données par divers moyens :
- 🎣 **Phishing d'informations** (extraction directe)
- 🌐 **Sources accessibles publiquement** (réseaux sociaux, sites web de l'organisation, bases de données ouvertes)

Cette collecte d'informations peut ensuite être exploitée pour :
- 🕵️‍♂️ **Améliorer la reconnaissance** (phishing, recherche sur les domaines exposés)
- 🎭 **Établir des ressources opérationnelles** (création ou compromission de comptes)
- 🔓 **Obtenir un accès initial** (phishing ciblé, exploitation de relations de confiance)

## 🚨 Cas Concret : Lazarus Group

Un ID bien connu du milieu : **GOO32**. Eh oui, parfois !

Le **Lazarus Group** est un acteur notoire utilisant cette technique. Exemple :
> "Le groupe Lazarus a étudié des informations disponibles publiquement sur une organisation ciblée afin d'adapter ses efforts de spear-phishing contre des départements et/ou des individus spécifiques."

💡 **Méthodologie :**
- 🎯 Utilisation de thèmes liés à la **COVID-19** dans les e-mails de spear-phishing
- 🕵️‍♂️ Ajout d'informations personnelles recueillies via des sources publiques
- 🔑 Collecte d'identifiants après un premier accès
- 🔄 Mouvement latéral au sein du réseau
- 🛡️ Contournement de la segmentation réseau en configurant un **routeur interne** comme proxy
- 📤 Exfiltration des données du réseau intranet vers un serveur distant

🌍 **Impact :** Plus d'une douzaine de pays affectés.

## 📚 Sources & Références

📰 **Google Threat Analysis Group** : [Nouvelle campagne ciblant les chercheurs en sécurité](https://blog.google/threat-analysis-group/new-campaign-targeting-security-researchers/)

📄 **Kaspersky** : [Lazarus cible l'industrie de la défense avec "Threatneedle"](https://ics-cert.kaspersky.com/media/Kaspersky-ICS-CERT-Lazarus-targets-defense-industry-with-Threatneedle-En.pdf)
📷 **Screens & Preuves** : [SecureList - Lazarus Threatneedle](https://securelist.com/lazarus-threatneedle/100803/)

## ⚠️ Conclusion

Cette technique est particulièrement difficile à contrer car elle repose sur des données **publiquement accessibles** 🏛️. Une approche quasi "open-source", combinant **dorks**, **OSINT** et autres méthodes d'investigation.

🔎 **Soyez vigilants sur votre empreinte numérique !** 🔐
