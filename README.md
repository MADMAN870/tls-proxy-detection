# TLS Inspection Proxy

Proxy mobile d'inspection TLS pour l'analyse du trafic HTTPS et la détection de fuites de données.

```
Mobile Device → Proxy (mitmproxy) → Analyzer → Alert System
```

## Fonctionnalités

- **Interception TLS** — Capture et inspecte le trafic HTTPS en temps réel via mitmproxy
- **Détection de fuites** — Identifie mots de passe, clés API, cartes bancaires, JWT, SSN, emails
- **Fichiers suspects** — Détecte les téléchargements dangereux (.exe, .ps1, .zip, etc.)
- **Domaines suspects** — Alerte sur les connexions vers pastebin, IPs brutes, etc.
- **Score de risque** — Scoring pondéré configurable avec 4 niveaux de sévérité
- **Tableau de bord** — Interface web temps réel avec alertes, trafic, entités et règles
- **API REST** — API complète pour l'intégration externe avec limite de débit
- **Persistance SQLite** — Alertes et entités persistent après redémarrage
- **Authentification par clé API** — Auth optionnelle pour déploiement en production
- **Health Checks** — Docker HEALTHCHECK pour l'API et le proxy

## Démarrage rapide

```bash
# Cloner et lancer
git clone <repo-url> tls-inspection-proxy
cd tls-inspection-proxy
docker compose up -d

# Ouvrir le tableau de bord (depuis le serveur Docker)
open http://localhost:8000

# Depuis un appareil mobile, utiliser l'IP du serveur Docker
open http://192.168.11.107:8000
```

## Configuration du Proxy

### 1. Télécharger le certificat CA

```bash
curl -o mitmproxy-ca.pem http://192.168.11.107:8000/ca.pem
```

Ou téléchargez depuis la page Settings du tableau de bord.

### 2. Installer le certificat

**Linux (système):**
```bash
sudo cp mitmproxy-ca.pem /usr/local/share/ca-certificates/
sudo update-ca-certificates
```

**Brave/Chrome:**
1. Aller dans Paramètres → Sécurité → Gérer les certificats
2. Cliquer sur **Importer** sous l'onglet **Autorités**
3. Sélectionner le fichier `.pem`
4. Cocher **"Faire confiance à ce certificat pour l'identification des sites web"**
5. Cliquer OK

### 3. Configurer le proxy navigateur

Définir le proxy HTTP/HTTPS du navigateur sur :
- **Hôte :** 192.168.11.107
- **Port :** 8082

Ajouter `192.168.11.107` à la liste d'exclusion **Aucun proxy pour** pour que le tableau de bord fonctionne avec le proxy activé.

### 4. Naviguer sur le web

Le trafic HTTPS sera intercepté et analysé en temps réel. Les alertes apparaissent sur le tableau de bord.

## Authentification (Optionnelle)

Par défaut, l'auth est **désactivée** — le système fonctionne sans configuration.

Pour activer l'authentification par clé API :

```bash
# Générer une clé API
python -c "import secrets; print(secrets.token_hex(32))"

# Modifier config/config.yaml :
auth:
  enabled: true
  api_key: "<votre-clé-générée>"

# Redémarrer l'API
docker compose up -d --build api
```

Tous les endpoints `/api/*` nécessiteront désormais un en-tête `X-API-Key`.

## Architecture

```
                  +-----------+
                  |  Client   |
                  +-----+-----+
                        |
                  +-----v------+
                  |   Proxy    |  mitmproxy:8082
                  +-----+------+
                        |  POST /api/v1/traffic
                  +-----v------+
                  |  API /     |  FastAPI:8000
                  |  Analyzer  |  + SQLite
                  +-----+------+
                        |
              +---------+---------+
              |                   |
        +-----v-----+     +------v------+
        |  Alerts   |     |  Web UI     |
        +-----------+     +-------------+
```

## Services

| Service    | URL                     | Description                          |
|------------|-------------------------|--------------------------------------|
| Web UI     | http://localhost:8000   | Tableau de bord et visualisation     |
| Proxy      | http://localhost:8082   | mitmproxy (configurer sur l'appareil)|
| Site test  | http://localhost:9000   | Application de test LeakyBank        |

## Générer du trafic de test

```bash
docker compose --profile test run test-traffic
```

## Documentation

- **[Documentation web](http://192.168.11.107:8000/docs)** — Documentation complète type Postman (tableau de bord, API, configuration, dépannage)
- [Architecture](docs/architecture.md) — Conception système, flux de données, scoring
- [Guide d'installation](docs/setup.md) — Authentification, configuration mobile, configuration
- [Guide d'utilisation](docs/usage.md) — Interface, API, limites de débit, motifs

## Configuration

Modifier `config/config.yaml` :
- Motifs de détection (regex)
- Poids et seuils du score de risque
- Paramètres d'authentification
- Limitation de débit
- Extensions et domaines suspects

## API (Référence rapide)

```http
POST /api/v1/traffic                          # Soumettre du trafic pour analyse
GET  /api/v1/alerts?severity=&limit=          # Récupérer les alertes
POST /api/v1/alerts/{id}/acknowledge          # Acquitter une alerte
POST /api/v1/alerts/acknowledge-all           # Acquitter toutes les alertes
GET  /api/v1/stats                            # Statistiques système
POST /api/v1/clear                            # Effacer toutes les données
POST /api/v1/test/trigger-leak                # Déclencher une alerte test
GET  /health                                  # Vérification de santé
GET  /ca.pem                                  # Télécharger le certificat CA
```

## Technologies

- **mitmproxy** 10.x — Proxy d'interception TLS
- **FastAPI** — Serveur API avec validation Pydantic
- **SQLite** — Stockage persistant des alertes et entités
- **slowapi** — Middleware de limite de débit
- **Jinja2** — Rendu de templates
- **Docker** — Déploiement conteneurisé
- **Tailwind CSS** — Interface utilisateur

## Tests

```bash
docker exec tls-inspection-api pip install pytest
docker exec tls-inspection-api python -m pytest tests/ -v
```
