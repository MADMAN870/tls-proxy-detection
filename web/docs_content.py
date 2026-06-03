DOCS = {
    "getting-started": {
        "label": {"fr": "Démarrage", "en": "Getting Started"},
        "pages": {
            "overview": {"title": {"fr": "Vue d'ensemble", "en": "Overview"}, "icon": "rocket"},
            "quickstart": {"title": {"fr": "Démarrage rapide", "en": "Quick Start"}, "icon": "bolt"},
            "installation": {"title": {"fr": "Installation", "en": "Installation"}, "icon": "download"},
        }
    },
    "setup": {
        "label": {"fr": "Configuration", "en": "Setup & Configuration"},
        "pages": {
            "configuration": {"title": {"fr": "Configuration", "en": "Configuration"}, "icon": "gear"},
            "proxy-setup": {"title": {"fr": "Configuration du proxy", "en": "Proxy Setup"}, "icon": "wifi"},
            "mobile-device": {"title": {"fr": "Appareil mobile", "en": "Mobile Device"}, "icon": "mobile-screen"},
        }
    },
    "usage": {
        "label": {"fr": "Guide d'utilisation", "en": "Usage Guide"},
        "pages": {
            "dashboard": {"title": {"fr": "Tableau de bord", "en": "Dashboard"}, "icon": "gauge"},
            "alerts": {"title": {"fr": "Alertes", "en": "Alerts"}, "icon": "bell"},
            "traffic": {"title": {"fr": "Journal du trafic", "en": "Traffic Log"}, "icon": "arrow-right-arrow-left"},
            "entities": {"title": {"fr": "Entités", "en": "Entities"}, "icon": "users"},
            "rules": {"title": {"fr": "Règles de détection", "en": "Detection Rules"}, "icon": "list-check"},
        }
    },
    "api": {
        "label": {"fr": "Référence API", "en": "API Reference"},
        "pages": {
            "traffic": {"title": {"fr": "API Trafic", "en": "Traffic API"}, "icon": "code"},
            "alerts": {"title": {"fr": "API Alertes", "en": "Alerts API"}, "icon": "code"},
            "stats": {"title": {"fr": "API Statistiques", "en": "Stats API"}, "icon": "code"},
            "health": {"title": {"fr": "Santé & Système", "en": "Health & System"}, "icon": "code"},
        }
    },
    "reference": {
        "label": {"fr": "Référence", "en": "Reference"},
        "pages": {
            "config": {"title": {"fr": "Réf. configuration", "en": "Config Reference"}, "icon": "file-lines"},
            "patterns": {"title": {"fr": "Motifs de détection", "en": "Detection Patterns"}, "icon": "shield"},
        }
    },
    "troubleshooting": {
        "label": {"fr": "Dépannage", "en": "Troubleshooting"},
        "pages": {
            "common-issues": {"title": {"fr": "Problèmes courants", "en": "Common Issues"}, "icon": "bug"},
        }
    },
}

import json
from pathlib import Path

_DOCS_PATH = Path(__file__).parent / "docs_content.json"
if _DOCS_PATH.exists():
    with open(_DOCS_PATH) as f:
        DOC_CONTENT = json.load(f)
else:
    DOC_CONTENT = {}
