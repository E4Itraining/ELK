# AI Monitoring & Observability Platform

Plateforme complète de monitoring et d'observabilité pour les systèmes d'Intelligence Artificielle.

## Vue d'ensemble

Cette plateforme fournit un monitoring multi-dimensionnel pour les systèmes d'IA :

| Dimension | Métriques |
|-----------|-----------|
| **Technique** | Latence, throughput, erreurs, disponibilité, rate limiting |
| **Cognitive** | Qualité des réponses, hallucinations, biais, toxicité, sentiment |
| **FinOps** | Coûts tokens, budget, ROI, optimisation |
| **DevOps** | Déploiement, scaling, santé, ressources (CPU/GPU/Mémoire) |
| **Compliance** | RGPD, audit, classification données, gouvernance modèles, EU AI Act |

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    AI Monitoring Platform                        │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐          │
│  │   Technical  │  │   Cognitive  │  │    FinOps    │          │
│  │   Monitor    │  │   Monitor    │  │   Monitor    │          │
│  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘          │
│         │                 │                 │                   │
│  ┌──────┴───────┐  ┌──────┴───────┐  ┌──────┴───────┐          │
│  │    DevOps    │  │  Compliance  │  │   Alerting   │          │
│  │   Monitor    │  │   Monitor    │  │   Manager    │          │
│  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘          │
│         │                 │                 │                   │
│  ┌──────┴─────────────────┴─────────────────┴───────┐          │
│  │              Metrics Collector                    │          │
│  └──────────────────────┬────────────────────────────┘          │
│                         │                                        │
│  ┌──────────────────────┴────────────────────────────┐          │
│  │           Elasticsearch Client                     │          │
│  └──────────────────────┬────────────────────────────┘          │
│                         │                                        │
└─────────────────────────┼────────────────────────────────────────┘
                          │
                          ▼
              ┌───────────────────────┐
              │    Elasticsearch      │
              │    + Kibana           │
              └───────────────────────┘
```

## Installation

### Prérequis

- Python 3.8+
- Elasticsearch 8.x
- Kibana 8.x (optionnel, pour les dashboards)

### Installation

```bash
# Cloner le repository
cd ai-monitoring

# Installer les dépendances
pip install -r requirements.txt

# Ou installer en tant que package
pip install -e .
```

### Configuration

```bash
# Copier le fichier de configuration
cp config/settings.yaml config/settings.local.yaml

# Éditer avec vos paramètres
# - Connexion Elasticsearch
# - Clés API des providers AI
# - Configuration des alertes
```

Variables d'environnement supportées :
- `ES_PASSWORD` - Mot de passe Elasticsearch
- `ES_CA_CERTS` - Chemin vers le certificat CA
- `OPENAI_API_KEY` - Clé API OpenAI
- `ANTHROPIC_API_KEY` - Clé API Anthropic
- `SLACK_WEBHOOK_URL` - URL webhook Slack pour les alertes

## Utilisation

### CLI

```bash
# Configuration initiale (templates, indices)
python ai_monitoring.py setup

# Voir le statut
python ai_monitoring.py status

# Voir les alertes actives
python ai_monitoring.py alerts

# Voir le résumé des métriques
python ai_monitoring.py summary

# Démarrer le démon de collection
python ai_monitoring.py collect

# Mode démo avec données d'exemple
python ai_monitoring.py demo

# Mode interactif
python ai_monitoring.py interactive
```

### Intégration Python

```python
from ai_monitoring.modules import MetricsCollector, AIRequest, load_config

# Charger la configuration
config = load_config()

# Créer le collecteur
collector = MetricsCollector(config)
collector.start()

# Enregistrer une requête AI
request = AIRequest(
    request_id="req-123",
    provider="openai",
    model="gpt-4",
    prompt="Qu'est-ce que Python ?",
    response="Python est un langage de programmation...",
    input_tokens=15,
    output_tokens=150,
    latency_ms=850.0,
    team="engineering",
    project="chatbot",
)

results = collector.record(request)

# Afficher les résultats
print(f"Quality Score: {results['cognitive'].quality.overall_score}")
print(f"Cost: ${results['finops'].cost.total_cost:.4f}")
print(f"Hallucination: {results['cognitive'].hallucination.detected}")

# Arrêter proprement
collector.stop()
```

### Context Manager

```python
from ai_monitoring.modules import MetricsCollector, MonitoringContext

collector = MetricsCollector(config)

# Monitoring automatique
with MonitoringContext(collector, provider="anthropic", model="claude-3-opus") as ctx:
    ctx.set_prompt("Explique-moi la relativité")

    # Appel à l'API AI
    response = call_ai_api(prompt)

    ctx.set_response(response, input_tokens=50, output_tokens=500)
```

## Métriques Collectées

### Technical Metrics

| Métrique | Description |
|----------|-------------|
| `latency.total_ms` | Latence totale de la requête |
| `latency.time_to_first_token_ms` | Temps jusqu'au premier token (streaming) |
| `latency.inference_ms` | Temps d'inférence |
| `throughput.tokens_per_second` | Débit en tokens/seconde |
| `error.type` | Type d'erreur (network, timeout, rate_limit, etc.) |
| `rate_limit.limited` | Indicateur de rate limiting |
| `cache.hit` | Hit de cache |

### Cognitive Metrics

| Métrique | Description |
|----------|-------------|
| `quality.overall_score` | Score de qualité global (0-1) |
| `quality.relevance_score` | Pertinence de la réponse |
| `quality.coherence_score` | Cohérence de la réponse |
| `hallucination.detected` | Hallucination détectée |
| `hallucination.confidence` | Confiance de la détection |
| `bias.detected` | Biais détecté |
| `bias.categories` | Catégories de biais |
| `toxicity.detected` | Toxicité détectée |
| `toxicity.categories` | Catégories de toxicité |
| `prompt_analysis.injection_attempt` | Tentative d'injection |
| `prompt_analysis.jailbreak_attempt` | Tentative de jailbreak |

### FinOps Metrics

| Métrique | Description |
|----------|-------------|
| `tokens.input` | Nombre de tokens en entrée |
| `tokens.output` | Nombre de tokens en sortie |
| `cost.total_cost` | Coût total de la requête |
| `budget.daily_spent` | Dépenses du jour |
| `budget.budget_exceeded` | Budget dépassé |
| `roi.business_value` | Valeur business générée |
| `roi.roi_ratio` | Ratio ROI |
| `optimization.cache_savings` | Économies cache |

### DevOps Metrics

| Métrique | Description |
|----------|-------------|
| `health.status` | Statut de santé |
| `availability.uptime_percentage` | Pourcentage de disponibilité |
| `resources.cpu.usage_percent` | Utilisation CPU |
| `resources.memory.usage_percent` | Utilisation mémoire |
| `resources.gpu.usage_percent` | Utilisation GPU |
| `scaling.current_replicas` | Nombre de réplicas |
| `deployment.status` | Statut de déploiement |

### Compliance Metrics

| Métrique | Description |
|----------|-------------|
| `pii.detected` | PII détectées |
| `pii.types` | Types de PII |
| `gdpr.consent.given` | Consentement RGPD |
| `gdpr.processing_basis` | Base légale du traitement |
| `model_governance.approval_status` | Statut d'approbation du modèle |
| `ai_act.risk_category` | Catégorie de risque EU AI Act |
| `audit.action` | Action auditée |
| `data_classification.level` | Niveau de classification |

## Dashboards Kibana

Importer les dashboards :

```bash
# Via l'API Kibana
curl -X POST "localhost:5601/api/saved_objects/_import" \
  -H "kbn-xsrf: true" \
  --form file=@dashboards/ai_monitoring_dashboard.ndjson
```

Dashboards disponibles :
- **AI Monitoring Overview** - Vue globale
- **Technical Metrics** - Latence, erreurs, throughput
- **Cognitive Analysis** - Qualité, hallucinations, biais
- **FinOps Dashboard** - Coûts, budget, ROI
- **DevOps Dashboard** - Santé, ressources, déploiements
- **Compliance Dashboard** - PII, audit, gouvernance

## Alertes

### Configuration

```yaml
alerting:
  enabled: true
  channels:
    slack:
      enabled: true
      webhook_url: "${SLACK_WEBHOOK_URL}"
      channels:
        critical: "#ai-alerts-critical"
        warning: "#ai-alerts-warning"
    email:
      enabled: true
      smtp_host: "smtp.example.com"
      recipients:
        critical: ["ops@example.com"]
```

### Règles Prédéfinies

- **High Latency** - P95 latence > 5000ms
- **Critical Error Rate** - Taux d'erreur > 5%
- **Budget Exceeded** - Budget quotidien dépassé
- **Hallucination Detected** - Hallucination haute confiance
- **Compliance Violation** - Violation de conformité

## Structure du Projet

```
ai-monitoring/
├── config/
│   └── settings.yaml          # Configuration
├── modules/
│   ├── __init__.py
│   ├── config.py              # Gestion configuration
│   ├── elasticsearch_client.py # Client ES
│   ├── technical_monitor.py   # Monitoring technique
│   ├── cognitive_monitor.py   # Monitoring cognitif
│   ├── finops_monitor.py      # Monitoring FinOps
│   ├── devops_monitor.py      # Monitoring DevOps
│   ├── compliance_monitor.py  # Monitoring compliance
│   ├── metrics_collector.py   # Collecteur central
│   └── alerting.py            # Gestion des alertes
├── templates/
│   ├── technical_metrics_template.json
│   ├── cognitive_metrics_template.json
│   ├── finops_metrics_template.json
│   ├── devops_metrics_template.json
│   ├── compliance_metrics_template.json
│   └── ilm_policies.json
├── dashboards/
│   └── ai_monitoring_dashboard.ndjson
├── ai_monitoring.py           # CLI principal
├── requirements.txt
├── setup.py
└── README.md
```

## Bonnes Pratiques

### Performance

- Utiliser le batching (configurable via `collection.batch_size`)
- Activer le cache pour les requêtes similaires
- Monitorer les files d'attente (`collector.get_summary()`)

### Sécurité

- Ne jamais stocker les prompts/réponses en clair
- Activer l'anonymisation des PII
- Utiliser des hashes pour les données sensibles
- Configurer les rétentions appropriées

### Compliance

- Enregistrer les consentements RGPD
- Documenter les bases légales de traitement
- Maintenir un registre des modèles approuvés
- Implémenter le droit à l'oubli

## Contribution

1. Fork le repository
2. Créer une branche feature
3. Commit les changements
4. Push vers la branche
5. Ouvrir une Pull Request

## Licence

MIT License - voir [LICENSE](LICENSE) pour les détails.
