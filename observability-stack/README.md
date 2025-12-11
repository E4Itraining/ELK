# Stack d'Observabilite ELK Complete

Une architecture d'observabilite production-ready basee sur Elasticsearch 8.x, Prometheus, Grafana et OpenTelemetry.

## Architecture

```
                                    ┌─────────────┐
                                    │   GRAFANA   │
                                    │   :3000     │
                                    └──────┬──────┘
                                           │
            ┌──────────────────────────────┼──────────────────────────────┐
            │                              │                              │
            ▼                              ▼                              ▼
    ┌───────────────┐           ┌───────────────┐              ┌───────────────┐
    │  PROMETHEUS   │           │ ELASTICSEARCH │              │    KIBANA     │
    │    :9090      │           │  (3 noeuds)   │              │    :5601      │
    └───────┬───────┘           └───────────────┘              └───────────────┘
            │                           ▲
            │                           │
    ┌───────┴───────────────────────────┴───────────────────┐
    │                                                       │
    ▼                       ▼                       ▼       │
┌─────────┐          ┌───────────┐          ┌───────────┐   │
│ES Export│          │ Blackbox  │          │   OTEL    │   │
│ :9114   │          │  :9115    │          │ Collector │   │
└─────────┘          └───────────┘          └───────────┘   │
                                                            │
                                                            ▼
                                               ┌───────────────┐
                                               │ ALERTMANAGER  │
                                               │    :9093      │
                                               └───────────────┘
```

## Composants

| Composant | Version | Port | Description |
|-----------|---------|------|-------------|
| Elasticsearch | 8.11.0 | 9200-9202 | Cluster 3 noeuds (stockage logs/metriques) |
| Kibana | 8.11.0 | 5601 | Interface d'exploration des logs |
| Prometheus | 2.47.0 | 9090 | Collecte et stockage des metriques |
| Alertmanager | 0.27.0 | 9093 | Gestion et routage des alertes |
| Grafana | 10.2.0 | 3000 | Dashboards et visualisation |
| ES Exporter | 1.6.0 | 9114 | Export metriques ES vers Prometheus |
| Blackbox Exporter | 0.24.0 | 9115 | Probes HTTP/TCP/ICMP |
| OTEL Collector | 0.88.0 | 4317/4318 | Collecte OTLP (metriques/traces/logs) |

## Demarrage Rapide

### Prerequisites

- Docker >= 20.10
- Docker Compose >= 2.0
- 8 GB RAM minimum recommande
- Linux: `sudo sysctl -w vm.max_map_count=262144`

### Installation

```bash
# Cloner le repo
cd observability-stack

# Copier et configurer l'environnement
cp .env.example .env
# Editer .env avec vos mots de passe

# Demarrer la stack
docker compose up -d

# Verifier les services
docker compose ps
```

### Acces aux Interfaces

| Interface | URL | Credentials |
|-----------|-----|-------------|
| Grafana | http://localhost:3000 | admin / admin |
| Kibana | http://localhost:5601 | elastic / (voir .env) |
| Prometheus | http://localhost:9090 | - |
| Alertmanager | http://localhost:9093 | - |

### Injection de Logs de Test

```bash
# Lancer l'injecteur de logs (10 logs/sec par defaut)
docker compose --profile inject up -d log-injector

# Ou avec un taux specifique
docker compose run --rm -e INJECTION_RATE=100 log-injector
```

## Structure du Projet

```
observability-stack/
├── docker-compose.yml          # Orchestration des services
├── .env.example                # Variables d'environnement
├── docs/
│   └── ARCHITECTURE.md         # Documentation complete
├── prometheus/
│   ├── prometheus.yml          # Configuration Prometheus
│   └── rules/
│       ├── recording_rules.yml # Rules de pre-calcul
│       └── alert_rules.yml     # Rules d'alertes
├── alertmanager/
│   └── alertmanager.yml        # Routes et receivers
├── grafana/
│   ├── provisioning/
│   │   ├── datasources/        # Datasources auto-provisionnes
│   │   └── dashboards/         # Config provisioning dashboards
│   └── dashboards/
│       ├── elasticsearch/      # Dashboards ES
│       ├── observability/      # Dashboards stack
│       └── slo/                # Dashboards SLO
├── blackbox/
│   └── blackbox.yml            # Configuration des probes
├── otel/
│   └── otel-collector-config.yml  # Pipeline OTEL
└── log-injector/
    ├── Dockerfile
    ├── requirements.txt
    └── log_injector.py         # Script d'injection
```

## Dashboards Inclus

1. **Elasticsearch Overview** - Sante cluster, performance, JVM
2. **Stack Overview** - Statut de tous les composants
3. **SLO Dashboard** - Objectifs de niveau de service

## Alertes Configurees

### Elasticsearch
- `ElasticsearchClusterRed` - Cluster en etat critique
- `ElasticsearchClusterYellow` - Replicas manquants
- `ElasticsearchHeapUsageHigh` - Memoire JVM > 85%
- `ElasticsearchDiskSpaceLow` - Disque > 80%
- `ElasticsearchUnassignedShards` - Shards non assignes

### Blackbox
- `EndpointDown` - Service indisponible
- `EndpointSlowResponse` - Latence > 5s
- `SSLCertificateExpiring` - Certificat expire dans < 30j

### SLO
- `SLOBudgetBurning` - Budget d'erreur < 50%
- `SLOBudgetExhausted` - Budget d'erreur epuise

## Configuration Avancee

### Scaling

```yaml
# Ajouter un 4eme noeud ES
es04:
  image: elasticsearch:8.11.0
  environment:
    - node.name=es04
    - node.roles=data
    - discovery.seed_hosts=es01,es02,es03
```

### Alertes Slack

```yaml
# alertmanager/alertmanager.yml
receivers:
  - name: 'slack'
    slack_configs:
      - api_url: 'https://hooks.slack.com/services/xxx/yyy/zzz'
        channel: '#alerts'
```

### Retention Prometheus

```bash
# .env
PROMETHEUS_RETENTION=30d
```

## Commandes Utiles

```bash
# Logs d'un service
docker compose logs -f es01

# Sante du cluster ES
curl -k -u elastic:$ELASTIC_PASSWORD https://localhost:9200/_cluster/health?pretty

# Targets Prometheus
curl http://localhost:9090/api/v1/targets | jq

# Alertes actives
curl http://localhost:9093/api/v2/alerts | jq

# Redemarrer un service
docker compose restart prometheus

# Arreter la stack
docker compose down

# Arreter et supprimer les volumes
docker compose down -v
```

## Documentation

Pour une documentation complete, voir [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) incluant:

- Diagrammes d'architecture detailles
- Flux de donnees (logs, metriques, alertes)
- Recording rules et Alert rules
- Bonnes pratiques de securite et HA
- Roadmap d'evolution

## License

MIT License - Voir LICENSE pour plus de details.

---

**Maintenu par**: E4I Training
**Version**: 1.0.0
