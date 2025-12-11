# Architecture d'Observabilité ELK - Documentation Complète

**Version**: 1.0.0
**Date**: Décembre 2024
**Auteur**: E4I Training
**Classification**: Documentation Technique Interne

---

## Table des Matières

1. [Résumé Exécutif](#1-résumé-exécutif)
2. [Architecture Globale](#2-architecture-globale)
3. [Composants et Rôles](#3-composants-et-rôles)
4. [Flux de Données](#4-flux-de-données)
5. [Collecte des Métriques](#5-collecte-des-métriques)
6. [Observabilité Enrichie](#6-observabilité-enrichie)
7. [Intégration Grafana](#7-intégration-grafana)
8. [Bonnes Pratiques d'Architecture](#8-bonnes-pratiques-darchitecture)
9. [Points d'Entrée et Exposition des Services](#9-points-dentrée-et-exposition-des-services)
10. [Risques et Mitigations](#10-risques-et-mitigations)
11. [Roadmap 3-6 Mois](#11-roadmap-3-6-mois)
12. [Limites et Évolutions](#12-limites-et-évolutions)

---

## 1. Résumé Exécutif

### En 10 Lignes

Cette architecture d'observabilité est construite autour d'un **cluster Elasticsearch 8.x à 3 nœuds** (es01, es02, es03) offrant haute disponibilité et résilience. **Prometheus** centralise la collecte des métriques via des exporters dédiés (**Elasticsearch Exporter** pour les métriques internes ES, **Blackbox Exporter** pour le monitoring HTTP). L'**OpenTelemetry Collector** enrichit le pipeline en recevant des métriques OTLP et en les exposant vers Prometheus. **Alertmanager** gère les routes d'alertes avec escalade configurable. **Grafana** fournit une visualisation unifiée avec des dashboards pré-provisionnés et des datasources multiples (Prometheus + Elasticsearch). **Kibana 8.x** complète l'écosystème pour l'exploration des logs et la gestion du cluster. L'ensemble est orchestré via **Docker Compose** pour un déploiement reproductible. La sécurité est assurée par **X-Pack** avec TLS et authentification. Un **script d'injection** permet de simuler des charges de logs réalistes pour les tests et démonstrations.

---

## 2. Architecture Globale

### 2.1 Diagramme d'Architecture ASCII

```
┌─────────────────────────────────────────────────────────────────────────────────────────────────────────┐
│                                    STACK D'OBSERVABILITÉ ELK                                            │
│                                                                                                         │
│  ┌──────────────────────────────────────────────────────────────────────────────────────────────────┐   │
│  │                              COUCHE VISUALISATION & ALERTING                                      │   │
│  │                                                                                                   │   │
│  │   ┌─────────────────────┐    ┌─────────────────────┐    ┌─────────────────────┐                  │   │
│  │   │      GRAFANA        │    │       KIBANA        │    │    ALERTMANAGER     │                  │   │
│  │   │    :3000 (HTTP)     │    │    :5601 (HTTP)     │    │    :9093 (HTTP)     │                  │   │
│  │   │                     │    │                     │    │                     │                  │   │
│  │   │ • Dashboards        │    │ • Log Explorer      │    │ • Routes d'alertes  │                  │   │
│  │   │ • Prometheus DS     │    │ • Dev Tools         │    │ • Silencing         │                  │   │
│  │   │ • Elasticsearch DS  │    │ • Index Management  │    │ • Grouping          │                  │   │
│  │   │ • Alerting          │    │ • Discover          │    │ • Webhooks/Email    │                  │   │
│  │   └─────────┬───────────┘    └──────────┬──────────┘    └──────────┬──────────┘                  │   │
│  │             │                           │                          │                             │   │
│  └─────────────┼───────────────────────────┼──────────────────────────┼─────────────────────────────┘   │
│                │                           │                          │                                 │
│  ┌─────────────┼───────────────────────────┼──────────────────────────┼─────────────────────────────┐   │
│  │             │          COUCHE COLLECTE & STOCKAGE MÉTRIQUES        │                             │   │
│  │             │                           │                          │                             │   │
│  │   ┌─────────▼───────────────────────────┼──────────────────────────▼──────────┐                  │   │
│  │   │                           PROMETHEUS                                       │                  │   │
│  │   │                          :9090 (HTTP)                                      │                  │   │
│  │   │                                                                            │                  │   │
│  │   │  • Scrape configs vers ES Exporter, Blackbox, OTEL                        │                  │   │
│  │   │  • Recording rules (SLO, agrégations)                                     │                  │   │
│  │   │  • Alert rules (cluster health, heap, latence)                            │                  │   │
│  │   │  • Stockage TSDB local (15j rétention)                                    │                  │   │
│  │   └─────────▲──────────────────▲──────────────────▲───────────────────────────┘                  │   │
│  │             │                  │                  │                                              │   │
│  └─────────────┼──────────────────┼──────────────────┼──────────────────────────────────────────────┘   │
│                │                  │                  │                                                  │
│  ┌─────────────┼──────────────────┼──────────────────┼──────────────────────────────────────────────┐   │
│  │             │    COUCHE EXPORTERS & COLLECTEURS   │                                              │   │
│  │             │                  │                  │                                              │   │
│  │   ┌─────────┴─────────┐  ┌────┴────────────┐  ┌──┴────────────────────┐                          │   │
│  │   │  ES EXPORTER      │  │ BLACKBOX        │  │   OTEL COLLECTOR      │                          │   │
│  │   │  :9114 (HTTP)     │  │ EXPORTER        │  │   :4317 (gRPC OTLP)   │                          │   │
│  │   │                   │  │ :9115 (HTTP)    │  │   :4318 (HTTP OTLP)   │                          │   │
│  │   │ • Cluster health  │  │                 │  │   :8888 (metrics)     │                          │   │
│  │   │ • Node stats      │  │ • HTTP probes   │  │                       │                          │   │
│  │   │ • Index stats     │  │ • TCP probes    │  │ • Réception OTLP      │                          │   │
│  │   │ • Shard stats     │  │ • ICMP probes   │  │ • Transformation      │                          │   │
│  │   │ • JVM metrics     │  │ • DNS probes    │  │ • Export Prometheus   │                          │   │
│  │   └─────────┬─────────┘  └────┬────────────┘  └──┬────────────────────┘                          │   │
│  │             │                 │                  │                                               │   │
│  └─────────────┼─────────────────┼──────────────────┼───────────────────────────────────────────────┘   │
│                │                 │                  │                                                   │
│  ┌─────────────┼─────────────────┼──────────────────┼───────────────────────────────────────────────┐   │
│  │             │    COUCHE STOCKAGE DONNÉES (ELASTICSEARCH CLUSTER)                                 │   │
│  │             │                 │                  │                                               │   │
│  │   ┌─────────▼─────────────────▼──────────────────▼─────────────────────────────────────────┐     │   │
│  │   │                                                                                        │     │   │
│  │   │                    ELASTICSEARCH CLUSTER (3 NŒUDS)                                     │     │   │
│  │   │                                                                                        │     │   │
│  │   │   ┌─────────────────┐   ┌─────────────────┐   ┌─────────────────┐                     │     │   │
│  │   │   │      ES01       │   │      ES02       │   │      ES03       │                     │     │   │
│  │   │   │  :9200 (HTTP)   │   │  :9201 (HTTP)   │   │  :9202 (HTTP)   │                     │     │   │
│  │   │   │  :9300 (Transport)  │  :9301 (Transport)  │  :9302 (Transport)                    │     │   │
│  │   │   │                 │   │                 │   │                 │                     │     │   │
│  │   │   │ • Master-eligible│   │ • Master-eligible│   │ • Master-eligible│                     │     │   │
│  │   │   │ • Data node     │   │ • Data node     │   │ • Data node     │                     │     │   │
│  │   │   │ • Ingest node   │   │ • Ingest node   │   │ • Ingest node   │                     │     │   │
│  │   │   └────────┬────────┘   └────────┬────────┘   └────────┬────────┘                     │     │   │
│  │   │            │                     │                     │                              │     │   │
│  │   │            └─────────────────────┴─────────────────────┘                              │     │   │
│  │   │                         Discovery & Consensus                                         │     │   │
│  │   │                              (Zen Discovery)                                          │     │   │
│  │   │                                                                                        │     │   │
│  │   │   Indices: logs-*, metrics-*, traces-*                                                │     │   │
│  │   │   ILM: Hot → Warm → Cold → Delete                                                     │     │   │
│  │   │                                                                                        │     │   │
│  │   └────────────────────────────────────────────────────────────────────────────────────────┘     │   │
│  │                                                                                                  │   │
│  └──────────────────────────────────────────────────────────────────────────────────────────────────┘   │
│                                                                                                         │
│  ┌──────────────────────────────────────────────────────────────────────────────────────────────────┐   │
│  │                                    INJECTION DE DONNÉES                                           │   │
│  │                                                                                                   │   │
│  │   ┌─────────────────────┐                                                                        │   │
│  │   │   LOG INJECTOR      │──────────────────────────────────────▶ Elasticsearch                   │   │
│  │   │   (Python Script)   │                                         (logs-*, metrics-*)            │   │
│  │   │                     │                                                                        │   │
│  │   │ • Génération logs   │                                                                        │   │
│  │   │ • Simulation trafic │                                                                        │   │
│  │   │ • Bulk indexing     │                                                                        │   │
│  │   └─────────────────────┘                                                                        │   │
│  │                                                                                                   │   │
│  └──────────────────────────────────────────────────────────────────────────────────────────────────┘   │
│                                                                                                         │
└─────────────────────────────────────────────────────────────────────────────────────────────────────────┘
```

### 2.2 Diagramme Simplifié des Flux

```
                                    ┌─────────────┐
                                    │   GRAFANA   │
                                    │   :3000     │
                                    └──────┬──────┘
                                           │ Query
            ┌──────────────────────────────┼──────────────────────────────┐
            │                              │                              │
            ▼                              ▼                              ▼
    ┌───────────────┐           ┌───────────────┐              ┌───────────────┐
    │  PROMETHEUS   │           │ ELASTICSEARCH │              │    KIBANA     │
    │    :9090      │           │  :9200-9202   │              │    :5601      │
    └───────┬───────┘           └───────────────┘              └───────────────┘
            │                           ▲
   Scrape   │                           │ Metrics
            │                           │
    ┌───────┴───────────────────────────┴───────────────────┐
    │                                                       │
    ▼                       ▼                       ▼       │
┌─────────┐          ┌───────────┐          ┌───────────┐   │
│ES Export│          │ Blackbox  │          │   OTEL    │   │
│ :9114   │          │  :9115    │          │ Collector │   │
└────┬────┘          └─────┬─────┘          └─────┬─────┘   │
     │                     │                      │         │
     │                     │                      │         │
     │                     ▼                      ▼         │
     │              HTTP Probes              OTLP Ingestion │
     │                                                      │
     └──────────────────────────────────────────────────────┘
                              │
                              ▼
                    ┌───────────────┐
                    │ ALERTMANAGER  │
                    │    :9093      │
                    └───────────────┘
                              │
                              ▼
                    Slack / Email / Webhook
```

---

## 3. Composants et Rôles

### 3.1 Cluster Elasticsearch (es01, es02, es03)

| Attribut | Valeur |
|----------|--------|
| **Version** | 8.x |
| **Rôle** | Master-eligible + Data + Ingest |
| **Ports HTTP** | 9200, 9201, 9202 |
| **Ports Transport** | 9300, 9301, 9302 |
| **Heap Size** | 512MB - 2GB (configurable) |
| **Découverte** | Zen Discovery (seed hosts) |

**Responsabilités** :
- Stockage persistant des logs, métriques et traces
- Indexation en temps réel avec ILM (Index Lifecycle Management)
- Réplication des données (1 réplica par défaut)
- Recherche full-text et agrégations
- Gestion de la haute disponibilité du cluster

**Configuration clé** :
```yaml
cluster.name: observability-cluster
node.roles: [master, data, ingest]
discovery.seed_hosts: ["es01", "es02", "es03"]
cluster.initial_master_nodes: ["es01", "es02", "es03"]
xpack.security.enabled: true
xpack.security.transport.ssl.enabled: true
```

### 3.2 Kibana

| Attribut | Valeur |
|----------|--------|
| **Version** | 8.x |
| **Port** | 5601 |
| **Backend** | Elasticsearch cluster |

**Responsabilités** :
- Interface utilisateur pour l'exploration des logs (Discover)
- Création de visualisations et dashboards
- Gestion du cluster (Stack Management)
- Console Dev Tools pour requêtes ES
- Gestion des index patterns et ILM

### 3.3 Prometheus

| Attribut | Valeur |
|----------|--------|
| **Version** | 2.x |
| **Port** | 9090 |
| **Rétention** | 15 jours (configurable) |
| **Stockage** | TSDB local |

**Responsabilités** :
- Collecte des métriques via pull (scrape)
- Stockage time-series optimisé
- Évaluation des recording rules
- Évaluation des alerting rules
- Service discovery des targets

### 3.4 Alertmanager

| Attribut | Valeur |
|----------|--------|
| **Version** | 0.27.x |
| **Port** | 9093 |

**Responsabilités** :
- Réception des alertes depuis Prometheus
- Déduplication des alertes
- Groupement intelligent (par cluster, severity)
- Routage vers les canaux appropriés
- Silencing et inhibition
- Intégration Slack, Email, Webhook, PagerDuty

### 3.5 Grafana

| Attribut | Valeur |
|----------|--------|
| **Version** | 10.x |
| **Port** | 3000 |
| **Auth** | admin/admin (défaut) |

**Responsabilités** :
- Visualisation unifiée des métriques et logs
- Dashboards pré-provisionnés
- Support multi-datasources
- Alerting natif (complémentaire à Alertmanager)
- Exploration ad-hoc des données

**Datasources configurées** :
1. **Prometheus** - Métriques système et applicatives
2. **Elasticsearch** - Logs et traces

### 3.6 Elasticsearch Exporter

| Attribut | Valeur |
|----------|--------|
| **Image** | prometheuscommunity/elasticsearch-exporter |
| **Port** | 9114 |

**Métriques exposées** :
- `elasticsearch_cluster_health_status` - État du cluster (green/yellow/red)
- `elasticsearch_cluster_health_number_of_nodes` - Nombre de nœuds
- `elasticsearch_cluster_health_number_of_data_nodes` - Nœuds data
- `elasticsearch_cluster_health_active_shards` - Shards actifs
- `elasticsearch_cluster_health_relocating_shards` - Shards en relocation
- `elasticsearch_cluster_health_unassigned_shards` - Shards non assignés
- `elasticsearch_jvm_memory_used_bytes` - Mémoire JVM utilisée
- `elasticsearch_jvm_memory_max_bytes` - Mémoire JVM max
- `elasticsearch_jvm_gc_collection_seconds_count` - Compteur GC
- `elasticsearch_indices_indexing_index_total` - Total documents indexés
- `elasticsearch_indices_search_query_total` - Total requêtes search
- `elasticsearch_indices_search_query_time_seconds` - Temps de recherche

### 3.7 Blackbox Exporter

| Attribut | Valeur |
|----------|--------|
| **Image** | prom/blackbox-exporter |
| **Port** | 9115 |

**Probes configurés** :
- **HTTP** - Vérification des endpoints (Kibana, ES API)
- **TCP** - Vérification des ports ouverts
- **ICMP** - Ping des hôtes (si privilégié)

**Métriques exposées** :
- `probe_success` - Succès de la probe (0/1)
- `probe_duration_seconds` - Durée de la probe
- `probe_http_status_code` - Code HTTP retourné
- `probe_http_ssl_earliest_cert_expiry` - Expiration certificat SSL
- `probe_http_content_length` - Taille de la réponse

### 3.8 OpenTelemetry Collector

| Attribut | Valeur |
|----------|--------|
| **Image** | otel/opentelemetry-collector-contrib |
| **Ports** | 4317 (gRPC), 4318 (HTTP), 8888 (metrics) |

**Responsabilités** :
- Réception des métriques via OTLP (gRPC et HTTP)
- Transformation et enrichissement des métriques
- Export vers Prometheus (via remote write ou scrape)
- Centralisation des traces (futur Tempo/Jaeger)
- Batching et retry intelligent

**Pipeline configuré** :
```
receivers (OTLP) → processors (batch, memory_limiter) → exporters (prometheus)
```

### 3.9 Script d'Injection de Logs

| Attribut | Valeur |
|----------|--------|
| **Langage** | Python 3.x |
| **Dépendances** | elasticsearch-py, faker |

**Fonctionnalités** :
- Génération de logs réalistes (niveaux INFO, WARN, ERROR)
- Simulation de trafic applicatif
- Bulk indexing optimisé
- Configuration du débit (logs/seconde)
- Support des index patterns temporels

---

## 4. Flux de Données

### 4.1 Flux des Logs

```
┌─────────────────┐    Bulk Index    ┌─────────────────┐    Index    ┌─────────────────┐
│  Log Injector   │ ──────────────▶  │  Elasticsearch  │ ─────────▶ │  logs-YYYY.MM   │
│  (Python)       │    JSON/NDJSON   │    Cluster      │            │  (Index Pattern)│
└─────────────────┘                  └─────────────────┘            └─────────────────┘
                                              │
                                              │ Query (KQL/Lucene)
                                              ▼
                                     ┌─────────────────┐
                                     │     Kibana      │
                                     │   (Discover)    │
                                     └─────────────────┘
```

### 4.2 Flux des Métriques

```
┌─────────────────┐                  ┌─────────────────┐
│  Elasticsearch  │                  │    Prometheus   │
│    Cluster      │◀──── Scrape ─────│                 │
└─────────────────┘                  └────────┬────────┘
        │                                     │
        │ Connect                             │ Scrape
        ▼                                     │
┌─────────────────┐                           │
│  ES Exporter    │◀──────────────────────────┤
│    :9114        │                           │
└─────────────────┘                           │
                                              │
┌─────────────────┐                           │
│ Blackbox Export │◀──────────────────────────┤
│    :9115        │                           │
└─────────────────┘                           │
                                              │
┌─────────────────┐                           │
│ OTEL Collector  │◀──────────────────────────┤
│    :8888        │                           │
└─────────────────┘                           │
                                              ▼
                                     ┌─────────────────┐
                                     │     Grafana     │
                                     │  (Dashboards)   │
                                     └─────────────────┘
```

### 4.3 Flux des Alertes

```
┌─────────────────┐    Evaluate     ┌─────────────────┐    Send      ┌─────────────────┐
│   Prometheus    │ ─────────────▶  │  Alertmanager   │ ──────────▶  │   Slack/Email   │
│  (Alert Rules)  │    firing       │  (Routes)       │   notify     │   /Webhook      │
└─────────────────┘                 └─────────────────┘              └─────────────────┘
                                            │
                                            │ Silence/Inhibit
                                            ▼
                                    ┌─────────────────┐
                                    │  Alert History  │
                                    │   (State DB)    │
                                    └─────────────────┘
```

---

## 5. Collecte des Métriques

### 5.1 Qui Scrape Qui ?

| Source | Cible | Port | Intervalle | Métriques Clés |
|--------|-------|------|------------|----------------|
| Prometheus | ES Exporter | 9114 | 15s | cluster_health, jvm, indices |
| Prometheus | Blackbox Exporter | 9115 | 30s | probe_success, http_status |
| Prometheus | OTEL Collector | 8888 | 15s | otelcol_receiver, otelcol_exporter |
| Prometheus | Prometheus (self) | 9090 | 15s | prometheus_* |
| Prometheus | Alertmanager | 9093 | 15s | alertmanager_* |

### 5.2 Configuration Prometheus (scrape_configs)

```yaml
scrape_configs:
  # Elasticsearch Exporter
  - job_name: 'elasticsearch'
    static_configs:
      - targets: ['elasticsearch-exporter:9114']
    scrape_interval: 15s
    metrics_path: /metrics

  # Blackbox Exporter - HTTP Probes
  - job_name: 'blackbox-http'
    metrics_path: /probe
    params:
      module: [http_2xx]
    static_configs:
      - targets:
        - http://es01:9200/_cluster/health
        - http://es02:9200/_cluster/health
        - http://es03:9200/_cluster/health
        - http://kibana:5601/api/status
    relabel_configs:
      - source_labels: [__address__]
        target_label: __param_target
      - source_labels: [__param_target]
        target_label: instance
      - target_label: __address__
        replacement: blackbox-exporter:9115

  # OpenTelemetry Collector
  - job_name: 'otel-collector'
    static_configs:
      - targets: ['otel-collector:8888']
    scrape_interval: 15s

  # Self-monitoring
  - job_name: 'prometheus'
    static_configs:
      - targets: ['localhost:9090']
```

### 5.3 Comment les Exporters Exposent les Métriques

#### Elasticsearch Exporter

L'exporter se connecte au cluster ES via l'API REST et transforme les réponses JSON en format Prometheus :

```
GET /_cluster/health → elasticsearch_cluster_health_*
GET /_nodes/stats   → elasticsearch_jvm_*, elasticsearch_indices_*
GET /_cat/indices   → elasticsearch_indices_docs_count, etc.
```

#### Blackbox Exporter

Le Blackbox effectue des probes actives et génère des métriques :

```
Request HTTP → Timing + Status Code → probe_http_duration_seconds
                                    → probe_http_status_code
                                    → probe_success
```

#### OpenTelemetry Collector

L'OTEL Collector expose ses propres métriques internes :

```
otelcol_receiver_accepted_metric_points    - Métriques reçues
otelcol_receiver_refused_metric_points     - Métriques refusées
otelcol_exporter_sent_metric_points        - Métriques exportées
otelcol_processor_batch_batch_send_size    - Taille des batches
```

### 5.4 Enrichissement par OTEL Collector

```yaml
processors:
  batch:
    send_batch_size: 10000
    timeout: 10s

  memory_limiter:
    check_interval: 1s
    limit_mib: 512
    spike_limit_mib: 128

  attributes:
    actions:
      - key: environment
        value: production
        action: upsert
      - key: cluster
        value: observability-cluster
        action: upsert

  resource:
    attributes:
      - key: service.namespace
        value: elk-observability
        action: upsert
```

---

## 6. Observabilité Enrichie

### 6.1 Recording Rules

Les recording rules pré-calculent des métriques complexes pour améliorer les performances des requêtes.

```yaml
groups:
  - name: elasticsearch_recording_rules
    interval: 30s
    rules:
      # SLO - Disponibilité du cluster
      - record: elasticsearch:cluster_availability:ratio
        expr: |
          sum(elasticsearch_cluster_health_status == 1)
          / count(elasticsearch_cluster_health_status)

      # Latence moyenne de recherche (5min)
      - record: elasticsearch:search_latency:avg_5m
        expr: |
          rate(elasticsearch_indices_search_query_time_seconds_total[5m])
          / rate(elasticsearch_indices_search_query_total[5m])

      # Taux d'indexation par seconde
      - record: elasticsearch:indexing_rate:per_second
        expr: |
          sum(rate(elasticsearch_indices_indexing_index_total[5m]))

      # Utilisation heap JVM (%)
      - record: elasticsearch:jvm_heap_usage:ratio
        expr: |
          elasticsearch_jvm_memory_used_bytes{area="heap"}
          / elasticsearch_jvm_memory_max_bytes{area="heap"}

      # Capacité disque utilisée
      - record: elasticsearch:disk_usage:ratio
        expr: |
          1 - (elasticsearch_filesystem_data_free_bytes
               / elasticsearch_filesystem_data_size_bytes)

  - name: slo_recording_rules
    interval: 1m
    rules:
      # SLO Budget - 99.9% disponibilité
      - record: slo:elasticsearch_availability:budget_remaining
        expr: |
          1 - (
            (1 - avg_over_time(elasticsearch:cluster_availability:ratio[30d]))
            / (1 - 0.999)
          )

      # SLO - Latence p99 < 500ms
      - record: slo:elasticsearch_latency_p99:compliance
        expr: |
          histogram_quantile(0.99,
            sum(rate(elasticsearch_http_request_duration_seconds_bucket[5m])) by (le)
          ) < 0.5
```

### 6.2 Alert Rules

```yaml
groups:
  - name: elasticsearch_alerts
    rules:
      # Alerte cluster health
      - alert: ElasticsearchClusterRed
        expr: elasticsearch_cluster_health_status{color="red"} == 1
        for: 1m
        labels:
          severity: critical
        annotations:
          summary: "Elasticsearch cluster status is RED"
          description: "Cluster {{ $labels.cluster }} is in RED state. Immediate action required."

      - alert: ElasticsearchClusterYellow
        expr: elasticsearch_cluster_health_status{color="yellow"} == 1
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "Elasticsearch cluster status is YELLOW"
          description: "Cluster {{ $labels.cluster }} is in YELLOW state. Some replicas may be missing."

      # Alerte JVM Heap
      - alert: ElasticsearchHeapUsageHigh
        expr: elasticsearch:jvm_heap_usage:ratio > 0.85
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "Elasticsearch JVM heap usage high"
          description: "Node {{ $labels.node }} heap usage is {{ $value | humanizePercentage }}"

      - alert: ElasticsearchHeapUsageCritical
        expr: elasticsearch:jvm_heap_usage:ratio > 0.95
        for: 2m
        labels:
          severity: critical
        annotations:
          summary: "Elasticsearch JVM heap usage critical"
          description: "Node {{ $labels.node }} heap usage is {{ $value | humanizePercentage }}. Risk of OOM."

      # Alerte latence recherche
      - alert: ElasticsearchSearchLatencyHigh
        expr: elasticsearch:search_latency:avg_5m > 0.5
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "Elasticsearch search latency high"
          description: "Average search latency is {{ $value | humanizeDuration }}"

      # Alerte taux d'indexation
      - alert: ElasticsearchIndexingRateDrop
        expr: |
          elasticsearch:indexing_rate:per_second < 100
          and
          elasticsearch:indexing_rate:per_second offset 1h > 1000
        for: 10m
        labels:
          severity: warning
        annotations:
          summary: "Elasticsearch indexing rate dropped significantly"
          description: "Indexing rate dropped from normal levels"

      # Alerte shards non assignés
      - alert: ElasticsearchUnassignedShards
        expr: elasticsearch_cluster_health_unassigned_shards > 0
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "Elasticsearch has unassigned shards"
          description: "{{ $value }} shards are unassigned in cluster {{ $labels.cluster }}"

      # Alerte SLO breach
      - alert: ElasticsearchSLOBudgetLow
        expr: slo:elasticsearch_availability:budget_remaining < 0.2
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "Elasticsearch SLO budget is running low"
          description: "Only {{ $value | humanizePercentage }} of error budget remaining"

      # Alerte disque
      - alert: ElasticsearchDiskSpaceLow
        expr: elasticsearch:disk_usage:ratio > 0.80
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "Elasticsearch disk space low"
          description: "Disk usage on {{ $labels.node }} is {{ $value | humanizePercentage }}"

      - alert: ElasticsearchDiskSpaceCritical
        expr: elasticsearch:disk_usage:ratio > 0.90
        for: 2m
        labels:
          severity: critical
        annotations:
          summary: "Elasticsearch disk space critical"
          description: "Disk usage on {{ $labels.node }} is {{ $value | humanizePercentage }}. Indexing may be blocked."

  - name: blackbox_alerts
    rules:
      - alert: EndpointDown
        expr: probe_success == 0
        for: 1m
        labels:
          severity: critical
        annotations:
          summary: "Endpoint {{ $labels.instance }} is down"
          description: "Blackbox probe failed for {{ $labels.instance }}"

      - alert: SSLCertificateExpiring
        expr: probe_ssl_earliest_cert_expiry - time() < 86400 * 30
        for: 1h
        labels:
          severity: warning
        annotations:
          summary: "SSL certificate expiring soon"
          description: "SSL certificate for {{ $labels.instance }} expires in {{ $value | humanizeDuration }}"
```

### 6.3 Transformations Internes PromQL

| Fonction | Usage | Exemple |
|----------|-------|---------|
| `rate()` | Taux de variation par seconde | `rate(elasticsearch_indices_indexing_index_total[5m])` |
| `increase()` | Augmentation sur période | `increase(elasticsearch_indices_search_query_total[1h])` |
| `histogram_quantile()` | Calcul percentiles | `histogram_quantile(0.99, ...)` |
| `predict_linear()` | Prédiction linéaire | `predict_linear(elasticsearch_filesystem_data_free_bytes[6h], 24*3600)` |
| `avg_over_time()` | Moyenne glissante | `avg_over_time(elasticsearch_cluster_health_status[1h])` |
| `deriv()` | Dérivée (tendance) | `deriv(elasticsearch_jvm_memory_used_bytes[15m])` |
| `absent()` | Détection absence | `absent(elasticsearch_cluster_health_status)` |
| `changes()` | Compteur changements | `changes(elasticsearch_cluster_health_status[1h])` |

**Exemple de prédiction de saturation disque** :
```promql
# Prédit quand le disque sera plein
predict_linear(
  elasticsearch_filesystem_data_free_bytes[6h],
  24 * 3600  # 24 heures
) < 0
```

---

## 7. Intégration Grafana

### 7.1 Datasources Configurées

#### Prometheus Datasource
```yaml
apiVersion: 1
datasources:
  - name: Prometheus
    type: prometheus
    access: proxy
    url: http://prometheus:9090
    isDefault: true
    editable: false
    jsonData:
      timeInterval: "15s"
      httpMethod: POST
```

#### Elasticsearch Datasource (Logs)
```yaml
  - name: Elasticsearch-Logs
    type: elasticsearch
    access: proxy
    url: http://es01:9200
    database: "logs-*"
    basicAuth: true
    basicAuthUser: elastic
    secureJsonData:
      basicAuthPassword: ${ES_PASSWORD}
    jsonData:
      esVersion: "8.0.0"
      timeField: "@timestamp"
      logMessageField: "message"
      logLevelField: "level"
```

### 7.2 Dashboard Overview

Le dashboard principal inclut les panneaux suivants :

#### Section 1 : Statut Cluster
| Panneau | Type | Métrique |
|---------|------|----------|
| Cluster Health | Stat | `elasticsearch_cluster_health_status` |
| Nodes Count | Stat | `elasticsearch_cluster_health_number_of_nodes` |
| Active Shards | Stat | `elasticsearch_cluster_health_active_shards` |
| Unassigned Shards | Stat | `elasticsearch_cluster_health_unassigned_shards` |

#### Section 2 : Performance
| Panneau | Type | Métrique |
|---------|------|----------|
| Indexing Rate | Graph | `rate(elasticsearch_indices_indexing_index_total[5m])` |
| Search Rate | Graph | `rate(elasticsearch_indices_search_query_total[5m])` |
| Search Latency | Graph | `elasticsearch:search_latency:avg_5m` |

#### Section 3 : Ressources
| Panneau | Type | Métrique |
|---------|------|----------|
| JVM Heap Usage | Gauge | `elasticsearch:jvm_heap_usage:ratio` |
| Disk Usage | Gauge | `elasticsearch:disk_usage:ratio` |
| GC Time | Graph | `rate(elasticsearch_jvm_gc_collection_seconds_count[5m])` |

#### Section 4 : Logs (Elasticsearch)
| Panneau | Type | Source |
|---------|------|--------|
| Log Volume | Bar Chart | Elasticsearch aggregation |
| Error Rate | Graph | Count where level=ERROR |
| Recent Logs | Logs Panel | Elasticsearch query |

### 7.3 Extensibilité de la Stack

#### Ajout de Tempo (Traces)
```yaml
datasources:
  - name: Tempo
    type: tempo
    access: proxy
    url: http://tempo:3200
    jsonData:
      tracesToLogs:
        datasourceUid: elasticsearch-logs
        tags: ['trace_id', 'span_id']
      serviceMap:
        datasourceUid: prometheus
```

#### Ajout de Loki (Logs centralisés)
```yaml
datasources:
  - name: Loki
    type: loki
    access: proxy
    url: http://loki:3100
    jsonData:
      derivedFields:
        - name: TraceID
          matcherRegex: "trace_id=(\\w+)"
          url: '$${__value.raw}'
          datasourceUid: tempo
```

---

## 8. Bonnes Pratiques d'Architecture

### 8.1 Sécurisation

#### X-Pack Security
```yaml
# elasticsearch.yml
xpack.security.enabled: true
xpack.security.enrollment.enabled: true

# Transport layer TLS
xpack.security.transport.ssl.enabled: true
xpack.security.transport.ssl.verification_mode: certificate
xpack.security.transport.ssl.keystore.path: certs/elastic-certificates.p12
xpack.security.transport.ssl.truststore.path: certs/elastic-certificates.p12

# HTTP layer TLS
xpack.security.http.ssl.enabled: true
xpack.security.http.ssl.keystore.path: certs/http.p12
```

#### Gestion des Credentials
```yaml
# .env (NE JAMAIS COMMITTER)
ELASTIC_PASSWORD=changeme_strong_password
KIBANA_PASSWORD=changeme_kibana_password
ES_KEYSTORE_PASSWORD=changeme_keystore
```

#### Principes de sécurité
1. **Moindre privilège** - Créer des rôles spécifiques (reader, writer, admin)
2. **Network isolation** - Réseau Docker dédié, ports internes non exposés
3. **TLS everywhere** - Transport et HTTP chiffrés
4. **Audit logging** - Activer les logs d'audit X-Pack
5. **API Keys** - Utiliser des API keys plutôt que username/password

### 8.2 Haute Disponibilité

#### Configuration cluster ES
```yaml
# Minimum 3 nœuds pour éviter le split-brain
cluster.initial_master_nodes: ["es01", "es02", "es03"]

# Découverte
discovery.seed_hosts: ["es01:9300", "es02:9300", "es03:9300"]

# Réplication
index.number_of_replicas: 1

# Allocation awareness
cluster.routing.allocation.awareness.attributes: rack_id
node.attr.rack_id: rack1
```

#### Résilience des composants
| Composant | HA Strategy |
|-----------|-------------|
| Elasticsearch | 3 nœuds master-eligible |
| Prometheus | Remote write vers stockage durable |
| Alertmanager | Cluster mode (gossip) |
| Grafana | Stateless (DB externe) |

### 8.3 Scaling Horizontal et Vertical

#### Scaling Vertical (ressources)
```yaml
# docker-compose.yml
services:
  es01:
    deploy:
      resources:
        limits:
          memory: 4G
          cpus: '2'
        reservations:
          memory: 2G
    environment:
      - "ES_JAVA_OPTS=-Xms2g -Xmx2g"
```

#### Scaling Horizontal (nœuds)
```yaml
# Ajouter un nœud data dédié
es04:
  image: elasticsearch:8.11.0
  environment:
    - node.name=es04
    - node.roles=data
    - discovery.seed_hosts=es01,es02,es03
```

### 8.4 Architecture Hot/Warm/Cold

```yaml
# Nœud Hot (SSD, plus de RAM)
es-hot:
  environment:
    - node.roles=data_hot,ingest
    - node.attr.data=hot

# Nœud Warm (HDD, moins de RAM)
es-warm:
  environment:
    - node.roles=data_warm
    - node.attr.data=warm

# ILM Policy
{
  "phases": {
    "hot": { "actions": { "rollover": { "max_age": "1d" } } },
    "warm": {
      "min_age": "7d",
      "actions": { "allocate": { "require": { "data": "warm" } } }
    },
    "cold": { "min_age": "30d", "actions": { "freeze": {} } },
    "delete": { "min_age": "90d", "actions": { "delete": {} } }
  }
}
```

### 8.5 Resource Limits et JVM Tuning

#### Règles de sizing JVM
```
# Règle d'or : Heap = min(50% RAM, 31GB)
# Pour 4GB RAM → Heap = 2GB
# Pour 64GB RAM → Heap = 31GB (compressed OOPs limit)

ES_JAVA_OPTS="-Xms2g -Xmx2g"
```

#### Paramètres GC recommandés
```bash
# G1GC (recommandé ES 8.x)
-XX:+UseG1GC
-XX:G1HeapRegionSize=32m
-XX:InitiatingHeapOccupancyPercent=75
```

### 8.6 Limites Docker à Connaître

| Limite | Impact | Mitigation |
|--------|--------|------------|
| Memory limits | ES peut être OOM killed | `memory_lock: true` + ulimits |
| File descriptors | Erreur "too many open files" | `ulimits: nofile: 65536` |
| mmap count | ES refuse de démarrer | `sysctl vm.max_map_count=262144` |
| CPU throttling | Latence variable | Éviter CPU limits stricts |

```yaml
# docker-compose.yml
services:
  es01:
    ulimits:
      memlock:
        soft: -1
        hard: -1
      nofile:
        soft: 65536
        hard: 65536
```

### 8.7 Partitionnement par Environnement

```
observability-stack/
├── docker-compose.base.yml      # Configuration commune
├── docker-compose.prod.yml      # Overrides production
├── docker-compose.staging.yml   # Overrides staging
├── docker-compose.lab.yml       # Overrides lab/dev
├── .env.prod
├── .env.staging
└── .env.lab

# Déploiement
docker compose -f docker-compose.base.yml -f docker-compose.prod.yml up -d
```

---

## 9. Points d'Entrée et Exposition des Services

### 9.1 Tableau des Ports

| Service | Port Interne | Port Externe | Protocole | Accès |
|---------|--------------|--------------|-----------|-------|
| Elasticsearch (es01) | 9200 | 9200 | HTTPS | API REST |
| Elasticsearch (es02) | 9200 | 9201 | HTTPS | API REST |
| Elasticsearch (es03) | 9200 | 9202 | HTTPS | API REST |
| ES Transport | 9300-9302 | - | TCP | Interne cluster |
| Kibana | 5601 | 5601 | HTTP | UI Web |
| Prometheus | 9090 | 9090 | HTTP | UI + API |
| Alertmanager | 9093 | 9093 | HTTP | UI + API |
| Grafana | 3000 | 3000 | HTTP | UI Web |
| ES Exporter | 9114 | - | HTTP | Métriques |
| Blackbox Exporter | 9115 | - | HTTP | Probes |
| OTEL Collector (gRPC) | 4317 | 4317 | gRPC | OTLP |
| OTEL Collector (HTTP) | 4318 | 4318 | HTTP | OTLP |
| OTEL Collector Metrics | 8888 | - | HTTP | Métriques |

### 9.2 URLs d'Accès

```
# Interfaces Web
Grafana:     http://localhost:3000  (admin/admin)
Kibana:      http://localhost:5601  (elastic/password)
Prometheus:  http://localhost:9090
Alertmanager: http://localhost:9093

# APIs
ES Cluster:  https://localhost:9200/_cluster/health
ES Nodes:    https://localhost:9200/_cat/nodes?v

# Métriques (internes)
ES Exporter: http://elasticsearch-exporter:9114/metrics
Blackbox:    http://blackbox-exporter:9115/metrics
```

---

## 10. Risques et Mitigations

### 10.1 Matrice des Risques

| Risque | Probabilité | Impact | Mitigation |
|--------|-------------|--------|------------|
| Split-brain cluster ES | Faible | Critique | 3 nœuds minimum, `minimum_master_nodes` |
| Perte de données | Moyenne | Critique | Réplication, snapshots réguliers |
| Saturation disque | Moyenne | Élevé | ILM, monitoring proactif, alertes |
| OOM Elasticsearch | Moyenne | Élevé | Heap sizing correct, memory_lock |
| Downtime Prometheus | Faible | Moyen | Remote write, rétention courte |
| Fuite credentials | Faible | Critique | Secrets management, rotation |
| Performance dégradée | Moyenne | Moyen | Recording rules, cache, optimization |
| Perte d'alertes | Faible | Élevé | Alertmanager HA, multi-canaux |

### 10.2 Plan de Mitigation Détaillé

#### Risque : Split-brain
```yaml
# Prévention
cluster.initial_master_nodes: ["es01", "es02", "es03"]
# Minimum de 2 nœuds pour élire un master
discovery.zen.minimum_master_nodes: 2  # ES 7.x
```

#### Risque : Perte de données
```bash
# Snapshots automatiques quotidiens
PUT /_slm/policy/daily-snapshot
{
  "schedule": "0 0 1 * * ?",
  "name": "<daily-snap-{now/d}>",
  "repository": "backup-repo",
  "config": { "indices": "*" },
  "retention": { "expire_after": "30d" }
}
```

#### Risque : Saturation disque
```yaml
# Alertes préventives
- alert: DiskWillFillIn24h
  expr: |
    predict_linear(elasticsearch_filesystem_data_free_bytes[6h], 24*3600) < 0
  labels:
    severity: warning
```

---

## 11. Roadmap 3-6 Mois

### Phase 1 : Fondations (Mois 1)
- [x] Déploiement cluster ES 3 nœuds
- [x] Configuration Prometheus + Alertmanager
- [x] Dashboards Grafana de base
- [x] Alertes critiques (cluster health, disk, heap)
- [ ] Documentation opérationnelle

### Phase 2 : Enrichissement (Mois 2-3)
- [ ] Ajout de Loki pour centralisation logs
- [ ] Configuration ILM avancée (Hot/Warm/Cold)
- [ ] Recording rules SLO
- [ ] Dashboards avancés (capacité planning)
- [ ] Intégration PagerDuty/OpsGenie

### Phase 3 : Traces & APM (Mois 4-5)
- [ ] Déploiement Tempo pour traces distribuées
- [ ] Intégration OTEL SDK dans applications
- [ ] Corrélation logs-métriques-traces
- [ ] Service Map automatique

### Phase 4 : Scale & Résilience (Mois 6)
- [ ] Migration Prometheus → VictoriaMetrics ou Thanos
- [ ] Multi-cluster ES avec Cross-Cluster Search
- [ ] Disaster Recovery (site secondaire)
- [ ] Capacity planning automatisé

---

## 12. Limites et Évolutions

### 12.1 Limites Actuelles

| Limitation | Description | Impact |
|------------|-------------|--------|
| Prometheus standalone | Pas de HA native, rétention limitée | Perte données si crash |
| Logs dans ES seulement | Pas de pipeline de logs dédié | Coût stockage ES |
| Pas de traces | Corrélation manuelle | Debugging complexe |
| Single cluster ES | Pas de DR géographique | Risque régional |
| Secrets en .env | Pas de vault | Sécurité limitée |

### 12.2 Évolutions Recommandées

#### Migration Prometheus → VictoriaMetrics
```yaml
# Avantages
- Stockage 10x plus efficace
- Compatible PromQL
- Haute disponibilité native
- Rétention longue durée

# Migration
remote_write:
  - url: http://victoriametrics:8428/api/v1/write
```

#### Migration Prometheus → Thanos
```yaml
# Avantages
- Stockage objet (S3, GCS)
- Requêtes globales multi-Prometheus
- Downsampling automatique
- Haute disponibilité

# Architecture
Prometheus → Thanos Sidecar → Thanos Query → Grafana
                  ↓
              Object Storage
```

#### Ajout de Loki
```yaml
# Architecture
Applications → Promtail → Loki → Grafana
                           ↑
                      Label-based
                      indexing
```

#### Ajout de Tempo
```yaml
# Architecture
Applications → OTEL Collector → Tempo → Grafana
                                  ↑
                            Trace storage
                            (object storage)
```

#### Multi-Cluster ES avec Cross-Cluster Search
```yaml
# Configuration
cluster.remote.cluster_b.seeds: ["es-cluster-b:9300"]
cluster.remote.cluster_c.seeds: ["es-cluster-c:9300"]

# Requête cross-cluster
GET /cluster_b:logs-*,cluster_c:logs-*/_search
```

---

## Annexes

### A. Commandes Utiles

```bash
# Vérifier santé cluster ES
curl -k -u elastic:password https://localhost:9200/_cluster/health?pretty

# Vérifier targets Prometheus
curl http://localhost:9090/api/v1/targets

# Vérifier alertes actives
curl http://localhost:9093/api/v2/alerts

# Logs d'un service
docker compose logs -f es01

# Redémarrer un service
docker compose restart prometheus
```

### B. Références

- [Elasticsearch Reference 8.x](https://www.elastic.co/guide/en/elasticsearch/reference/current/index.html)
- [Prometheus Documentation](https://prometheus.io/docs/)
- [Grafana Documentation](https://grafana.com/docs/)
- [OpenTelemetry Collector](https://opentelemetry.io/docs/collector/)
- [Alertmanager Configuration](https://prometheus.io/docs/alerting/latest/configuration/)

---

**Document maintenu par** : E4I Training
**Dernière mise à jour** : Décembre 2024
**Version** : 1.0.0
