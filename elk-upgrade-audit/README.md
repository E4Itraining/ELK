# ELK Upgrade Audit Tool

Outil complet d'audit et de pilotage des mises à niveau de clusters Elasticsearch.

## Fonctionnalités

- **Audit pré-upgrade** : Analyse complète de l'état du cluster avant migration
- **Vérification de compatibilité** : Validation des chemins de mise à niveau supportés
- **Gestion des snapshots** : Création et vérification des sauvegardes
- **Orchestration des phases** : Pilotage guidé du processus d'upgrade
- **Validation post-upgrade** : Vérification de l'intégrité après migration
- **Génération de rapports** : HTML, JSON et Markdown

## Structure du Projet

```
elk-upgrade-audit/
├── elk_upgrade_audit.py      # Script principal CLI
├── requirements.txt          # Dépendances Python
├── config/
│   └── settings.yaml         # Configuration
├── modules/
│   ├── config.py             # Gestion de la configuration
│   ├── elasticsearch_client.py  # Client Elasticsearch
│   ├── pre_upgrade_audit.py  # Audit pré-upgrade
│   ├── compatibility_checker.py  # Vérification compatibilité
│   ├── snapshot_manager.py   # Gestion des snapshots
│   ├── upgrade_orchestrator.py   # Orchestration upgrade
│   ├── post_upgrade_validator.py # Validation post-upgrade
│   └── report_generator.py   # Génération de rapports
├── reports/                  # Rapports générés
└── templates/                # Templates de rapport
```

## Installation

```bash
# Cloner le repository
cd elk-upgrade-audit

# Installer les dépendances
pip install -r requirements.txt

# Configurer la connexion Elasticsearch
cp config/settings.yaml config/settings.local.yaml
# Éditer settings.local.yaml avec vos paramètres
```

## Configuration

Éditer `config/settings.yaml` :

```yaml
elasticsearch:
  hosts:
    - "https://localhost:9200"
  username: "elastic"
  password: ""  # Ou utiliser la variable ES_PASSWORD
  verify_certs: true

upgrade:
  target_version: "8.11.0"
  strategy: "rolling"  # ou "full-cluster-restart"

snapshot:
  repository: "elk-backup"
  type: "fs"
  location: "/mnt/elasticsearch-backups"
```

## Utilisation

### Mode Interactif

```bash
python elk_upgrade_audit.py interactive
```

### Audit Pré-Upgrade

```bash
# Audit complet avec génération de rapport HTML
python elk_upgrade_audit.py audit --target-version 8.11.0 --output ./reports --format html
```

### Vérification de Compatibilité

```bash
# Vérifier la compatibilité des versions
python elk_upgrade_audit.py compat --target-version 8.11.0

# Avec vérification des indices
python elk_upgrade_audit.py compat --target-version 8.11.0 --check-indices
```

### Gestion des Snapshots

```bash
# Lister les repositories et snapshots
python elk_upgrade_audit.py backup list

# Vérifier la préparation des sauvegardes
python elk_upgrade_audit.py backup check

# Créer un snapshot pré-upgrade
python elk_upgrade_audit.py backup create
```

### Plan d'Upgrade

```bash
# Afficher le plan d'upgrade
python elk_upgrade_audit.py upgrade plan --target-version 8.11.0

# Exécuter une phase spécifique
python elk_upgrade_audit.py upgrade execute --phase pre_checks
```

### Validation Post-Upgrade

```bash
python elk_upgrade_audit.py validate --output ./reports --format html
```

## Phases d'Upgrade

L'outil guide à travers les phases suivantes :

1. **PRE_CHECKS** - Vérifications pré-upgrade
2. **BACKUP** - Création du snapshot de sauvegarde
3. **DISABLE_ALLOCATION** - Désactivation de l'allocation des shards
4. **STOP_INDEXING** - Arrêt de l'indexation (conseil)
5. **SYNC_FLUSH** - Flush synchronisé des indices
6. **NODE_UPGRADE** - Mise à niveau des nœuds
7. **ENABLE_ALLOCATION** - Réactivation de l'allocation
8. **WAIT_RECOVERY** - Attente de la récupération du cluster
9. **POST_CHECKS** - Validation post-upgrade

## Vérifications Pré-Upgrade

| Vérification | Description |
|--------------|-------------|
| Cluster Health | État GREEN requis |
| Node Versions | Tous les nœuds sur la même version |
| Node Resources | Mémoire et processeurs disponibles |
| Disk Space | Minimum 20% d'espace libre |
| Heap Usage | Maximum 85% d'utilisation |
| Shard Allocation | Pas de shards en mouvement |
| Unassigned Shards | Aucun shard non assigné |
| Index Health | Aucun index RED |
| Deprecation Warnings | Analyse des paramètres obsolètes |
| Pending Tasks | Pas de tâches en attente |
| Snapshot Status | Repository configuré et fonctionnel |
| Plugin Compatibility | Vérification des plugins installés |

## Validation Post-Upgrade

| Vérification | Description |
|--------------|-------------|
| Cluster Health | Santé du cluster |
| Node Versions | Version cible sur tous les nœuds |
| Node Count | Tous les nœuds ont rejoint |
| Shard Allocation | Allocation complète |
| Index Availability | Indices accessibles |
| Index Health | Santé des indices |
| Document Counts | Comptage des documents |
| Search Functionality | Test de recherche |
| Indexing Functionality | Test d'indexation |
| Security Configuration | Configuration sécurité (ES 8.x) |

## Chemins d'Upgrade Supportés

| Version Source | Versions Cibles |
|----------------|-----------------|
| 6.8.x | 7.17.x |
| 7.0.x - 7.16.x | 7.17.x, 8.x (via 7.17) |
| 7.17.x | 8.0.x - 8.15.x |
| 8.x | Versions 8.x ultérieures |

**Note** : Pour passer de 6.x à 8.x, il faut d'abord migrer vers 7.17.x.

## Formats de Rapport

### HTML
Rapport visuel complet avec graphiques et mise en forme.

### JSON
Format structuré pour intégration avec d'autres outils.

### Markdown
Format texte pour documentation et partage.

## Variables d'Environnement

| Variable | Description |
|----------|-------------|
| ES_PASSWORD | Mot de passe Elasticsearch |
| ES_CA_CERTS | Chemin vers les certificats CA |

## Prérequis

- Python 3.8+
- Elasticsearch 7.x ou 8.x
- elasticsearch-py >= 8.0.0
- PyYAML >= 6.0

## Exemple de Workflow Complet

```bash
# 1. Vérifier la configuration
python elk_upgrade_audit.py interactive

# 2. Audit pré-upgrade
python elk_upgrade_audit.py audit --target-version 8.11.0 -o reports

# 3. Vérifier les sauvegardes
python elk_upgrade_audit.py backup check

# 4. Créer un snapshot
python elk_upgrade_audit.py backup create

# 5. Afficher le plan d'upgrade
python elk_upgrade_audit.py upgrade plan --target-version 8.11.0

# 6. Procéder à l'upgrade (manuel sur chaque nœud)
# ...

# 7. Validation post-upgrade
python elk_upgrade_audit.py validate -o reports
```

## Rollback

En cas d'échec de l'upgrade :

```bash
python elk_upgrade_audit.py upgrade rollback
```

Affiche les instructions de rollback incluant la restauration depuis snapshot.

## Contribution

Les contributions sont bienvenues ! Veuillez soumettre vos pull requests.

## Licence

MIT License
