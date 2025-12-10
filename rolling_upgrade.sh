#!/usr/bin/env bash
set -euo pipefail

########################################
# CONFIGURATION GÉNÉRALE
########################################

# URL du cluster Elasticsearch (pointant sur un nœud du cluster)
ES_HOST="https://mon-es-admin:9200"
# Si  HTTP simple :
# ES_HOST="http://mon-es-admin:9200"

# Credentials Elasticsearch (laisser vide si non utilisé)
ES_USER=""
ES_PASSWORD=""

# Liste des hosts Docker (1 host = 1 node hot + 1 node warm)
HOSTS=(
  "es-host-1"
  "es-host-2"
  "es-host-3"
  "es-host-4"
  "es-host-5"
)

# Utilisateur SSH sur les hosts
SSH_USER="localadmin"

# Répertoire où se trouve le docker-compose sur les hosts
REMOTE_COMPOSE_DIR="/opt/elk"

# Noms des services Docker Compose pour les nœuds hot / warm
HOT_SERVICE_NAME="es-hot"
WARM_SERVICE_NAME="es-warm"

# Commande docker compose (v2)
DOCKER_COMPOSE_CMD="docker compose"
# si tu utilises l'ancien binaire :
# DOCKER_COMPOSE_CMD="docker-compose"

# Fichier de log (sur la machine d’admin)
LOG_FILE="./rolling_upgrade_es_docker.log"

# Temps entre deux checks du cluster (en secondes)
SLEEP_BETWEEN_CHECKS=15

########################################
# MODE DRY-RUN
########################################

DRY_RUN=false

for arg in "$@"; do
  if [[ "$arg" == "--dry-run" ]]; then
    DRY_RUN=true
  fi
done

########################################
# FONCTIONS UTILITAIRES
########################################

log() {
  local msg="$1"
  local ts
  ts="$(date '+%Y-%m-%d %H:%M:%S')"
  echo "[$ts] $msg" | tee -a "$LOG_FILE"
}

require_cmd() {
  local cmd="$1"
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo " Commande requise manquante : $cmd"
    exit 1
  fi
}

########################################
# FONCTIONS ELASTICSEARCH
########################################

es_curl() {
  local method="$1"
  local path="$2"
  local data="${3:-}"

  local auth_args=()
  if [[ -n "$ES_USER" && -n "$ES_PASSWORD" ]]; then
    auth_args=(-u "${ES_USER}:${ES_PASSWORD}")
  fi

  if [[ -n "$data" ]]; then
    curl -sS "${auth_args[@]}" \
      -X "$method" \
      -H "Content-Type: application/json" \
      "${ES_HOST}${path}" \
      -d "$data"
  else
    curl -sS "${auth_args[@]}" -X "$method" "${ES_HOST}${path}"
  fi
}

wait_for_cluster_status() {
  local target="$1" # "green" ou "yellow_or_green"
  log " Attente que le cluster atteigne l'état [$target]..."

  while true; do
    local health
    health=$(es_curl GET "/_cluster/health" || echo "{}")

    local status
    status=$(echo "$health" | jq -r '.status // "unknown"')

    log "   → Statut actuel du cluster : $status"

    if [[ "$target" == "yellow_or_green" ]]; then
      if [[ "$status" == "yellow" || "$status" == "green" ]]; then
        log " Cluster dans un état acceptable : $status"
        break
      fi
    else
      if [[ "$status" == "$target" ]]; then
        log "Cluster au statut $status"
        break
      fi
    fi

    sleep "$SLEEP_BETWEEN_CHECKS"
  done
}

disable_allocation() {
  log " Désactivation de l'allocation et du rebalance (aucun mouvement de shards)..."
  if $DRY_RUN; then
    log "DRY-RUN → Skipping ES settings change : allocation.enable=none, rebalance.enable=none"
    return
  fi

  es_curl PUT "/_cluster/settings" '{
    "transient": {
      "cluster.routing.allocation.enable": "none",
      "cluster.routing.rebalance.enable": "none"
    }
  }' | jq . | tee -a "$LOG_FILE"
}

restore_allocation() {
  log " Restauration de l'allocation et du rebalance normaux..."
  if $DRY_RUN; then
    log "DRY-RUN → Skipping ES settings change : allocation.enable=all, rebalance.enable=all"
    return
  fi

  es_curl PUT "/_cluster/settings" '{
    "transient": {
      "cluster.routing.allocation.enable": "all",
      "cluster.routing.rebalance.enable": "all"
    }
  }' | jq . | tee -a "$LOG_FILE"
}

########################################
# FONCTION D'UPGRADE D'UN SERVICE SUR UN HOST
########################################

upgrade_service_on_host() {
  local host="$1"
  local service="$2"
  local role="$3" # "hot" ou "warm"

  log "Upgrade du service [$service] ($role) sur le host [$host]"

  local cmd="cd ${REMOTE_COMPOSE_DIR} && \
${DOCKER_COMPOSE_CMD} pull ${service} && \
${DOCKER_COMPOSE_CMD} up -d ${service}"

  if $DRY_RUN; then
    log "DRY-RUN → Sur [$host], j'exécuterais : $cmd"
    return
  fi

  ssh "${SSH_USER}@${host}" "$cmd"

  # Après le redémarrage du service, on attend que le cluster revienne à un état acceptable
  log " Attente que le cluster revienne au moins en yellow après upgrade de [$service] sur [$host]..."
  wait_for_cluster_status "yellow_or_green"

  log " Service [$service] ($role) sur [$host] upgradé."
}

########################################
# FONCTION D'UPGRADE D'UN HOST (HOT + WARM)
########################################

upgrade_host() {
  local host="$1"

  log "======================================"
  log " UPGRADE DU HOST : $host (hot + warm)"
  log "======================================"

  # Upgrade du node HOT
  upgrade_service_on_host "$host" "$HOT_SERVICE_NAME" "hot"

  # Upgrade du node WARM
  upgrade_service_on_host "$host" "$WARM_SERVICE_NAME" "warm"

  log " Host [$host] : hot + warm upgradés."
}

########################################
# MAIN
########################################

log "======================================"
log " DÉMARRAGE DU ROLLING UPGRADE ELK (Docker, hot/warm)"
log " Mode dry-run : $DRY_RUN"
log "======================================"

# Check dépendances minimales
require_cmd "curl"
require_cmd "jq"
require_cmd "ssh"

log " Vérification initiale : cluster doit être au moins green..."
wait_for_cluster_status "green"

# Désactiver allocation/rebalance pour éviter les mouvements de shards pendant l'upgrade
disable_allocation

# Upgrade host par host
for host in "${HOSTS[@]}"; do
  upgrade_host "$host"
done

# Rétablir l'allocation et le rebalance
restore_allocation

log " Vérification finale : cluster green attendu..."
wait_for_cluster_status "green"

log " Rolling upgrade terminé avec succès pour tous les hosts."
