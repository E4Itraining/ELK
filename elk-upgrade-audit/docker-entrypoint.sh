#!/bin/bash
# ELK Upgrade Audit Tool - Docker Entrypoint
# ===========================================

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}╔════════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║          ELK Upgrade Audit Tool - Docker                   ║${NC}"
echo -e "${GREEN}╚════════════════════════════════════════════════════════════╝${NC}"
echo ""

# Function to generate config from environment variables
generate_config() {
    local config_file="/app/config/settings.yaml"

    # Only generate if no custom config exists
    if [ ! -f "$config_file" ] || [ "$FORCE_CONFIG" = "true" ]; then
        echo -e "${YELLOW}Generating configuration from environment variables...${NC}"

        cat > "$config_file" << EOF
# Auto-generated configuration from Docker environment
# Generated at: $(date -Iseconds)

elasticsearch:
  hosts:
    - "${ES_HOSTS:-https://localhost:9200}"
  username: "${ES_USERNAME:-elastic}"
  password: "${ES_PASSWORD:-}"
  verify_certs: ${ES_VERIFY_CERTS:-true}
  ca_certs: "${ES_CA_CERTS:-}"
  timeout: ${ES_TIMEOUT:-30}
  max_retries: ${ES_MAX_RETRIES:-3}

cluster:
  name: "${CLUSTER_NAME:-elk-cluster}"
  environment: "${CLUSTER_ENV:-production}"

upgrade:
  target_version: "${TARGET_VERSION:-8.11.0}"
  current_version: ""
  strategy: "${UPGRADE_STRATEGY:-rolling}"

audit:
  reports_dir: "/app/reports"
  format: "${REPORT_FORMAT:-html}"
  checks:
    cluster_health: true
    node_info: true
    index_health: true
    shard_allocation: true
    deprecation_warnings: true
    plugin_compatibility: true
    mapping_analysis: true
    snapshot_status: true
    disk_usage: true
    memory_usage: true

snapshot:
  repository: "${SNAPSHOT_REPO:-elk-backup}"
  type: "${SNAPSHOT_TYPE:-fs}"
  location: "${SNAPSHOT_LOCATION:-/mnt/elasticsearch-backups}"
  name_pattern: "pre-upgrade-{date}"

logging:
  level: "${LOG_LEVEL:-INFO}"
  file: "/app/logs/elk-audit.log"
EOF

        echo -e "${GREEN}Configuration generated successfully${NC}"
    else
        echo -e "${YELLOW}Using existing configuration file${NC}"
    fi
}

# Function to check Elasticsearch connectivity
check_es_connection() {
    echo -e "${YELLOW}Checking Elasticsearch connectivity...${NC}"

    local host="${ES_HOSTS:-https://localhost:9200}"
    local user="${ES_USERNAME:-elastic}"
    local pass="${ES_PASSWORD:-}"

    # Build curl command
    local curl_opts="-s -o /dev/null -w %{http_code}"

    if [ "$ES_VERIFY_CERTS" = "false" ]; then
        curl_opts="$curl_opts -k"
    fi

    if [ -n "$pass" ]; then
        curl_opts="$curl_opts -u $user:$pass"
    fi

    # Try to connect
    local status=$(curl $curl_opts "$host" 2>/dev/null || echo "000")

    if [ "$status" = "200" ] || [ "$status" = "401" ]; then
        echo -e "${GREEN}Elasticsearch is reachable${NC}"
        return 0
    else
        echo -e "${RED}Warning: Cannot reach Elasticsearch at $host (HTTP $status)${NC}"
        echo -e "${YELLOW}The tool will still run but may fail to connect${NC}"
        return 1
    fi
}

# Function to show help
show_help() {
    echo "Usage: docker run elk-upgrade-audit [COMMAND] [OPTIONS]"
    echo ""
    echo "Commands:"
    echo "  interactive    Run in interactive mode (default)"
    echo "  audit          Run pre-upgrade audit"
    echo "  compat         Check version compatibility"
    echo "  backup         Manage snapshots (list|create|check)"
    echo "  upgrade        Manage upgrade (plan|status|execute)"
    echo "  validate       Run post-upgrade validation"
    echo ""
    echo "Environment Variables:"
    echo "  ES_HOSTS          Elasticsearch URL (default: https://localhost:9200)"
    echo "  ES_USERNAME       Elasticsearch username (default: elastic)"
    echo "  ES_PASSWORD       Elasticsearch password"
    echo "  ES_VERIFY_CERTS   Verify SSL certificates (default: true)"
    echo "  ES_CA_CERTS       Path to CA certificate"
    echo "  TARGET_VERSION    Target ES version (default: 8.11.0)"
    echo "  UPGRADE_STRATEGY  Upgrade strategy: rolling|full (default: rolling)"
    echo "  REPORT_FORMAT     Report format: html|json|markdown (default: html)"
    echo "  LOG_LEVEL         Log level: DEBUG|INFO|WARNING|ERROR (default: INFO)"
    echo ""
    echo "Examples:"
    echo "  docker run -it --rm elk-upgrade-audit interactive"
    echo "  docker run --rm -e ES_HOSTS=https://es:9200 elk-upgrade-audit audit"
    echo "  docker run --rm -v ./reports:/app/reports elk-upgrade-audit audit -o /app/reports"
}

# Main entrypoint logic
main() {
    # Handle help
    if [ "$1" = "--help" ] || [ "$1" = "-h" ]; then
        show_help
        exit 0
    fi

    # Generate configuration
    generate_config

    # Check connection (non-blocking)
    check_es_connection || true

    echo ""
    echo -e "${GREEN}Starting ELK Upgrade Audit Tool...${NC}"
    echo ""

    # Execute the Python script with all arguments
    exec python /app/elk_upgrade_audit.py "$@"
}

# Run main function with all script arguments
main "$@"
