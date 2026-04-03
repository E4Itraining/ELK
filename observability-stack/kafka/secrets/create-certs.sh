#!/bin/bash
# ============================================================================
# KAFKA SSL/SASL CERTIFICATE GENERATION SCRIPT
# ============================================================================
# This script generates all necessary certificates for Kafka SSL/SASL setup
# ============================================================================

set -e

# Configuration
VALIDITY_DAYS=365
KEY_SIZE=2048
STORE_PASSWORD=${KAFKA_CERT_PASSWORD:-kafka-secret}
KEY_PASSWORD=${KAFKA_KEY_PASSWORD:-kafka-secret}
CA_CN="Kafka-CA"
KAFKA_BROKERS=("kafka01" "kafka02" "kafka03")
OUTPUT_DIR="/var/ssl/private"

echo "============================================"
echo "Kafka SSL Certificate Generation"
echo "============================================"

# Create output directory
mkdir -p ${OUTPUT_DIR}
cd ${OUTPUT_DIR}

# ============================================================================
# Generate CA (Certificate Authority)
# ============================================================================
echo "[1/4] Generating Certificate Authority..."

if [ ! -f ca-cert ]; then
    # Generate CA key
    openssl req -new -x509 -keyout ca-key -out ca-cert -days ${VALIDITY_DAYS} \
        -subj "/CN=${CA_CN}/O=Observability/C=FR" \
        -passout pass:${STORE_PASSWORD}

    echo "CA certificate generated"
else
    echo "CA certificate already exists, skipping..."
fi

# ============================================================================
# Generate Broker Certificates
# ============================================================================
echo "[2/4] Generating broker certificates..."

for BROKER in "${KAFKA_BROKERS[@]}"; do
    echo "  Processing ${BROKER}..."

    if [ ! -f ${BROKER}.keystore.jks ]; then
        # Generate keystore with keypair
        keytool -keystore ${BROKER}.keystore.jks -alias ${BROKER} \
            -validity ${VALIDITY_DAYS} -genkey -keyalg RSA -keysize ${KEY_SIZE} \
            -storepass ${STORE_PASSWORD} -keypass ${KEY_PASSWORD} \
            -dname "CN=${BROKER},O=Observability,C=FR" \
            -ext SAN=DNS:${BROKER},DNS:localhost,IP:127.0.0.1

        # Generate CSR
        keytool -keystore ${BROKER}.keystore.jks -alias ${BROKER} \
            -certreq -file ${BROKER}.csr \
            -storepass ${STORE_PASSWORD} -keypass ${KEY_PASSWORD} \
            -ext SAN=DNS:${BROKER},DNS:localhost,IP:127.0.0.1

        # Sign with CA
        openssl x509 -req -CA ca-cert -CAkey ca-key -in ${BROKER}.csr \
            -out ${BROKER}-signed.crt -days ${VALIDITY_DAYS} -CAcreateserial \
            -passin pass:${STORE_PASSWORD} \
            -extfile <(printf "subjectAltName=DNS:${BROKER},DNS:localhost,IP:127.0.0.1")

        # Import CA into keystore
        keytool -keystore ${BROKER}.keystore.jks -alias CARoot \
            -import -file ca-cert -noprompt \
            -storepass ${STORE_PASSWORD}

        # Import signed certificate
        keytool -keystore ${BROKER}.keystore.jks -alias ${BROKER} \
            -import -file ${BROKER}-signed.crt \
            -storepass ${STORE_PASSWORD} -keypass ${KEY_PASSWORD}

        # Create truststore with CA cert
        keytool -keystore ${BROKER}.truststore.jks -alias CARoot \
            -import -file ca-cert -noprompt \
            -storepass ${STORE_PASSWORD}

        echo "  ${BROKER} certificates generated"
    else
        echo "  ${BROKER} certificates already exist, skipping..."
    fi
done

# ============================================================================
# Generate Client Certificates
# ============================================================================
echo "[3/4] Generating client certificates..."

CLIENT_NAME="kafka-client"

if [ ! -f ${CLIENT_NAME}.keystore.jks ]; then
    # Generate client keystore
    keytool -keystore ${CLIENT_NAME}.keystore.jks -alias ${CLIENT_NAME} \
        -validity ${VALIDITY_DAYS} -genkey -keyalg RSA -keysize ${KEY_SIZE} \
        -storepass ${STORE_PASSWORD} -keypass ${KEY_PASSWORD} \
        -dname "CN=${CLIENT_NAME},O=Observability,C=FR"

    # Generate CSR
    keytool -keystore ${CLIENT_NAME}.keystore.jks -alias ${CLIENT_NAME} \
        -certreq -file ${CLIENT_NAME}.csr \
        -storepass ${STORE_PASSWORD} -keypass ${KEY_PASSWORD}

    # Sign with CA
    openssl x509 -req -CA ca-cert -CAkey ca-key -in ${CLIENT_NAME}.csr \
        -out ${CLIENT_NAME}-signed.crt -days ${VALIDITY_DAYS} -CAcreateserial \
        -passin pass:${STORE_PASSWORD}

    # Import CA into keystore
    keytool -keystore ${CLIENT_NAME}.keystore.jks -alias CARoot \
        -import -file ca-cert -noprompt \
        -storepass ${STORE_PASSWORD}

    # Import signed certificate
    keytool -keystore ${CLIENT_NAME}.keystore.jks -alias ${CLIENT_NAME} \
        -import -file ${CLIENT_NAME}-signed.crt \
        -storepass ${STORE_PASSWORD} -keypass ${KEY_PASSWORD}

    # Create client truststore
    keytool -keystore ${CLIENT_NAME}.truststore.jks -alias CARoot \
        -import -file ca-cert -noprompt \
        -storepass ${STORE_PASSWORD}

    echo "Client certificates generated"
else
    echo "Client certificates already exist, skipping..."
fi

# ============================================================================
# Create Credentials File
# ============================================================================
echo "[4/4] Creating credentials files..."

# Create password file for Kafka
echo "${STORE_PASSWORD}" > credentials

# Create JAAS config for brokers
cat > kafka_server_jaas.conf << EOF
KafkaServer {
    org.apache.kafka.common.security.plain.PlainLoginModule required
    username="admin"
    password="admin-secret"
    user_admin="admin-secret"
    user_producer="producer-secret"
    user_consumer="consumer-secret"
    user_logstash="logstash-secret"
    user_connect="connect-secret"
    user_schemaregistry="schema-secret"
    user_ksql="ksql-secret";
};

Client {
    org.apache.kafka.common.security.plain.PlainLoginModule required
    username="admin"
    password="admin-secret";
};
EOF

# Create JAAS config for clients
cat > kafka_client_jaas.conf << EOF
KafkaClient {
    org.apache.kafka.common.security.plain.PlainLoginModule required
    username="producer"
    password="producer-secret";
};
EOF

# Create JAAS config for Zookeeper
cat > zookeeper_jaas.conf << EOF
Server {
    org.apache.kafka.common.security.plain.PlainLoginModule required
    username="admin"
    password="admin-secret"
    user_admin="admin-secret"
    user_kafka="kafka-secret";
};
EOF

echo "============================================"
echo "Certificate generation complete!"
echo "============================================"
echo ""
echo "Generated files:"
ls -la ${OUTPUT_DIR}
echo ""
echo "Store password: ${STORE_PASSWORD}"
echo "============================================"
