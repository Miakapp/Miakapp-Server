#!/bin/sh
set -eu

required_environment() {
  value=$(printenv "$1" || true)
  if [ -z "$value" ]; then
    echo "$1 is required" >&2
    exit 64
  fi
}

for name in \
  MIAKAPP_V3_REPOSITORY \
  MIAKAPP_API_REPOSITORY \
  MIAKAPP_RELAY_FIXTURE_BINARY \
  MIAKAPP_INTEGRATION_CERT_FILE \
  MIAKAPP_INTEGRATION_KEY_FILE \
  MIAKAPP_CONTROL_METADATA_FILE \
  MIAKAPP_CONTROL_EVIDENCE_FILE \
  MIAKAPP_CONTROL_SECRET_FILE \
  MIAKAPP_RELAY_METADATA_FILE \
  MIAKAPP_RELAY_EVIDENCE_FILE \
  MIAKAPP_RELAY_CONTROL_SECRET_FILE \
  MIAKAPP_HOME_KEY_FILE; do
  required_environment "$name"
done

control_pid=
relay_pid=
cleanup() {
  if [ -n "$relay_pid" ]; then
    kill -TERM "$relay_pid" 2>/dev/null || true
    wait "$relay_pid" 2>/dev/null || true
  fi
  if [ -n "$control_pid" ]; then
    kill -TERM "$control_pid" 2>/dev/null || true
    wait "$control_pid" 2>/dev/null || true
  fi
}
trap cleanup EXIT INT TERM

wait_for_file() {
  file=$1
  pid=$2
  errors=$3
  attempt=0
  while [ ! -s "$file" ]; do
    if ! kill -0 "$pid" 2>/dev/null; then
      sed -n '1,120p' "$errors" >&2
      exit 1
    fi
    attempt=$((attempt + 1))
    if [ "$attempt" -ge 200 ]; then
      echo "Timed out waiting for an integration fixture" >&2
      exit 1
    fi
    sleep 0.05
  done
}

node "$MIAKAPP_V3_REPOSITORY/control-plane/scripts/relay-integration-server.mjs" \
  >"$MIAKAPP_CONTROL_METADATA_FILE.stdout" \
  2>"$MIAKAPP_CONTROL_METADATA_FILE.stderr" &
control_pid=$!
wait_for_file \
  "$MIAKAPP_CONTROL_METADATA_FILE" \
  "$control_pid" \
  "$MIAKAPP_CONTROL_METADATA_FILE.stderr"

"$MIAKAPP_RELAY_FIXTURE_BINARY" \
  >"$MIAKAPP_RELAY_METADATA_FILE.stdout" \
  2>"$MIAKAPP_RELAY_METADATA_FILE.stderr" &
relay_pid=$!
wait_for_file \
  "$MIAKAPP_RELAY_METADATA_FILE" \
  "$relay_pid" \
  "$MIAKAPP_RELAY_METADATA_FILE.stderr"

NODE_EXTRA_CA_CERTS="$MIAKAPP_INTEGRATION_CERT_FILE" node \
  "$MIAKAPP_V3_REPOSITORY/control-plane/scripts/setup-relay-integration.mjs" \
  "$MIAKAPP_CONTROL_METADATA_FILE" \
  "$MIAKAPP_RELAY_METADATA_FILE" \
  "$MIAKAPP_HOME_KEY_FILE"

NODE_EXTRA_CA_CERTS="$MIAKAPP_INTEGRATION_CERT_FILE" node \
  "$(cd "$(dirname "$0")/.." && pwd)/test/integration/platform-auth.mjs" \
  "$MIAKAPP_API_REPOSITORY" \
  "$MIAKAPP_CONTROL_METADATA_FILE" \
  "$MIAKAPP_RELAY_METADATA_FILE" \
  "$MIAKAPP_HOME_KEY_FILE" \
  "$MIAKAPP_CONTROL_SECRET_FILE" \
  "$MIAKAPP_RELAY_CONTROL_SECRET_FILE" \
  "$MIAKAPP_CONTROL_EVIDENCE_FILE" \
  "$MIAKAPP_RELAY_EVIDENCE_FILE"
