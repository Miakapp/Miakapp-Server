#!/bin/sh
set -eu
umask 077

if [ "$#" -ne 2 ]; then
  echo "Usage: $0 /absolute/path/to/Miakapp-V3 /absolute/path/to/MiakAPI" >&2
  exit 64
fi
case "$1:$2" in
  /*:/*) ;;
  *)
    echo "Repository paths must be absolute" >&2
    exit 64
    ;;
esac

relay_repository=$(cd "$(dirname "$0")/.." && pwd)
v3_repository=$1
api_repository=$2
if [ ! -f "$v3_repository/control-plane/lib/api.js" ] \
  || [ ! -f "$api_repository/dist/access-token-provider.js" ]; then
  echo "Miakapp-V3 control plane and MiakAPI must be built before integration" >&2
  exit 66
fi

if [ -z "${JAVA_HOME:-}" ]; then
  for candidate in \
    /opt/homebrew/opt/openjdk@21/libexec/openjdk.jdk/Contents/Home \
    /usr/local/opt/openjdk@21/libexec/openjdk.jdk/Contents/Home; do
    if [ -x "$candidate/bin/java" ]; then
      export JAVA_HOME="$candidate"
      export PATH="$JAVA_HOME/bin:$PATH"
      break
    fi
  done
fi
if ! java -version >/dev/null 2>&1; then
  echo "Java 21 is required by the Firebase Local Emulator Suite" >&2
  exit 69
fi
java_version=$(java -version 2>&1 | awk -F '"' 'NR == 1 { print $2 }')
case "$java_version" in
  21|21.*) ;;
  *)
    echo "Java 21 is required; found ${java_version:-an unknown version}" >&2
    exit 69
    ;;
esac

integration_directory=$(mktemp -d)
cleanup() {
  rm -rf "$integration_directory"
}
trap cleanup EXIT INT TERM

openssl req -x509 -newkey rsa:2048 -sha256 -nodes -days 1 \
  -keyout "$integration_directory/tls.key" \
  -out "$integration_directory/tls.crt" \
  -subj '/CN=127.0.0.1' \
  -addext 'subjectAltName=IP:127.0.0.1' \
  >/dev/null 2>&1
go build -tags integration -trimpath \
  -o "$integration_directory/platform-fixture-server" \
  ./test/platform-fixture-server

export MIAKAPP_V3_REPOSITORY="$v3_repository"
export MIAKAPP_API_REPOSITORY="$api_repository"
export MIAKAPP_RELAY_FIXTURE_BINARY="$integration_directory/platform-fixture-server"
export MIAKAPP_INTEGRATION_CERT_FILE="$integration_directory/tls.crt"
export MIAKAPP_INTEGRATION_KEY_FILE="$integration_directory/tls.key"
export MIAKAPP_CONTROL_METADATA_FILE="$integration_directory/control.json"
export MIAKAPP_CONTROL_EVIDENCE_FILE="$integration_directory/control-evidence.json"
export MIAKAPP_CONTROL_SECRET_FILE="$integration_directory/control-secret"
export MIAKAPP_RELAY_METADATA_FILE="$integration_directory/relay.json"
export MIAKAPP_RELAY_EVIDENCE_FILE="$integration_directory/evidence.json"
export MIAKAPP_RELAY_CONTROL_SECRET_FILE="$integration_directory/relay-secret"
export MIAKAPP_HOME_KEY_FILE="$integration_directory/home-key"
export FIREBASE_CLI_DISABLE_UPDATE_CHECK=true
export GCLOUD_PROJECT=demo-miakapp-v4
export GOOGLE_CLOUD_PROJECT=demo-miakapp-v4
export FIRESTORE_EMULATOR_VERSION=1.19.4
export FIREBASE_EMULATORS_PATH="$v3_repository/control-plane/.firebase/emulators"

openssl rand -hex 32 > "$MIAKAPP_CONTROL_SECRET_FILE"
openssl rand -hex 32 > "$MIAKAPP_RELAY_CONTROL_SECRET_FILE"

cd "$v3_repository/control-plane"
bunx firebase setup:emulators:firestore --non-interactive
firestore_jar="$FIREBASE_EMULATORS_PATH/cloud-firestore-emulator-v1.19.4.jar"
firestore_size=$(wc -c < "$firestore_jar" | tr -d '[:space:]')
firestore_sha256=$(node -e '
  const { createHash } = require("node:crypto");
  const { readFileSync } = require("node:fs");
  process.stdout.write(createHash("sha256").update(readFileSync(process.argv[1])).digest("hex"));
' "$firestore_jar")
if [ "$firestore_size" != 65913000 ] \
  || [ "$firestore_sha256" != 15acd294f527ecd1ab1b109e2e037e6612c4e5f3d52eeff2f1c33651b3058429 ]; then
  echo "Pinned Firestore Emulator integrity verification failed" >&2
  exit 70
fi
bunx firebase emulators:exec \
  --non-interactive \
  --project demo-miakapp-v4 \
  --config firebase.json \
  --only auth,firestore \
  "$relay_repository/scripts/run-platform-integration.sh"
