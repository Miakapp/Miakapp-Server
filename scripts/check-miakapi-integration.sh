#!/bin/sh
set -eu

if [ "$#" -ne 1 ]; then
  echo "Usage: $0 /absolute/path/to/MiakAPI" >&2
  exit 2
fi

miakapi_repository=$1
if [ ! -f "$miakapi_repository/dist/index.js" ] || [ ! -f "$miakapi_repository/dist/protocol/codec.js" ]; then
  echo "MiakAPI must be built before running the relay integration check" >&2
  exit 2
fi

fixture_directory=$(mktemp -d)
fixture_pid=

cleanup() {
  if [ -n "$fixture_pid" ]; then
    kill -TERM "$fixture_pid" 2>/dev/null || true
    wait "$fixture_pid" 2>/dev/null || true
  fi
  rm -rf "$fixture_directory"
}
trap cleanup EXIT INT TERM

go run ./test/fixture-server >"$fixture_directory/metadata.json" 2>"$fixture_directory/fixture.err" &
fixture_pid=$!

attempt=0
while [ ! -s "$fixture_directory/metadata.json" ]; do
  if ! kill -0 "$fixture_pid" 2>/dev/null; then
    cat "$fixture_directory/fixture.err" >&2
    exit 1
  fi
  attempt=$((attempt + 1))
  if [ "$attempt" -ge 200 ]; then
    echo "Timed out waiting for the relay fixture" >&2
    exit 1
  fi
  sleep 0.05
done

relay_url=$(node -e 'const fs=require("fs"); process.stdout.write(JSON.parse(fs.readFileSync(process.argv[1], "utf8")).relayUrl)' "$fixture_directory/metadata.json")
ca_file=$(node -e 'const fs=require("fs"); process.stdout.write(JSON.parse(fs.readFileSync(process.argv[1], "utf8")).caFile)' "$fixture_directory/metadata.json")

NODE_EXTRA_CA_CERTS=$ca_file node ./test/integration/miakapi.mjs "$miakapi_repository" "$relay_url"
