#!/bin/sh
set -eu

if [ "$#" -ne 1 ]; then
  echo "usage: $0 /absolute/path/to/Miakapp-V3" >&2
  exit 64
fi

contract_root=$1
case "$contract_root" in
  /*) ;;
  *)
    echo "Miakapp-V3 path must be absolute" >&2
    exit 64
    ;;
esac

fixture="$contract_root/control-plane-contract/fixtures/v1/access-tokens.json"
if [ ! -f "$fixture" ] || [ -L "$fixture" ]; then
  echo "canonical control-plane fixture is missing or symlinked" >&2
  exit 66
fi

MIAKAPP_CONTROL_PLANE_FIXTURE=$fixture \
  go test -race ./internal/auth -run '^TestCanonicalControlPlaneTokenVectors$' -count=1
