#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
COMPOSE_FILE="${COMPOSE_FILE:-$ROOT_DIR/docker/compose.control.yml}"
ENV_FILE="${ENV_FILE:-$ROOT_DIR/docker/control.postgres.env.example}"
API_URL="${API_URL:-http://127.0.0.1:8000}"
SMOKE_REASON="${SMOKE_REASON:-postgres runtime rehearsal}"
SMOKE_CHANGED_BY="${SMOKE_CHANGED_BY:-operator}"
KEEP_UP=0
SKIP_BUILD=0
KEEP_ARTIFACTS=0

usage() {
  cat <<'EOF'
Usage: run_postgres_runtime_rehearsal.sh [options]

Options:
  --env-file PATH         Compose env file to use.
  --api-url URL           API base URL to probe. Default: http://127.0.0.1:8000
  --changed-by NAME       Operator name recorded in the runtime smoke event.
  --reason TEXT           Reason recorded in the runtime smoke event.
  --keep-up               Leave the compose stack running after the rehearsal.
  --keep-artifacts        Keep smoke records/artifacts instead of cleaning them up.
  --skip-build            Do not pass --build to docker compose up.
  --help                  Show this help message.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --env-file)
      ENV_FILE="$2"
      shift 2
      ;;
    --api-url)
      API_URL="$2"
      shift 2
      ;;
    --changed-by)
      SMOKE_CHANGED_BY="$2"
      shift 2
      ;;
    --reason)
      SMOKE_REASON="$2"
      shift 2
      ;;
    --keep-up)
      KEEP_UP=1
      shift
      ;;
    --keep-artifacts)
      KEEP_ARTIFACTS=1
      shift
      ;;
    --skip-build)
      SKIP_BUILD=1
      shift
      ;;
    --help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown option: $1" >&2
      usage >&2
      exit 1
      ;;
  esac
done

if ! command -v docker >/dev/null 2>&1; then
  echo "docker is required for the Postgres runtime rehearsal." >&2
  exit 1
fi
if ! command -v python3 >/dev/null 2>&1; then
  echo "python3 is required for API response verification." >&2
  exit 1
fi

if [[ ! -f "$ENV_FILE" ]]; then
  echo "Env file not found: $ENV_FILE" >&2
  exit 1
fi

set -a
# shellcheck disable=SC1090
source "$ENV_FILE"
set +a

API_KEY="${LSA_API_KEY:-}"
if [[ -z "$API_KEY" ]]; then
  echo "LSA_API_KEY must be set in the env file or environment." >&2
  exit 1
fi

compose() {
  docker compose --profile postgres --env-file "$ENV_FILE" -f "$COMPOSE_FILE" "$@"
}

cleanup() {
  if [[ $KEEP_UP -eq 0 ]]; then
    compose down -v
  fi
}

trap cleanup EXIT

UP_ARGS=(up -d)
if [[ $SKIP_BUILD -eq 0 ]]; then
  UP_ARGS+=(--build)
fi
compose "${UP_ARGS[@]}"

echo "Waiting for API health at $API_URL/health ..."
for _ in $(seq 1 60); do
  if python3 - "$API_URL/health" <<'PY'
import json
import sys
import urllib.request

url = sys.argv[1]
try:
    with urllib.request.urlopen(url, timeout=2) as response:
        payload = json.loads(response.read().decode("utf-8"))
except Exception:
    sys.exit(1)
sys.exit(0 if payload.get("status") == "ok" else 1)
PY
  then
    break
  fi
  sleep 2
done

HEALTH_JSON="$(python3 - "$API_URL/health" <<'PY'
import sys
import urllib.request

with urllib.request.urlopen(sys.argv[1], timeout=5) as response:
    sys.stdout.write(response.read().decode("utf-8"))
PY
)"

echo "Health payload:"
echo "$HEALTH_JSON"

python3 - "$HEALTH_JSON" <<'PY'
import json
import sys

payload = json.loads(sys.argv[1])
expected = {
    "snapshot_repository_backend": "postgres",
    "audit_repository_backend": "postgres",
    "job_repository_backend": "postgres",
    "control_plane_repository_layout": "shared",
}
for key, value in expected.items():
    actual = payload.get(key)
    if actual != value:
        raise SystemExit(f"health check failed: {key}={actual!r}, expected {value!r}")
if payload.get("control_plane_mixed_backends"):
    raise SystemExit("health check failed: expected control_plane_mixed_backends=false")
if not payload.get("job_repository_runtime_active"):
    raise SystemExit("health check failed: expected job_repository_runtime_active=true")
if payload.get("database_backend") != "postgres":
    raise SystemExit(f"health check failed: database_backend={payload.get('database_backend')!r}")
PY

REHEARSAL_JSON="$(python3 - "$API_URL/maintenance/control-plane-runtime-rehearsal" "$API_KEY" "$SMOKE_CHANGED_BY" "$SMOKE_REASON" "$KEEP_ARTIFACTS" <<'PY'
import json
import sys
import urllib.request

url, api_key, changed_by, reason, keep_artifacts = sys.argv[1:]
cleanup = keep_artifacts != "1"
request = urllib.request.Request(
    url,
    data=json.dumps(
        {
            "changed_by": changed_by,
            "expected_backend": "postgres",
            "expected_repository_layout": "shared",
            "reason": reason,
            "cleanup": cleanup,
        }
    ).encode("utf-8"),
    headers={
        "Content-Type": "application/json",
        "X-API-Key": api_key,
    },
    method="POST",
)
with urllib.request.urlopen(request, timeout=10) as response:
    sys.stdout.write(response.read().decode("utf-8"))
PY
)"

echo "Runtime rehearsal payload:"
echo "$REHEARSAL_JSON"

python3 - "$REHEARSAL_JSON" "$KEEP_ARTIFACTS" <<'PY'
import json
import sys

payload = json.loads(sys.argv[1])
keep_artifacts = sys.argv[2] == "1"
if payload.get("status") != "passed":
    raise SystemExit(f"runtime rehearsal failed: status={payload.get('status')!r}")
if payload.get("expected_backend") != "postgres":
    raise SystemExit(f"runtime rehearsal failed: expected_backend={payload.get('expected_backend')!r}")
if payload.get("expected_repository_layout") != "shared":
    raise SystemExit(
        f"runtime rehearsal failed: expected_repository_layout={payload.get('expected_repository_layout')!r}"
    )
smoke = payload.get("smoke", {})
if smoke.get("cleanup_requested") != (not keep_artifacts):
    raise SystemExit("runtime rehearsal failed: smoke cleanup_requested mismatch")
if not keep_artifacts and not smoke.get("cleanup_completed"):
    raise SystemExit("runtime rehearsal failed: smoke cleanup_completed=false")
PY

echo "Postgres runtime rehearsal completed successfully."
