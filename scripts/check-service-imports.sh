#!/usr/bin/env bash
# Import each service's app inside its own built image, which runs the Python version the service really runs on (3.11), with the local source copied over the image's.
#
# Why: a type annotation naming something that was never imported works on newer Pythons (3.14 evaluates annotations lazily) and crashes the service on start on 3.11. The unit tests
# cannot see that when they run on the newer Python. This can.
#
#     bash scripts/check-service-imports.sh            # every service whose image is built locally
#     bash scripts/check-service-imports.sh api fusion # only these
set -u
export MSYS_NO_PATHCONV=1
here="$(cd "$(dirname "$0")/.." && pwd)"
declare -A IMAGE=( [api]=aisoc-core-api [fusion]=aisoc-fusion [actions]=aisoc-actions [agents]=aisoc-agents [connectors]=aisoc-connectors [threatintel]=aisoc-threatintel [ueba]=aisoc-ueba )
services=("$@")
[ ${#services[@]} -eq 0 ] && services=(api fusion actions agents connectors threatintel ueba)
failed=0
for svc in "${services[@]}"; do
  image="${AISOC_IMAGE_NAMESPACE:-ghcr.io/halion9000}/${IMAGE[$svc]:-}:${AISOC_VERSION:-latest}"
  if ! docker image inspect "$image" >/dev/null 2>&1; then echo "skip   $svc (no local image $image)"; continue; fi
  cid=$(docker create --entrypoint python "$image" -c "import app.main" 2>/dev/null) || { echo "skip   $svc (could not create a container)"; continue; }
  docker cp "$here/services/$svc/app/." "$cid:/app/app/" >/dev/null 2>&1
  out=$(docker start -a "$cid" 2>&1); code=$?
  docker rm -f "$cid" >/dev/null 2>&1
  if [ $code -eq 0 ]; then echo "ok     $svc"; else echo "FAILED $svc"; echo "$out" | tail -6 | sed 's/^/         /'; failed=1; fi
done
exit $failed
