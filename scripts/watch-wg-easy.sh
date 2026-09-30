#!/bin/sh
# Host-side lifecycle watcher for an independently managed wg-easy container.
set -eu
project_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
compose_file="$project_dir/compose.acl.example.yaml"
last_namespace=
while :; do
  container_id=$(docker inspect -f '{{.Id}}' wg-easy 2>/dev/null || :)
  pid=$(docker inspect -f '{{.State.Pid}}' wg-easy 2>/dev/null || :)
  namespace=
  case "$pid" in
    ''|0|*[!0-9]*) ;;
    *) namespace=$(stat -Lc '%i' "/proc/$pid/ns/net" 2>/dev/null || :) ;;
  esac
  if [ -n "$container_id" ] && [ -n "$namespace" ]; then
    identity="$container_id:$namespace"
    enforcer_id=$(docker compose -f "$compose_file" ps -q acl-enforcer 2>/dev/null || :)
    running=
    if [ -n "$enforcer_id" ]; then
      running=$(docker inspect -f '{{.State.Running}}' "$enforcer_id" 2>/dev/null || :)
    fi
    if [ "$identity" != "$last_namespace" ] || [ "$running" != true ]; then
      if docker compose -f "$compose_file" up -d --no-build --force-recreate --no-deps acl-enforcer; then
        last_namespace=$identity
      fi
    fi
  else
    last_namespace=
  fi
  [ "${ACL_WATCH_ONCE:-}" = 1 ] && exit 0
  sleep 5
done
