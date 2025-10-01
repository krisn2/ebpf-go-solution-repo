#!/bin/bash
set -euo pipefail

CGROUP_PATH="$1"
shift || {
  echo "usage: $0 /sys/fs/cgroup/mygroup <command...>"
  exit 1
}

sudo mkdir -p "$CGROUP_PATH"

echo $$ | sudo tee "$CGROUP_PATH/cgroup.procs" >/dev/null

exec "$@"
