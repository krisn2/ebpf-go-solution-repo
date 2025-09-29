#!/bin/bash
set -e


CGROUP_PATH=$1
shift


if [ -z "$CGROUP_PATH" ]; then
echo "usage: $0 /sys/fs/cgroup/mygroup <command...>"
exit 1
fi


sudo mkdir -p "$CGROUP_PATH"
# For cgroup v2 write pid to cgroup.procs
# run command in background and add its pid to the cgroup
"$@" &
PID=$!


echo $PID | sudo tee "${CGROUP_PATH}/cgroup.procs"


echo "Started pid $PID in cgroup $CGROUP_PATH"


echo "PID=$PID"

