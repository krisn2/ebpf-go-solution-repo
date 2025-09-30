#!/bin/bash
set -e

CGROUP_PATH="/sys/fs/cgroup/mygroup"
ALLOWED_PORT=4040
DENIED_PORT=8080

echo "🔧 Setting up test for cgroup at $CGROUP_PATH (allowed port $ALLOWED_PORT)"

# Helper: run server inside cgroup
run_server() {
    local port=$1
    echo "👉 Starting server on port $port"
    ./create_cgroup.sh "$CGROUP_PATH" nc -l "$port" &
    sleep 1
    if ps -ef | grep "[n]c -l $port" >/dev/null; then
        echo "✅ server $port started"
    else
        echo "❌ server $port denied"
    fi
}

# Helper: run client inside cgroup
run_client() {
    local port=$1
    echo "👉 Connecting to port $port"
    ./create_cgroup.sh "$CGROUP_PATH" nc 127.0.0.1 "$port" || true
    sleep 1
    if ps -ef | grep "[n]c 127.0.0.1 $port" >/dev/null; then
        echo "✅ client $port connected"
    else
        echo "❌ client $port denied"
    fi
}

echo
echo "===== 🧪 SERVER TEST ====="
run_server $ALLOWED_PORT   # should succeed
run_server $DENIED_PORT    # should fail

echo
echo "===== 🧪 CLIENT TEST ====="
run_client $ALLOWED_PORT   # should succeed
run_client $DENIED_PORT    # should fail

echo
echo "🔎 Check kernel logs with:"
echo "    sudo cat /sys/kernel/debug/tracing/trace_pipe"

