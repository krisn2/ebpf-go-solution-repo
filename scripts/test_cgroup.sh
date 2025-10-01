#!/bin/bash
set -euo pipefail

CGROUP_PATH="/sys/fs/cgroup/mygroup"
PORT=4040
DENY_PORT=8080

echo "🔧 Setting up test for cgroup at $CGROUP_PATH (allowed port $PORT)"


run_server() {
  local port="$1"
  echo "👉 Attempting to start server on port $port"
  ./create_cgroup.sh "$CGROUP_PATH" nc -l -p "$port" >/dev/null 2>&1 &
  server_pid=$!
  sleep 1
  if ps -p "$server_pid" >/dev/null; then
    echo "✅ Server bind on port $port succeeded"
    kill "$server_pid" 2>/dev/null || true
  else
    echo "❌ Server bind on port $port failed"
  fi
}

run_client() {
  local port="$1"
  echo "👉 Attempting to connect to port $port"
  nc -l -p "$port" >/dev/null 2>&1 &
  server_pid=$!
  sleep 1

  if ./create_cgroup.sh "$CGROUP_PATH" nc -z 127.0.0.1 "$port" >/dev/null 2>&1; then
    echo "✅ Client connect to port $port succeeded"
  else
    echo "❌ Client connect to port $port failed"
  fi

  kill "$server_pid" 2>/dev/null || true
}

echo "===== 🧪 SERVER (BIND) TEST ====="
run_server "$PORT"      
run_server "$DENY_PORT" 

echo "===== 🧪 CLIENT (CONNECT) TEST ====="
run_client "$PORT"     
run_client "$DENY_PORT" 
