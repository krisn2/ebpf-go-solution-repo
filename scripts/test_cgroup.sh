#!/bin/bash
set -e

CGROUP_PATH="/sys/fs/cgroup/mygroup"
ALLOWED_PORT=4040
DENIED_PORT=8080

echo "🔧 Setting up test for cgroup at $CGROUP_PATH (allowed port $ALLOWED_PORT)"

# Helper: run server inside cgroup
# This checks the bind operation's success/failure
run_server() {
    local port=$1
    local expected_result=$2 # 'allow' or 'deny'
    
    echo "👉 Attempting to start server on port $port (Expected: $expected_result)"
    
    # We use a subshell to capture the exit code of nc within the cgroup
    ./create_cgroup.sh "$CGROUP_PATH" nc -l "$port" >/dev/null 2>&1 &
    PID=$!
    
    # Give the kernel and nc a moment to process the bind call
    sleep 0.5 
    
    # Check if the process is still running (successful bind)
    if kill -0 $PID 2>/dev/null; then
        kill $PID >/dev/null 2>&1 || true # Kill the successful server
        if [ "$expected_result" = "allow" ]; then
            echo "✅ Server bind on port $port succeeded (as expected)."
        else
            echo "❌ Server bind on port $port **SUCCEEDED** but should have been DENIED."
        fi
    else
        # Process is dead (failed bind)
        if [ "$expected_result" = "deny" ]; then
            echo "✅ Server bind on port $port DENIED (as expected)."
        else
            echo "❌ Server bind on port $port **DENIED** but should have been allowed."
        fi
    fi
}

# Helper: run client inside cgroup
# This checks the connect operation's success/failure
run_client() {
    local port=$1
    local expected_result=$2 # 'allow' or 'deny'

    echo "👉 Attempting to connect to port $port (Expected: $expected_result)"
    
    # Run nc connect command inside the cgroup
    # Use timeout to prevent hanging if the connection is blocked indefinitely
    ./create_cgroup.sh "$CGROUP_PATH" timeout 1s nc 127.0.0.1 "$port" >/dev/null 2>&1
    CLIENT_STATUS=$? # Capture exit status
    
    # Status 0 means successful connection (or timeout if it connected)
    # Status 124 means timeout (might indicate success or block)
    # Status 1 means connection refused/failure (might indicate BPF block)

    if [ $CLIENT_STATUS -eq 0 ] || [ $CLIENT_STATUS -eq 124 ]; then
        if [ "$expected_result" = "allow" ]; then
            echo "✅ Client connect to port $port succeeded (as expected)."
        else
            echo "❌ Client connect to port $port **SUCCEEDED** but should have been DENIED."
        fi
    else
        if [ "$expected_result" = "deny" ]; then
            echo "✅ Client connect to port $port DENIED (as expected)."
        else
            echo "❌ Client connect to port $port **DENIED** but should have been allowed."
        fi
    fi
}

# --- Preparation ---
# Ensure a listening service is running on the allowed port outside the cgroup
# for the client test, or the client test will always fail by nature.
nc -l $ALLOWED_PORT >/dev/null 2>&1 &
NC_ALLOWED_PID=$!
sleep 1

echo
echo "===== 🧪 SERVER (BIND) TEST ====="
# The server will attempt to bind a port inside the restricted cgroup
run_server $ALLOWED_PORT   "allow"
run_server $DENIED_PORT    "deny"

echo
echo "===== 🧪 CLIENT (CONNECT) TEST ====="
# The client will attempt to connect from inside the restricted cgroup
run_client $ALLOWED_PORT   "allow"
run_client $DENIED_PORT    "deny"

# --- Cleanup ---
echo
echo "🧹 Cleaning up..."
sudo rm -rf "$CGROUP_PATH"
kill $NC_ALLOWED_PID 2>/dev/null || true