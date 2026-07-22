#!/usr/bin/env bash
set -euo pipefail

repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
server_dir="$repo_dir/csv-mcp-server"
run_dir="$repo_dir/.diewan/run"
pid_file="$run_dir/parwana-mcp.pid"
log_file="$run_dir/parwana-mcp.log"
port="${PARWANA_MCP_PORT:-3100}"

mkdir -p "$run_dir"
if [[ -f "$pid_file" ]] && kill -0 "$(<"$pid_file")" 2>/dev/null; then
  echo "Parwana MCP is already running (PID $(<"$pid_file"), http://127.0.0.1:$port/sse)."
  exit 0
fi
rm -f "$pid_file"
command -v npm >/dev/null || { echo "npm is required" >&2; exit 1; }
[[ -d "$server_dir/node_modules" ]] || { echo "Run 'npm ci' in $server_dir first." >&2; exit 1; }
(cd "$server_dir" && npm run build >>"$log_file" 2>&1)
(
  cd "$server_dir"
  exec nohup setsid node dist/index.js --sse --port="$port" >>"$log_file" 2>&1
) &
echo $! >"$pid_file"

ready=false
for _ in {1..30}; do
  if (echo >/dev/tcp/127.0.0.1/"$port") >/dev/null 2>&1; then ready=true; break; fi
  if ! kill -0 "$(<"$pid_file")" 2>/dev/null; then echo "Parwana MCP exited; inspect $log_file" >&2; exit 1; fi
  sleep 1
done
if [[ "$ready" != true ]]; then echo "Parwana MCP did not open port $port; inspect $log_file" >&2; exit 1; fi
echo "Parwana MCP is running at http://127.0.0.1:$port/sse (log: $log_file)."
