#!/bin/bash

set -euo pipefail

usage() {
    cat <<'EOF'
Usage: sudo ./tests/two-node-lan/run-macos.sh [options]

Options:
  --left-visible NAME   Host-visible left feth (default: feth6100)
  --left-peer NAME      Stella I/O left feth (default: feth6101)
  --right-visible NAME  Host-visible right feth (default: feth6102)
  --right-peer NAME     Stella I/O right feth (default: feth6103)
  --python PATH         Python with pip support (default: python3)
  --artifacts PATH      Create-new artifact directory
  --controller-port N   Controller TCP port (default: 44990)
  --left-udp-port N     Left client UDP port (default: 45101)
  --right-udp-port N    Right client UDP port (default: 45102)
  --skip-build          Use existing target/release binaries
  -h, --help            Show this help
EOF
}

left_visible="feth6100"
left_peer="feth6101"
right_visible="feth6102"
right_peer="feth6103"
python="python3"
artifacts=""
controller_port=44990
left_udp_port=45101
right_udp_port=45102
skip_build=0

while (($# > 0)); do
    case "$1" in
        --left-visible)
            left_visible=$2
            shift 2
            ;;
        --left-peer)
            left_peer=$2
            shift 2
            ;;
        --right-visible)
            right_visible=$2
            shift 2
            ;;
        --right-peer)
            right_peer=$2
            shift 2
            ;;
        --python)
            python=$2
            shift 2
            ;;
        --artifacts)
            artifacts=$2
            shift 2
            ;;
        --controller-port)
            controller_port=$2
            shift 2
            ;;
        --left-udp-port)
            left_udp_port=$2
            shift 2
            ;;
        --right-udp-port)
            right_udp_port=$2
            shift 2
            ;;
        --skip-build)
            skip_build=1
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "unknown option: $1" >&2
            usage >&2
            exit 2
            ;;
    esac
done

if ((EUID != 0)); then
    echo "run this end-to-end test as root" >&2
    exit 1
fi

interfaces=("$left_visible" "$left_peer" "$right_visible" "$right_peer")
for interface in "${interfaces[@]}"; do
    if [[ ! $interface =~ ^feth[0-9]+$ ]]; then
        echo "invalid feth interface name: $interface" >&2
        exit 1
    fi
done
for ((left = 0; left < ${#interfaces[@]}; left++)); do
    for ((right = left + 1; right < ${#interfaces[@]}; right++)); do
        if [[ ${interfaces[$left]} == "${interfaces[$right]}" ]]; then
            echo "all four feth interface names must be distinct" >&2
            exit 1
        fi
    done
done

script_directory=$(cd "$(dirname "$0")" && pwd)
repository=$(cd "$script_directory/../.." && pwd)
server="$repository/target/release/stella-server"
client="$repository/target/release/stella-client"
helper="$repository/target/release/stella-tap-helper"
helper_socket="/var/run/stella-tap-helper.sock"
verifier="$script_directory/verify_l2.py"
requirements="$script_directory/requirements.txt"
if [[ -z $artifacts ]]; then
    artifacts="${TMPDIR:-/tmp}/stella-two-node-macos-$(date -u +%Y%m%d-%H%M%S)"
fi
if [[ -e $artifacts ]]; then
    echo "artifact directory already exists: $artifacts" >&2
    exit 1
fi
artifacts=$(mkdir -p "$(dirname "$artifacts")" && cd "$(dirname "$artifacts")" && pwd)/$(basename "$artifacts")

for interface in "${interfaces[@]}"; do
    if /sbin/ifconfig "$interface" >/dev/null 2>&1; then
        echo "refusing to reuse pre-existing interface: $interface" >&2
        exit 1
    fi
done

mkdir -p "$artifacts"
server_config="$artifacts/server/server.toml"
left_config="$artifacts/left/client.toml"
right_config="$artifacts/right/client.toml"
scapy="$artifacts/python-packages"
server_pid=""
left_pid=""
right_pid=""
helper_pid=""
helper_socket_identity=""
current_stage="initialization"
completed=0

stop_process() {
    local pid=$1
    local signal=${2:-INT}
    local deadline
    local state
    [[ -n $pid ]] || return 0
    kill -0 "$pid" >/dev/null 2>&1 || return 0
    kill -"$signal" "$pid" >/dev/null 2>&1 || true
    deadline=$((SECONDS + 10))
    while kill -0 "$pid" >/dev/null 2>&1 && ((SECONDS < deadline)); do
        state=$(ps -o state= -p "$pid" 2>/dev/null | tr -d ' ') || state=""
        if [[ -z $state || $state == Z* ]]; then
            wait "$pid" >/dev/null 2>&1 || true
            return 0
        fi
        sleep 0.1
    done
    if kill -0 "$pid" >/dev/null 2>&1; then
        kill -TERM "$pid" >/dev/null 2>&1 || true
        sleep 0.5
    fi
    if kill -0 "$pid" >/dev/null 2>&1; then
        kill -KILL "$pid" >/dev/null 2>&1 || true
    fi
    wait "$pid" >/dev/null 2>&1 || true
}

cleanup() {
    local exit_status=$?
    set +e
    stop_process "$left_pid"
    stop_process "$right_pid"
    stop_process "$helper_pid" TERM
    stop_process "$server_pid"
    if [[ -n $helper_socket_identity && -S $helper_socket ]] && \
        [[ $(/usr/bin/stat -f '%d:%i' "$helper_socket" 2>/dev/null) == "$helper_socket_identity" ]]; then
        rm -f "$helper_socket"
    fi
    for interface in "$right_peer" "$right_visible" "$left_peer" "$left_visible"; do
        if /sbin/ifconfig "$interface" >/dev/null 2>&1; then
            /sbin/ifconfig "$interface" destroy >/dev/null 2>&1 || true
        fi
    done
    if ((completed == 0)); then
        echo "FAIL: macOS E2E stopped during $current_stage (exit status $exit_status); artifacts=$artifacts" >&2
    fi
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

wait_tcp_port() {
    local port=$1
    local pid=$2
    local deadline=$((SECONDS + 15))
    while ((SECONDS < deadline)); do
        if ! kill -0 "$pid" >/dev/null 2>&1; then
            echo "controller exited before accepting connections" >&2
            return 1
        fi
        if "$python" -c 'import socket,sys; s=socket.socket(); s.settimeout(.2); s.connect(("127.0.0.1", int(sys.argv[1]))); s.close()' "$port" >/dev/null 2>&1; then
            return 0
        fi
        sleep 0.2
    done
    echo "controller did not listen on 127.0.0.1:$port" >&2
    return 1
}

wait_helper_socket() {
    local deadline=$((SECONDS + 10))
    while ((SECONDS < deadline)); do
        if ! kill -0 "$helper_pid" >/dev/null 2>&1; then
            echo "TAP helper exited before creating its socket" >&2
            return 1
        fi
        if [[ -S $helper_socket ]]; then
            return 0
        fi
        sleep 0.1
    done
    echo "TAP helper did not create $helper_socket" >&2
    return 1
}

wait_log() {
    local stdout_path=$1
    local stderr_path=$2
    local pattern=$3
    local pid=$4
    local deadline=$((SECONDS + 45))
    while ((SECONDS < deadline)); do
        if ! kill -0 "$pid" >/dev/null 2>&1; then
            echo "process exited before log pattern '$pattern'" >&2
            return 1
        fi
        if grep -Fq "$pattern" "$stdout_path" 2>/dev/null || grep -Fq "$pattern" "$stderr_path" 2>/dev/null; then
            return 0
        fi
        if grep -Fq "active data plane ended" "$stdout_path" 2>/dev/null || \
            grep -Fq "active data plane ended" "$stderr_path" 2>/dev/null; then
            echo "client data plane failed before reporting '$pattern'" >&2
            tail -n 12 "$stdout_path" "$stderr_path" >&2
            return 1
        fi
        sleep 0.25
    done
    echo "timed out waiting for '$pattern'" >&2
    return 1
}

add_advertised_endpoint() {
    local config_path=$1
    local port=$2
    "$python" - "$config_path" "$port" <<'PY'
from pathlib import Path
import sys

path = Path(sys.argv[1])
port = int(sys.argv[2])
text = path.read_text(encoding="utf-8")
needle = f'udp_bind = "127.0.0.1:{port}"\nadvertised_endpoints = []'
replacement = (
    f'udp_bind = "127.0.0.1:{port}"\n\n'
    '[[transport.advertised_endpoints]]\n'
    f'address = "127.0.0.1:{port}"\n'
    'priority = 0\n'
    'max_datagram_size = 1200'
)
if text.count(needle) != 1:
    raise SystemExit("generated client configuration has an unexpected transport block")
path.write_text(text.replace(needle, replacement), encoding="utf-8")
PY
}

key_value() {
    local text=$1
    local key=$2
    printf '%s\n' "$text" | awk -F= -v key="$key" '$1 == key { print substr($0, length(key) + 2); exit }'
}

interface_mac() {
    /sbin/ifconfig "$1" | awk '$1 == "ether" { print $2; exit }'
}

wait_pair_persisted_and_visible_down() {
    local visible=$1
    local peer=$2
    local deadline=$((SECONDS + 5))
    local first_line
    while ((SECONDS < deadline)); do
        if /sbin/ifconfig "$visible" >/dev/null 2>&1 && \
            /sbin/ifconfig "$peer" >/dev/null 2>&1; then
            first_line=$(/sbin/ifconfig "$visible" | sed -n '1p')
            if [[ $first_line != *"<UP,"* && $first_line != *",UP,"* && $first_line != *",UP>"* ]]; then
                return 0
            fi
        fi
        sleep 0.1
    done
    echo "feth pair did not persist in the down state after client shutdown: $visible/$peer" >&2
    /sbin/ifconfig "$visible" >&2 || true
    /sbin/ifconfig "$peer" >&2 || true
    return 1
}

start_clients() {
    local phase=$1
    local left_stdout="$artifacts/left.$phase.stdout.log"
    local left_stderr="$artifacts/left.$phase.stderr.log"
    local right_stdout="$artifacts/right.$phase.stdout.log"
    local right_stderr="$artifacts/right.$phase.stderr.log"
    "$client" --config "$left_config" run >"$left_stdout" 2>"$left_stderr" &
    left_pid=$!
    "$client" --config "$right_config" run >"$right_stdout" 2>"$right_stderr" &
    right_pid=$!
    wait_log "$left_stdout" "$left_stderr" "macOS data plane is active" "$left_pid"
    wait_log "$right_stdout" "$right_stderr" "macOS data plane is active" "$right_pid"
    sleep 2
}

stop_clients_and_verify_persistence() {
    stop_process "$left_pid"
    stop_process "$right_pid"
    left_pid=""
    right_pid=""
    wait_pair_persisted_and_visible_down "$left_visible" "$left_peer"
    wait_pair_persisted_and_visible_down "$right_visible" "$right_peer"
}

run_verifier() {
    local output=$1
    PYTHONPATH="$scapy" "$python" "$verifier" \
        --left-interface "$left_visible" \
        --right-interface "$right_visible" \
        --left-mac "$left_mac" \
        --right-mac "$right_mac" \
        --output "$output"
}

current_stage="release build"
if ((skip_build == 0)); then
    if [[ -n ${SUDO_USER:-} && ${SUDO_USER} != root ]]; then
        cargo_path=$(command -v cargo)
        sudo -u "$SUDO_USER" -H "$cargo_path" build --manifest-path "$repository/Cargo.toml" --release -p stella-server -p stella-client -p stella-tap
    else
        cargo build --manifest-path "$repository/Cargo.toml" --release -p stella-server -p stella-client -p stella-tap
    fi
fi
if [[ ! -x $server || ! -x $client || ! -x $helper ]]; then
    echo "release binaries are missing; rerun without --skip-build" >&2
    exit 1
fi
if [[ -e $helper_socket ]]; then
    echo "refusing to replace an existing helper socket: $helper_socket" >&2
    exit 1
fi

current_stage="TAP helper startup"
"$helper" --allow-uid 0 >"$artifacts/helper.stdout.log" 2>"$artifacts/helper.stderr.log" &
helper_pid=$!
wait_helper_socket
helper_socket_identity=$(/usr/bin/stat -f '%d:%i' "$helper_socket")

current_stage="controller and client configuration"
init_output=$("$server" --config "$server_config" init --listen "127.0.0.1:$controller_port" --tls-name localhost)
controller_id=$(key_value "$init_output" controller_id)
tls_spki_pin=$(key_value "$init_output" tls_spki_pin)
if [[ -z $controller_id || -z $tls_spki_pin ]]; then
    echo "controller initialization returned incomplete trust material" >&2
    exit 1
fi
network_id=$("$server" --config "$server_config" network create --name "Stella macOS two-node LAN" --id 77777777777777777777777777777777)
left_enrollment=$("$server" --config "$server_config" enrollment-token create)
right_enrollment=$("$server" --config "$server_config" enrollment-token create)
left_join=$("$server" --config "$server_config" join-token create --network "$network_id")
right_join=$("$server" --config "$server_config" join-token create --network "$network_id")

"$client" --config "$left_config" init \
    --controller "127.0.0.1:$controller_port" \
    --tls-name localhost \
    --controller-id "$controller_id" \
    --spki-pin "$tls_spki_pin" \
    --display-name "Stella macOS Node A" \
    --udp-bind "127.0.0.1:$left_udp_port"
"$client" --config "$right_config" init \
    --controller "127.0.0.1:$controller_port" \
    --tls-name localhost \
    --controller-id "$controller_id" \
    --spki-pin "$tls_spki_pin" \
    --display-name "Stella macOS Node B" \
    --udp-bind "127.0.0.1:$right_udp_port"
add_advertised_endpoint "$left_config" "$left_udp_port"
add_advertised_endpoint "$right_config" "$right_udp_port"

current_stage="controller startup"
"$server" --config "$server_config" run >"$artifacts/server.stdout.log" 2>"$artifacts/server.stderr.log" &
server_pid=$!
wait_tcp_port "$controller_port" "$server_pid"

current_stage="network join"
"$client" --config "$left_config" join \
    --network "$network_id" \
    --token "$left_join" \
    --enrollment-token "$left_enrollment" \
    --tap-adapter "$left_visible" \
    --tap-peer "$left_peer"
"$client" --config "$right_config" join \
    --network "$network_id" \
    --token "$right_join" \
    --enrollment-token "$right_enrollment" \
    --tap-adapter "$right_visible" \
    --tap-peer "$right_peer"
unset left_enrollment right_enrollment left_join right_join

echo "INFO: starting initial client data planes"
current_stage="initial client startup"
start_clients first
left_mac=$(interface_mac "$left_visible")
right_mac=$(interface_mac "$right_visible")
if [[ -z $left_mac || -z $right_mac ]]; then
    echo "could not read feth MAC addresses" >&2
    exit 1
fi

current_stage="Scapy installation"
PIP_ROOT_USER_ACTION=ignore "$python" -m pip install \
    --disable-pip-version-check \
    --no-cache-dir \
    --target "$scapy" \
    -r "$requirements"
echo "INFO: running initial L2 verification"
current_stage="initial L2 verification"
run_verifier "$artifacts/l2-report.json"
echo "PASS: initial L2 verification"
echo "INFO: stopping initial clients and checking persistent feth pairs"
current_stage="initial persistent-pair check"
stop_clients_and_verify_persistence
echo "PASS: initial feth pairs persisted with visible interfaces down"

echo "INFO: restarting clients with the same feth pairs"
current_stage="reuse client startup"
start_clients reuse
echo "INFO: running persistent-pair reuse L2 verification"
current_stage="reuse L2 verification"
run_verifier "$artifacts/l2-reuse-report.json"
echo "PASS: persistent-pair reuse L2 verification"
echo "INFO: stopping reused clients and checking persistent feth pairs"
current_stage="reuse persistent-pair check"
stop_clients_and_verify_persistence
echo "PASS: reused feth pairs persisted with visible interfaces down"

current_stage="summary generation"
git_commit=$(git -C "$repository" rev-parse HEAD)
"$python" - "$artifacts/l2-report.json" "$artifacts/l2-reuse-report.json" "$artifacts/summary.md" \
    "$git_commit" "$left_visible" "$left_peer" "$left_mac" "$right_visible" "$right_peer" "$right_mac" "$controller_port" <<'PY'
import datetime
import json
from pathlib import Path
import sys

first = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
reuse = json.loads(Path(sys.argv[2]).read_text(encoding="utf-8"))
output = Path(sys.argv[3])
commit, left, left_peer, left_mac, right, right_peer, right_mac, port = sys.argv[4:]
lines = [
    "# Stella macOS two-node LAN verification",
    "",
    f"- UTC: {datetime.datetime.now(datetime.timezone.utc).isoformat()}",
    f"- Git commit: {commit}",
    f"- Left feth pair: {left}/{left_peer} ({left_mac})",
    f"- Right feth pair: {right}/{right_peer} ({right_mac})",
    f"- Controller: 127.0.0.1:{port}",
    f"- Initial result: {'PASS' if first['passed'] else 'FAIL'}",
    f"- Persistent-pair reuse result: {'PASS' if reuse['passed'] else 'FAIL'}",
    "",
    "## Initial run",
    "",
]
for check in first["checks"]:
    lines.append(f"- {'[x]' if check['passed'] else '[ ]'} {check['name']}: {check['detail']}")
lines.extend(["", "## Reuse run", ""])
for check in reuse["checks"]:
    lines.append(f"- {'[x]' if check['passed'] else '[ ]'} {check['name']}: {check['detail']}")
output.write_text("\n".join(lines) + "\n", encoding="utf-8")
PY

completed=1
echo "PASS: artifacts=$artifacts"
