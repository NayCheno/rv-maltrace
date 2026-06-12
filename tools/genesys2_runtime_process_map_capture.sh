#!/bin/sh
set -u

sample_id="${1:?sample id required}"
sample_class="${2:-p0_safe_synthetic}"
runtime_path="${3:?runtime path required}"
mode="${4:-trace-on}"
rep="${5:-0}"
warmup="${6:-1}"
settle="${7:-0.5}"
target_first="${8:-1}"
runner_maps="${9:-0}"
stop_for_map="${10:-1}"

hex() {
  printf '%s' "$1" | od -An -tx1 -v | tr -d ' \n'
}

emit_proc() {
  role="$1"
  pid="$2"
  include_maps="$3"
  if [ -r "/proc/$pid/comm" ] && [ -r "/proc/$pid/maps" ]; then
    comm=$(cat "/proc/$pid/comm" 2>/dev/null | tr -d '\r\n')
    cmdline=$(tr '\000' ' ' < "/proc/$pid/cmdline" 2>/dev/null | sed 's/[[:space:]]*$//')
    exe=$(readlink "/proc/$pid/exe" 2>/dev/null || true)
    echo "RVMT_RUNTIME_PROCESS role=$role pid=$pid tgid=$pid comm_hex=$(hex "$comm") cmdline_hex=$(hex "$cmdline") exe_hex=$(hex "$exe") status=PASS"
    if [ "$include_maps" = "1" ]; then
      while IFS= read -r line; do
        echo "RVMT_RUNTIME_PROCESS_MAP_RAW role=$role line_hex=$(hex "$line")"
      done < "/proc/$pid/maps"
    fi
  else
    echo "RVMT_RUNTIME_PROCESS role=$role pid=$pid tgid=$pid comm_hex= cmdline_hex= exe_hex= status=BLOCKED"
  fi
}

echo "RVMT_RUNTIME_PROCESS_MAP_BEGIN schema=rvmt.runtime_process_map.v1 class=$sample_class sample=$sample_id mode=$mode rep=$rep warmup=$warmup"
"$runtime_path" &
target_pid=$!
sleep "$settle"

if [ "$stop_for_map" = "1" ]; then
  kill -STOP "$target_pid" 2>/dev/null || true
fi

if [ "$target_first" = "1" ]; then
  emit_proc target_child "$target_pid" 1
  emit_proc runner_parent $$ "$runner_maps"
else
  emit_proc runner_parent $$ "$runner_maps"
  emit_proc target_child "$target_pid" 1
fi

if [ "$stop_for_map" = "1" ]; then
  kill -CONT "$target_pid" 2>/dev/null || true
fi

echo "RVMT_RUNTIME_PROCESS_PROVENANCE collector=tools/genesys2_runtime_process_map_capture.sh method=genesys2_uart_procfs_snapshot proc_sample_time=$(date +%Y%m%dT%H%M%S 2>/dev/null || echo unknown) status=PASS warnings_hex="
wait "$target_pid"
target_exit=$?
echo "RVMT_RUNTIME_PROCESS_MAP_END status=PASS target_exit=$target_exit"
