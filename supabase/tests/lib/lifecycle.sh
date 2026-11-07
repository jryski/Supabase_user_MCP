# shellcheck shell=bash
# Shared, verifiable lifecycle for the synthetic local Supabase harnesses.
#
# Sourced by run-s1-lab.sh and run-m2-memory-lab.sh after they set
# LC_TAG, PROJECT_ROOT, NETWORK_NAME and TMP_DIR.
#
# Guarantees:
# - Required commands are present before anything starts.
# - The fixed local project id from supabase/config.toml is never stopped on
#   behalf of a different checkout; a collision fails closed instead.
# - On exit, the stack is stopped and the result is verified: no containers or
#   volumes labelled with the project id remain, a network this run created is
#   removed, a pre-existing network is reported as retained, and the temporary
#   directory is gone. Any cleanup failure makes the harness exit non-zero.

LC_LABEL_PROJECT="com.supabase.cli.project"
LC_LABEL_WORKDIR="com.supabase.cli.workdir"
LC_NETWORK_CREATED=0
LC_OWNS_PROJECT=0
LC_NETWORK_PREEXISTING=0

lc_log() { printf '[%s] %s\n' "$LC_TAG" "$*"; }
lc_fail() { printf '[%s] FAIL: %s\n' "$LC_TAG" "$1" >&2; exit 1; }

lc_require_tools() {
  local missing=() tool
  for tool in "$@"; do
    command -v "$tool" >/dev/null 2>&1 || missing+=("$tool")
  done
  ((${#missing[@]} == 0)) || lc_fail "missing prerequisite command(s): ${missing[*]}"
}

lc_read_project_id() {
  LC_PROJECT_ID="$(sed -n 's/^project_id = "\([A-Za-z0-9_.-]\{1,\}\)"$/\1/p' \
    "$PROJECT_ROOT/supabase/config.toml" | head -n 1)"
  [[ -n "$LC_PROJECT_ID" ]] || lc_fail "supabase/config.toml has no usable project_id"
}

# Prints labelled container ids; returns non-zero if Docker cannot be queried.
lc_containers() {
  docker container ls -a -q --filter "label=${LC_LABEL_PROJECT}=${LC_PROJECT_ID}"
}

lc_volumes() {
  docker volume ls -q --filter "label=${LC_LABEL_PROJECT}=${LC_PROJECT_ID}"
}

# Refuse to stop a stack with the same fixed project id that belongs to another
# checkout. A leftover stack from this checkout is stopped and must stop.
lc_guard_project_collision() {
  local workdirs workdir
  workdirs="$(docker container ls -a \
    --filter "label=${LC_LABEL_PROJECT}=${LC_PROJECT_ID}" \
    --format "{{.Label \"${LC_LABEL_WORKDIR}\"}}")" \
    || lc_fail "could not query Docker for existing project containers"
  if [[ -z "$workdirs" ]]; then
    LC_OWNS_PROJECT=1
    return 0
  fi
  while IFS= read -r workdir; do
    if [[ -z "$workdir" || "$(cd "$workdir" 2>/dev/null && pwd -P)" != "$(cd "$PROJECT_ROOT" && pwd -P)" ]]; then
      lc_fail "local project id ${LC_PROJECT_ID} is already in use by another checkout or tool; stop that stack from its own checkout first. This harness will not stop it."
    fi
  done <<<"$workdirs"
  LC_OWNS_PROJECT=1
  lc_log "Stopping a leftover stack from this checkout."
  supabase stop --workdir "$PROJECT_ROOT" --no-backup >/dev/null 2>&1 \
    || lc_fail "could not stop the leftover stack from this checkout"
  [[ -z "$(lc_containers)" ]] || lc_fail "leftover project containers remain after stop"
}

lc_prepare_network() {
  local binding option="com.docker.network.bridge.host_binding_ipv4"
  if docker network inspect "$NETWORK_NAME" >/dev/null 2>&1; then
    binding="$(docker network inspect --format "{{ index .Options \"${option}\" }}" "$NETWORK_NAME")"
    [[ "$binding" == "127.0.0.1" ]] || lc_fail "existing Docker network ${NETWORK_NAME} is not loopback-only"
    LC_NETWORK_PREEXISTING=1
    lc_log "Using pre-existing loopback-only Docker network ${NETWORK_NAME}; it will be retained."
  else
    lc_log "Creating loopback-only Docker network ${NETWORK_NAME}; it will be removed on exit."
    docker network create --driver bridge --opt "${option}=127.0.0.1" "$NETWORK_NAME" >/dev/null
    LC_NETWORK_CREATED=1
  fi
}

lc_cleanup() {
  local rc=$? problems=() ids network_state
  trap - EXIT
  set +e
  # Only a project this checkout owns is ever stopped; a collision with
  # another checkout leaves that stack untouched.
  if [[ "$LC_OWNS_PROJECT" == 1 ]]; then
    if ids="$(lc_containers)"; then
      if [[ -n "$ids" ]]; then
        supabase stop --workdir "$PROJECT_ROOT" --no-backup >/dev/null 2>&1 \
          || problems+=("supabase stop failed")
      fi
      ids="$(lc_containers)" || problems+=("could not re-query project containers")
      [[ -z "$ids" ]] || problems+=("project containers remain")
      ids="$(lc_volumes)" || problems+=("could not query project volumes")
      [[ -z "$ids" ]] || problems+=("project volumes remain")
    else
      problems+=("could not query project containers")
    fi
  fi
  if [[ "$LC_NETWORK_CREATED" == 1 ]]; then
    docker network rm "$NETWORK_NAME" >/dev/null 2>&1
    if docker network inspect "$NETWORK_NAME" >/dev/null 2>&1; then
      problems+=("created network ${NETWORK_NAME} remains")
      network_state="removal-failed"
    else
      network_state="removed"
    fi
  elif [[ "$LC_NETWORK_PREEXISTING" == 1 ]]; then
    network_state="retained-preexisting"
  else
    network_state="not-used"
  fi
  [[ -z "${TMP_DIR:-}" ]] || rm -rf "$TMP_DIR"
  [[ -z "${TMP_DIR:-}" || ! -e "$TMP_DIR" ]] || problems+=("temporary directory remains")
  if ((${#problems[@]})); then
    printf '[%s] FAIL: cleanup not verified: %s\n' "$LC_TAG" "$(IFS=';'; printf '%s' "${problems[*]}")" >&2
    ((rc != 0)) || rc=1
  else
    if [[ "$LC_OWNS_PROJECT" != 1 ]]; then
      lc_log "Cleanup verified: project=${LC_PROJECT_ID:-none} not-owned-untouched network=${network_state} temp=removed"
    else
      lc_log "Cleanup verified: project=${LC_PROJECT_ID:-none} containers=0 volumes=0 network=${network_state} temp=removed"
    fi
  fi
  exit "$rc"
}
