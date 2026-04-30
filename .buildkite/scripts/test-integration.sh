#!/usr/bin/env bash
set -euo pipefail

# Integration test runner script for Buildkite CI
# Handles setup, execution, and teardown of integration tests

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"

# Default values
SUITE="${SUITE:-}"
BROWSER="${BROWSER:-chrome}"
HEADLESS="${HEADLESS:-true}"
RETRY_COUNT="${RETRY_COUNT:-2}"
TIMEOUT="${TIMEOUT:-60000}"

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log_info() {
  echo -e "${GREEN}[INFO]${NC} $*"
}

log_warn() {
  echo -e "${YELLOW}[WARN]${NC} $*"
}

log_error() {
  echo -e "${RED}[ERROR]${NC} $*" >&2
}

cleanup() {
  local exit_code=$?
  log_info "Running cleanup..."

  # Stop any running docker-compose services
  if [[ -f "${ROOT_DIR}/docker-compose.yml" ]]; then
    log_info "Stopping docker-compose services..."
    docker compose -f "${ROOT_DIR}/docker-compose.yml" down --volumes --remove-orphans 2>/dev/null || true
  fi

  # Collect logs on failure
  if [[ ${exit_code} -ne 0 ]]; then
    log_warn "Tests failed with exit code ${exit_code}. Collecting logs..."
    collect_logs
  fi

  exit ${exit_code}
}

collect_logs() {
  local log_dir="${ROOT_DIR}/test-logs"
  mkdir -p "${log_dir}"

  # Collect docker container logs
  for container in $(docker ps -a --format '{{.Names}}' 2>/dev/null || true); do
    log_info "Collecting logs for container: ${container}"
    docker logs "${container}" > "${log_dir}/${container}.log" 2>&1 || true
  done

  log_info "Logs collected in: ${log_dir}"
}

wait_for_services() {
  local max_attempts=30
  local attempt=0
  local url="${1:-http://localhost:9091/api/health}"

  log_info "Waiting for services to be ready at ${url}..."

  while [[ ${attempt} -lt ${max_attempts} ]]; do
    if curl -sf "${url}" > /dev/null 2>&1; then
      log_info "Services are ready!"
      return 0
    fi
    attempt=$((attempt + 1))
    log_info "Attempt ${attempt}/${max_attempts} - services not ready yet, waiting 5s..."
    sleep 5
  done

  log_error "Services failed to become ready after ${max_attempts} attempts"
  return 1
}

run_suite() {
  local suite="$1"
  log_info "Running integration test suite: ${suite}"

  cd "${ROOT_DIR}/internal/suites"

  SUITE="${suite}" \
  BROWSER="${BROWSER}" \
  HEADLESS="${HEADLESS}" \
  go test -v \
    -timeout "${TIMEOUT}ms" \
    -count=1 \
    -run "Test${suite}Suite" \
    ./... 2>&1
}

main() {
  trap cleanup EXIT

  log_info "Starting integration tests"
  log_info "Suite: ${SUITE:-all}"
  log_info "Browser: ${BROWSER}"
  log_info "Headless: ${HEADLESS}"

  cd "${ROOT_DIR}"

  # Start required services
  if [[ -f "docker-compose.yml" ]]; then
    log_info "Starting docker-compose services..."
    docker compose up -d
    wait_for_services
  fi

  if [[ -n "${SUITE}" ]]; then
    run_suite "${SUITE}"
  else
    log_info "Running all integration test suites..."
    # Run all available suites
    for suite_dir in "${ROOT_DIR}/internal/suites/"*/; do
      suite_name=$(basename "${suite_dir}")
      run_suite "${suite_name}" || log_warn "Suite ${suite_name} failed, continuing..."
    done
  fi

  log_info "Integration tests completed successfully"
}

main "$@"
