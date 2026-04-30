#!/usr/bin/env bash
set -euo pipefail

# test-integration-suite.sh - Run a specific integration test suite for Authelia
# This script is used by Buildkite to run individual integration test suites
# in parallel across multiple agents.

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"

# Source common environment setup
if [[ -f "${DIR}/../hooks/pre-command" ]]; then
  # shellcheck disable=SC1091
  source "${DIR}/../hooks/pre-command" || true
fi

SUITE=${1:-}
if [[ -z "${SUITE}" ]]; then
  echo "Error: No test suite specified."
  echo "Usage: $0 <suite-name>"
  exit 1
fi

echo "--- :go: Running integration test suite: ${SUITE}"

# Ensure required environment variables are set
REQUIRED_VARS=("SUITE")
for var in "${REQUIRED_VARS[@]}"; do
  if [[ -z "${!var:-}" ]]; then
    echo "Error: Required environment variable '${var}' is not set."
    exit 1
  fi
done

# Default timeout for integration suites (in minutes)
TEST_TIMEOUT=${TEST_TIMEOUT:-10}

# Determine the log output directory
LOG_DIR="${LOG_DIR:-/tmp/authelia-integration-logs}"
mkdir -p "${LOG_DIR}"

echo "--- :docker: Starting test environment for suite: ${SUITE}"

# Bring up the required Docker Compose services for the suite
if [[ -f "internal/suites/${SUITE}/docker-compose.yml" ]]; then
  docker compose \
    -f internal/suites/docker-compose.yml \
    -f "internal/suites/${SUITE}/docker-compose.yml" \
    up -d --quiet-pull 2>&1 | tee "${LOG_DIR}/${SUITE}-compose.log"
else
  docker compose \
    -f internal/suites/docker-compose.yml \
    up -d --quiet-pull 2>&1 | tee "${LOG_DIR}/${SUITE}-compose.log"
fi

cleanup() {
  local exit_code=$?
  echo "--- :docker: Stopping test environment for suite: ${SUITE}"
  docker compose \
    -f internal/suites/docker-compose.yml \
    down --volumes --remove-orphans 2>/dev/null || true

  # Collect container logs on failure
  if [[ ${exit_code} -ne 0 ]]; then
    echo "+++ :warning: Test suite '${SUITE}' failed. Collecting container logs..."
    docker compose \
      -f internal/suites/docker-compose.yml \
      logs --no-color 2>/dev/null > "${LOG_DIR}/${SUITE}-containers.log" || true
  fi

  exit ${exit_code}
}

trap cleanup EXIT INT TERM

echo "+++ :go: Executing integration tests for suite: ${SUITE}"

# Run the integration tests for the specified suite
go test \
  -v \
  -timeout "${TEST_TIMEOUT}m" \
  -run "Test${SUITE}Suite" \
  ./internal/suites/... \
  2>&1 | tee "${LOG_DIR}/${SUITE}-tests.log"

TEST_EXIT_CODE=${PIPESTATUS[0]}

if [[ ${TEST_EXIT_CODE} -ne 0 ]]; then
  echo "+++ :x: Integration test suite '${SUITE}' FAILED (exit code: ${TEST_EXIT_CODE})"
else
  echo "--- :white_check_mark: Integration test suite '${SUITE}' PASSED"
fi

exit ${TEST_EXIT_CODE}
