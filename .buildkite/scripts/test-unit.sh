#!/usr/bin/env bash
set -euo pipefail

# test-unit.sh - Run unit tests for Authelia with coverage reporting
#
# This script executes the Go unit test suite, generates coverage reports,
# and optionally uploads results to Buildkite Test Analytics.

ROOT_DIR="$(git rev-parse --show-toplevel)"
COVERAGE_DIR="${ROOT_DIR}/coverage"
COVERAGE_FILE="${COVERAGE_DIR}/coverage.out"
COVERAGE_HTML="${COVERAGE_DIR}/coverage.html"
JUNIT_REPORT="${COVERAGE_DIR}/junit.xml"

# Ensure coverage directory exists
mkdir -p "${COVERAGE_DIR}"

echo "--- :go: Setting up Go environment"
go version
go env

echo "--- :broom: Tidying Go modules"
cd "${ROOT_DIR}"
go mod tidy

echo "--- :hammer_and_wrench: Building test dependencies"
go build ./...

echo "+++ :test_tube: Running unit tests"
go test \
  -v \
  -race \
  -covermode=atomic \
  -coverprofile="${COVERAGE_FILE}" \
  -timeout 300s \
  ./... 2>&1 | tee /tmp/test-output.txt

TEST_EXIT_CODE=${PIPESTATUS[0]}

echo "--- :bar_chart: Generating coverage report"
if [[ -f "${COVERAGE_FILE}" ]]; then
  go tool cover -html="${COVERAGE_FILE}" -o "${COVERAGE_HTML}"
  COVERAGE_PCT=$(go tool cover -func="${COVERAGE_FILE}" | grep total | awk '{print $3}')
  echo "Total coverage: ${COVERAGE_PCT}"
else
  echo "Warning: No coverage file generated"
fi

# Generate JUnit XML report if gotestsum is available
if command -v gotestsum &>/dev/null; then
  echo "--- :clipboard: Generating JUnit report"
  gotestsum \
    --junitfile="${JUNIT_REPORT}" \
    --format=standard-quiet \
    -- -coverprofile="${COVERAGE_FILE}" ./... || true
fi

# Upload test results to Buildkite Test Analytics if token is set
if [[ -n "${BUILDKITE_ANALYTICS_TOKEN:-}" ]]; then
  echo "--- :buildkite: Uploading test analytics"
  if [[ -f "${JUNIT_REPORT}" ]]; then
    curl \
      --fail \
      --silent \
      --request POST \
      --url "https://analytics-api.buildkite.com/v1/uploads" \
      --header "Authorization: Token token=\"${BUILDKITE_ANALYTICS_TOKEN}\"" \
      --form "data=@${JUNIT_REPORT}" \
      --form "format=junit" \
      --form "run_env[CI]=buildkite" \
      --form "run_env[key]=${BUILDKITE_BUILD_ID}" \
      --form "run_env[number]=${BUILDKITE_BUILD_NUMBER}" \
      --form "run_env[branch]=${BUILDKITE_BRANCH}" \
      --form "run_env[commit_sha]=${BUILDKITE_COMMIT}" \
      --form "run_env[message]=${BUILDKITE_MESSAGE}" \
      --form "run_env[url]=${BUILDKITE_BUILD_URL}" || echo "Warning: Failed to upload test analytics"
  fi
fi

echo "--- :page_facing_up: Test summary"
if [[ ${TEST_EXIT_CODE} -ne 0 ]]; then
  echo "Unit tests FAILED with exit code ${TEST_EXIT_CODE}"
else
  echo "Unit tests PASSED"
fi

exit ${TEST_EXIT_CODE}
