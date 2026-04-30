#!/usr/bin/env bash
set -euo pipefail

# Build and optionally push Docker images for Authelia.
# Usage: build-docker.sh [--push] [--platform <platform>] [--tag <tag>]

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

# Default values
PUSH=false
PLATFORM="linux/amd64"
TAG=""
DOCKERFILE="${PROJECT_ROOT}/Dockerfile"
IMAGE_NAME="authelia/authelia"

# Parse arguments
while [[ $# -gt 0 ]]; do
  case "$1" in
    --push)
      PUSH=true
      shift
      ;;
    --platform)
      PLATFORM="$2"
      shift 2
      ;;
    --tag)
      TAG="$2"
      shift 2
      ;;
    --image)
      IMAGE_NAME="$2"
      shift 2
      ;;
    --dockerfile)
      DOCKERFILE="$2"
      shift 2
      ;;
    *)
      echo "Unknown argument: $1" >&2
      exit 1
      ;;
  esac
done

# Determine the tag if not explicitly provided
if [[ -z "${TAG}" ]]; then
  if [[ -n "${BUILDKITE_TAG:-}" ]]; then
    TAG="${BUILDKITE_TAG}"
  elif [[ -n "${BUILDKITE_BRANCH:-}" ]]; then
    # Sanitize branch name for use as a Docker tag
    TAG="$(echo "${BUILDKITE_BRANCH}" | sed 's/[^a-zA-Z0-9._-]/-/g')"
  else
    TAG="dev"
  fi
fi

FULL_IMAGE="${IMAGE_NAME}:${TAG}"

echo "--- :docker: Building Docker image"
echo "  Image:      ${FULL_IMAGE}"
echo "  Platform:   ${PLATFORM}"
echo "  Dockerfile: ${DOCKERFILE}"
echo "  Push:       ${PUSH}"

# Build arguments
BUILD_ARGS=(
  "--file" "${DOCKERFILE}"
  "--platform" "${PLATFORM}"
  "--tag" "${FULL_IMAGE}"
  "--label" "org.opencontainers.image.revision=${BUILDKITE_COMMIT:-unknown}"
  "--label" "org.opencontainers.image.created=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  "--label" "org.opencontainers.image.version=${TAG}"
)

if [[ "${PUSH}" == "true" ]]; then
  BUILD_ARGS+=("--push")
else
  BUILD_ARGS+=("--load")
fi

BUILD_ARGS+=("${PROJECT_ROOT}")

# Ensure buildx builder is available
if ! docker buildx inspect authelia-builder &>/dev/null; then
  echo "--- :docker: Creating buildx builder instance"
  docker buildx create --name authelia-builder --use
fi

docker buildx build "${BUILD_ARGS[@]}"

echo "--- :docker: Build complete: ${FULL_IMAGE}"
