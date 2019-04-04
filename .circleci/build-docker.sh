#!/usr/bin/env bash
#
# Rebuild and publish all docker images.
# Use the --dry-run argument to prevent the actual build process from running.
#
# Note: This script should not be triggered manually. Only run it in CI.
set -euo pipefail

if [[ "${1:-}" = "--dry-run" ]]; then
    echo -e "Dry run!"
    docker="echo > docker"
else
    docker="docker"
fi

# Determine supported tags
tags=$(git tag -l --sort=-v:refname | grep -E "${SUPPORTED_TAGS}" | tr '\n' ' ')
echo "Building tags: ${tags}"

# Build Docker images for supported tags
function needs () {
    local item match="${1}"
    shift
    for item; do [[ "${item}" = "${match}" ]] && return 1; done
    return 0
}
push_tags=()
for tag in ${tags}; do
    git checkout ${tag}
    ${docker} build \
        --no-cache \
        -t saltyrtc/saltyrtc-server-python:${tag:1} \
        .
    push_tags+=(${tag:1})
    minortag=$(echo ${tag} | sed 's/^\(v[0-9]*\.[0-9]*\)\..*$/\1/')
    if needs "${minortag:1}" "${push_tags[@]}"; then
        ${docker} tag \
            saltyrtc/saltyrtc-server-python:${tag:1} \
            saltyrtc/saltyrtc-server-python:${minortag:1}
        push_tags+=(${minortag:1})
    fi
    majortag=$(echo ${tag} | sed 's/^\(v[0-9]*\)\..*$/\1/')
    if needs "${majortag:1}" "${push_tags[@]}"; then
        ${docker} tag \
            saltyrtc/saltyrtc-server-python:${tag:1} \
            saltyrtc/saltyrtc-server-python:${majortag:1}
        push_tags+=(${majortag:1})
    fi
done
echo "Pushing tags: ${push_tags[@]}"

# Push Docker images for supported tags
for tag in ${push_tags[@]}; do
    ${docker} push saltyrtc/saltyrtc-server-python:${tag}
done
