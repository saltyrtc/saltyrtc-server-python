#!/usr/bin/env bash
#
# Rebuild, test and publish all docker images.
# Use the --dry-run argument to prevent the actual build process from running.
#
# Note: This script should not be triggered manually. Only run it in CI.
set -euo pipefail

# Determine tags to build
build_tags=()
for tag in $(git tag -l --sort=-v:refname | tr '\n' ' '); do
    if [ -f "${tag}.Dockerfile" ]; then
        build_tags+=(${tag})
    fi
done

# Build and test Docker images
echo "Building tags: ${build_tags[@]}"
function needs () {
    local item match="${1}"
    shift
    for item; do [[ "${item}" = "${match}" ]] && return 1; done
    return 0
}
push_tags=()
for tag in ${build_tags}; do
    git worktree add ./src-${tag} ${tag}
    cp ./${tag}.* ./src-${tag}/
    cd ./src-${tag}
    if [ -f "${tag}.patch" ]; then
        git apply ./${tag}.patch
    fi
    docker build \
        --no-cache \
        -t saltyrtc/saltyrtc-server-python:${tag:1} \
        -f ${tag}.Dockerfile \
        .
    cd -
    docker run --entrypoint /bin/bash \
        saltyrtc/saltyrtc-server-python:${tag:1} \
        -c "pip install .[dev] && py.test -k 'not test_generate_key_invalid_permissions'"
    push_tags+=(${tag:1})
    minortag=$(echo ${tag} | sed 's/^\(v[0-9]*\.[0-9]*\)\..*$/\1/')
    if needs "${minortag:1}" "${push_tags[@]}"; then
        docker tag \
            saltyrtc/saltyrtc-server-python:${tag:1} \
            saltyrtc/saltyrtc-server-python:${minortag:1}
        push_tags+=(${minortag:1})
    fi
    majortag=$(echo ${tag} | sed 's/^\(v[0-9]*\)\..*$/\1/')
    if needs "${majortag:1}" "${push_tags[@]}"; then
        docker tag \
            saltyrtc/saltyrtc-server-python:${tag:1} \
            saltyrtc/saltyrtc-server-python:${majortag:1}
        push_tags+=(${majortag:1})
    fi
done

# Push Docker images
echo "Pushing tags: ${push_tags[@]}"
docker login -u ${DOCKER_USER} -p ${DOCKER_API_KEY}
for tag in ${push_tags[@]}; do
    docker push saltyrtc/saltyrtc-server-python:${tag}
done
