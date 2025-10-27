#!/bin/bash

SCRIPT_NAME=$(basename $0)

function usage {
    echo "Usage: $SCRIPT_NAME [options]"
    echo "Options:"
    echo "  --cache    Use the cache normally when building the image"
    echo "  --no-cache Don't use the cache at all when building the image"
    echo "  --verbose  Display build logs"
    echo "  --help     Display this help screen"
    echo "Notes:"
    echo "  - If --cache and --no-cache are both omitted, then 3rd party"
    echo "    packages are cached, but local packages that are in flux"
    echo "    are not cached."
    echo "  - Normally, without the --verbose option, docker build is"
    echo "    called with the -q option, which suppresses build output."
    if [ "$HELP" = true ]; then
        exit 0
    else
        exit 1
    fi
}

CACHE=false
NO_CACHE=false
QUIET="-q"
HELP=false

# Parse arguments
while [ $# -gt 0 ]; do
    case "$1" in
        --cache)
            CACHE=true
            ;;
        --no-cache)
            NO_CACHE=true
            ;;
        --verbose)
            QUIET=""
            ;;
        --help)
            HELP=true
            usage
            ;;
        *)
            usage
            ;;
    esac
    shift
done

if [ "$NO_CACHE" = true ]; then
    echo "docker build $QUIET --no-cache -t macnod/rbac-test:latest ."
    docker build $QUIET --no-cache -t "macnod/rbac-test:latest" .
elif [ "$CACHE" = true ]; then
    echo "docker build $QUIET -t macnod/rbac-test:latest ."
    docker build $QUIET -t "macnod/rbac-test:latest" .
else
    echo "docker build $QUIET --build-arg CACHEBUST=$(date +%s) -t macnod/rbac-test:latest ."
    docker build $QUIET --build-arg CACHEBUST=$(date +%s) -t "macnod/rbac-test:latest" .
fi
