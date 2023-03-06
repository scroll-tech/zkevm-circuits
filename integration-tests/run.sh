#!/bin/sh
set -e

ARG_DEFAULT_SUDO=
ARG_DEFAULT_STEPS="setup gendata tests cleanup"
ARG_DEFAULT_TESTS="rpc circuit_input_builder circuits::mock_prover"

usage() {
    cat >&2 << EOF
        Usage: $0 [OPTIONS]
        Options:
          --sudo         Use sudo for docker-compoes commands.
          --steps ARG    Space separated list of steps to do.
                         Default: "${ARG_DEFAULT_STEPS}".
          --tests ARG    Space separated list of tests to run.
                         Default: "${ARG_DEFAULT_TESTS}".
          -h | --help    Show help

EOF
}

ARG_SUDO="${ARG_DEFAULT_SUDO}"
ARG_STEPS="${ARG_DEFAULT_STEPS}"
ARG_TESTS="${ARG_DEFAULT_TESTS}"

while [ "$1" != "" ]; do
    case "$1" in
        --sudo )
            ARG_SUDO=1
        ;;
        --steps )
            shift
            ARG_STEPS="$1"
        ;;
        --tests )
            shift
            ARG_TESTS="$1"
        ;;
        -h | --help )
            usage
            exit
        ;;
        * )
            echo "Unknown flag \"$1\""
            usage
            exit 1
    esac
    shift
done

STEP_SETUP=
STEP_GENDATA=
STEP_TESTS=
STEP_CLEANUP=

for step in $ARG_STEPS; do
    case "$step" in
        setup )
            STEP_SETUP=1
        ;;
        gendata )
            STEP_GENDATA=1
        ;;
        tests )
            STEP_TESTS=1
        ;;
        cleanup )
            STEP_CLEANUP=1
        ;;
        * )
            echo "Unknown step \"$step\""
            usage
            exit 1
    esac
done

docker_compose_cmd() {
    if [ -n "$ARG_SUDO" ]; then
        sudo docker-compose $@
    else
        docker-compose $@
    fi
}

if [ -n "$STEP_SETUP" ]; then
    echo "+ Setup..."
    docker_compose_cmd down -v --remove-orphans
    docker_compose_cmd up -d geth0
fi

if [ -n "$STEP_GENDATA" ]; then
    echo "+ Gen blockchain data..."
    git submodule update --init --recursive --checkout contracts/vendor
    rm gendata_output.json > /dev/null 2>&1 || true
    cargo run --bin gen_blockchain_data
fi

if [ -n "$STEP_TESTS" ]; then
    for testname in $ARG_TESTS; do
        echo "+ Running test group $testname"
	cargo test --profile release --test $(echo $testname | sed -e 's/::/ /g') --all-features -- --nocapture
    done
fi

if [ -n "$STEP_CLEANUP" ]; then
    echo "+ Cleanup..."
    docker_compose_cmd down -v --remove-orphans
fi
