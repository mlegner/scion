# This is a base file included/sourced by each border router acceptance test

export TEST_ARTIFACTS_DIR="${ACCEPTANCE_ARTIFACTS:?}/${TEST_NAME}"
TEST_DIR=${TEST_NAME}_acceptance
BRACCEPT=bin/braccept

UTIL_DIR=${UTIL_DIR:=acceptance/brutil}
BRUTIL=${BRUTIL:=$UTIL_DIR/util.sh}
COMMON_CONF_DIR=${COMMON_CONF_DIR:=$UTIL_DIR/conf}
DOCKER_COMPOSE_FN=${DOCKER_COMPOSE_FN:=$UTIL_DIR/docker-compose.yml}

BR_TOML_FN=${BR_TOML_FN:=br.toml}
BR_TOML=$TEST_ARTIFACTS_DIR/conf/$BR_TOML_FN

. $BRUTIL
. acceptance/common.sh

# Following are the functions required by the acceptance framework

# Each test should have its own set_veths function for specific setup
test_setup() {
    set -e

    # XXX(kormat): This is conditional on the binary existing, because when
    # running on CI 'setup' is run on the host, where the binary doesn't exist.
    [ -e $BRACCEPT ] && make -s setcap

    test_config

    local disp_dir="/run/shm/dispatcher"
    [ -d "$disp_dir" ] || mkdir "$disp_dir"
    [ $(stat -c "%U" "$disp_dir") == "$LOGNAME" ] || { sudo -p "Fixing ownership of $disp_dir - [sudo] password for %p: " chown $LOGNAME: "$disp_dir"; }

    sudo -p "Setup docker containers and virtual interfaces - [sudo] password for %p: " true
    # Bring up the dispatcher container and add new veth interfaces
    # This approach currently works because the dispatcher binds to 0.0.0.0 address.
    docker-compose -f $DOCKER_COMPOSE_FN --no-ansi up --detach dispatcher

    set_docker_ns_link

    set_veths

    docker-compose -f $DOCKER_COMPOSE_FN --no-ansi up --detach $BRID
    docker_status
}

test_config() {
    # Clear stale config files
    rm -rf "$TEST_ARTIFACTS_DIR/conf"

    # Create test directories
    mkdir -p $TEST_ARTIFACTS_DIR/conf $TEST_ARTIFACTS_DIR/logs

    # Copy common configuration
    cp -Lr "$COMMON_CONF_DIR/." "$TEST_ARTIFACTS_DIR/conf"

    # Copy custom test configuration files, ie. topology
    cp -Lr "acceptance/${TEST_DIR}/conf/." "$TEST_ARTIFACTS_DIR/conf"

    # Replace BR ID
    sed -i "s/ID = .*$/ID = \"${BRID}\"/g" "$BR_TOML"
    sed -i "s/Path = .*$/Path = \"\/share\/logs\/${BRID}.log\"/g" "$BR_TOML"
}

test_run() {
    set -e
    $BRACCEPT -testName "${TEST_NAME:?}" -keysDirPath "$TEST_ARTIFACTS_DIR/conf/keys" "$@"
}

test_teardown() {
    set -e
    sudo -p "Teardown docker containers and virtual interfaces - [sudo] password for %p: " true
    del_veths
    rm_docker_ns_link
    docker_status
    docker-compose -f $DOCKER_COMPOSE_FN --no-ansi down
}

print_help() {
    PROGRAM="$1"
    echo
	cat <<-_EOF
	    $PROGRAM name
	        return the name of this test
	    $PROGRAM setup
	        execute only the setup phase.
	    $PROGRAM run <args>
	        execute only the run phase (allows passing specific argumented to the test binary).
	    $PROGRAM teardown
	        execute only the teardown phase.
	_EOF
}

do_command() {
    PROGRAM="$1"
    COMMAND="$2"
    TEST_NAME="${3}"
    shift 3
    case "$COMMAND" in
        name)
            echo $TEST_NAME ;;
        setup|run|teardown)
            "test_$COMMAND" "$@" ;;
        *) print_help $PROGRAM; exit 1 ;;
    esac
}

