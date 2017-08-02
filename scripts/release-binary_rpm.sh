#!/bin/sh
##
## FILE: release-binary_rpm.sh
##
## DESCRIPTION: rpmbuild
##

command -v readlink > /dev/null && {
    OWD="$PWD"
    cd "$(dirname "$(dirname "$(readlink -f "$0")")")"
    . scripts/env.sh
} || {
    echo 'readlink required'
    exit 1
}

##
command -v rpmbuild > /dev/null || {
    echo 'rpmbuild required'
    exit 1
}

##
[ -d 'build' ] || {
    echo 'Release Source Before Binary'
    exit 1
}

rpmbuild -ba --define "__cmake $(which ${CMAKE_COMMAND})" --define "_topdir ${PWD}/build" --define "_sourcedir ${PWD}/build" contrib/*.spec


##
cd "$OWD"
exit 0
