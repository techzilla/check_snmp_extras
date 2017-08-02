#!/bin/sh
##
## FILE: release-binary_rpm.sh
##
## DESCRIPTION: rpmbuild
##

## Exit Point
die() {
	[ -n "$2" ] && echo "$2"
	exit $1
}

##
command -v rpmbuild > /dev/null || die 78 'Required, rpmbuild'

## Goto Directory
OWD="$PWD"
command -v readlink > /dev/null && {
    cd "$(dirname "$(dirname "$(readlink -f scripts/release-binary_rpm.sh)")")"
    ## Git Bash Lacks Readlink
}

##
[ -d 'build' ] || {
    echo "Release Source Before Binary"
    exit 1
}

rpmbuild -ba --define "_topdir ${PWD}/build" --define "_sourcedir ${PWD}/build" contrib/*.spec


cd "$OWD"


## Exit Jump
die 0

