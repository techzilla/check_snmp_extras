#!/bin/sh
##
## FILE: release-source.sh
##
## DESCRIPTION: cmake make package_source
##

## Exit Point
die() {
	[ -n "$2" ] && echo "$2"
	exit $1
}

##
command -v cmake > /dev/null || die 78 'Required, cmake'

## Goto Directory
OWD="$PWD"
command -v readlink > /dev/null && {
    cd "$(dirname "$(dirname "$(readlink -f scripts/release-source.sh)")")"
    ## Git Bash Lacks Readlink
}

##
[ -d 'src' ] || {
    echo "Execute From Project Root"
    exit 1
}

## Prepare Build Directory
[ -d 'build' ] && {
    rm -rf build
}
mkdir build
cd build 

## Begin Build
cmake -DCMAKE_INSTALL_PREFIX=/usr -DCMAKE_BUILD_TYPE=Release ..
make package_source

cd "$OWD"


## Exit Jump
die 0
