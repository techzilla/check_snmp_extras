#!/bin/sh
##
## FILE: build.sh
##
## DESCRIPTION: cmake make build
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
    cd "$(dirname "$(dirname "$(readlink -f scripts/build.sh)")")"
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
make

cd "$OWD"


## Exit Jump
die 0
