#!/bin/sh
##
## FILE: install.sh
##
## DESCRIPTION: make install
##

## Exit Point
die() {
	[ -n "$2" ] && echo "$2"
	exit $1
}

## Goto Directory
OWD="$PWD"
command -v readlink > /dev/null && {
    cd "$(dirname "$(dirname "$(readlink -f scripts/release-binary_rpm.sh)")")"
    ## Git Bash Lacks Readlink
}

##
[ -d 'build' ] || {
    echo "Build Before Installing"
    exit 1
}
cd build 

make install

cd "$OWD"


## Exit Jump
die 0
