#!/bin/sh
##
## FILE: install.sh
##
## DESCRIPTION: make install
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
[ -d 'build' ] || {
    echo 'Build Before Installing'
    exit 1
}
cd build 
make install


##
cd "$OWD"
exit 0
