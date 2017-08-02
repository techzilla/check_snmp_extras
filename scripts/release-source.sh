#!/bin/sh
##
## FILE: release-source.sh
##
## DESCRIPTION: cmake make package_source
##

command -v readlink > /dev/null && {
    OWD="$PWD"
    cd "$(dirname "$(dirname "$(readlink -f "$0")")")"
    . scripts/env.sh
} || {
    echo 'readlink required'
    exit 1
}


## Confirm Lists
[ -f 'CMakeLists.txt' ] || {
    echo 'CMakeLists.txt required'
    exit 1

}

## Prepare Build Directory
[ -d 'build' ] && {
    rm -rf build
}
mkdir build
cd build 

## Begin Build
${CMAKE_COMMAND} -DCMAKE_INSTALL_PREFIX=/usr -DCMAKE_BUILD_TYPE=Release ..
make package_source


##
cd "$OWD"
exit 0
