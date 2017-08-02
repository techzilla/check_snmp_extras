
## Set CMake Binary
command -v cmake > /dev/null && {
    CMAKE_COMMAND="cmake"
}
command -v cmake3 > /dev/null && {
    CMAKE_COMMAND="cmake3"
}
[ -z CMAKE_COMMAND ] && {
    echo 'cmake required'
    exit 1
}
export CMAKE_COMMAND
