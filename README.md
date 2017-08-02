# check_snmp_extras

Extra SNMP check plugins, written in C.

### Usage


    ./check_snmp_disks -v 2c -c <COMMUNITY> <HOSTNAME>


### Prerequisites

You will need CMake >= 3.5, and Net-SNMP.

### Installing

to install directly from source

    ./scripts/build.sh
    sudo ./scripts/install.sh



### Deployment

to generate an RPM 

    ./scripts/release-source.sh
    ./scripts/release-binary_rpm.sh

