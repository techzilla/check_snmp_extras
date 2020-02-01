# check_snmp_extras

Extra SNMP Monitoring Check Plugins for Nagios, Icinga and Icinga2, written in C.

MIB objects:
 - [HOST-RESOURCES-MIB](http://www.net-snmp.org/docs/mibs/host.html)

### Usage


    ./check_snmp_disk -v 2c -c <COMMUNITY> -Cw 85 -Cw 95 <HOSTNAME>


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

