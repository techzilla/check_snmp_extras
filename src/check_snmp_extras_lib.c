/** @file check_snmp_extras_lib.c
 *  @brief Check SNMP Misc
 *
 *  Check SNMP Misc
 *
 *  @author J. M. Becker
 *  @date 7/27/17
 */

#include <stdio.h>

char*
readable_fs(long unsigned bytes, char* buf)
{
    int i = 0;
    const char* units[] = { "B", "kB", "MB", "GB", "TB", "PB", "EB", "ZB", "YB" };
    while (bytes > 1024) {
        bytes /= 1024;
        i++;
    }
    sprintf(buf, "%lu%s", bytes, units[i]);
    return buf;
}
