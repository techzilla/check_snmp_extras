/** @file check_snmp_extras.h
 *  @brief Check SNMP Extras
 *
 *  Check SNMP Extras
 *
 *  @author J. M. Becker
 *  @date 7/27/17
 */

#ifndef CHECK_SNMP_EXTRAS_H
#define CHECK_SNMP_EXTRAS_H

#include "check_snmp_extras_lib.h"

/* Exit Status */
#define STATUS_OK 0
#define STATUS_WARNING 1
#define STATUS_CRITICAL 2
#define STATUS_UNKNOWN 3

#define MAX_ENTRIES 128
#define MAX_OCTETSTRING_LEN 255
#define MAX_OCTETSTRING_128_LEN 128
#define MAX_OCTETSTRING_64_LEN 64

#endif /* CHECK_SNMP_EXTRAS_H */