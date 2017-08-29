/** @file check_snmp_extras_lib.h
 *  @brief Check SNMP Misc
 *
 *  Check SNMP Misc
 *
 *  @author J. M. Becker
 *  @date 7/27/17
 */

#ifndef CHECK_SNMP_EXTRAS_LIB_H
#define CHECK_SNMP_EXTRAS_LIB_H

/* Entry Limit */
#define MAX_ENTRIES 128

/* Exit Status */
#define STATUS_OK 0
#define STATUS_WARNING 1
#define STATUS_CRITICAL 2
#define STATUS_UNKNOWN 3

/* SNMP Definitions */
#define MAX_OCTETSTRING_LEN 255
#define MAX_OCTETSTRING_128_LEN 128
#define MAX_OCTETSTRING_64_LEN 64

/* Extend Limit */
#define STRMAX 1024

char*
readable_fs(double bytes, char* buf);

#endif /* CHECK_SNMP_EXTRAS_LIB_H */

