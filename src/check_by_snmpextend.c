/** @file check_by_snmpextend.c
 *  @brief Check by SNMP Extend
 *
 *  Check by SNMP Extend
 *
 *  @author J. M. Becker
 *  @date 7/27/17
 */

#include "check_snmp_extras_lib.h"

#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>

char exec_name[STRMAX];

void
usage(void)
{
    fprintf(stderr, "USAGE: check_by_snmpextend");
    snmp_parse_args_usage(stderr);
    fprintf(stderr, "\n\n");
    snmp_parse_args_descriptions(stderr);
    fprintf(stderr, "Application specific options.\n");
    fprintf(stderr, "  -C APPOPTS\n");
    fprintf(stderr, "\t\t\t  E:  Extend Table Name.\n");
}

static void
opt_proc(int argc, char* const* argv, int opt)
{
    switch (opt) {
        case 'C':
            while (*optarg) {
                switch (*optarg++) {
                    case 'E':
                        optind++;
                        if (optind < argc) {
                            snprintf(exec_name, STRMAX, "%s", argv[optind - 1]);
                        } else {
                            fprintf(stderr, "No name passed to -CE");
                            exit(STATUS_UNKNOWN);
                        }
                        break;
                    default:
                        fprintf(stderr, "Unknown flag passed to -C: %c", optarg[-1]);
                        exit(STATUS_UNKNOWN);
                        break;
                }
            }
            break;
        default:
            break;
    }
}

int
main(int argc, char** argv)
{
    int arg;
    int query_status;
    int exit_status = STATUS_UNKNOWN;

    const char* nsextendol_pre = "NET-SNMP-EXTEND-MIB::nsExtendOutputFull";
    char nsextenol_str[STRMAX + 50];
    oid nsextendol_oid[MAX_OID_LEN];
    size_t nsextendol_len = MAX_OID_LEN;

    const char* nsextendr_pre = "NET-SNMP-EXTEND-MIB::nsExtendResult";
    char nsextendr_str[STRMAX + 50];
    oid nsextendr_oid[MAX_OID_LEN];
    size_t nsextendr_len = MAX_OID_LEN;

    netsnmp_variable_list* nsextend_var = NULL;
    netsnmp_variable_list* vp = NULL;

    netsnmp_session session, *ss;

    init_snmp(argv[0]);
    snmp_sess_init(&session);

    switch (arg = snmp_parse_args(argc, argv, &session, "C:", opt_proc)) {
        case NETSNMP_PARSE_ARGS_ERROR:
            exit(STATUS_UNKNOWN);
        case NETSNMP_PARSE_ARGS_SUCCESS_EXIT:
            exit(STATUS_OK);
        case NETSNMP_PARSE_ARGS_ERROR_USAGE:
            usage();
            exit(STATUS_UNKNOWN);
        default:
            break;
    }

    if (strlen(exec_name) == 0) {
        printf("Exec Name Required\n");
        usage();
        exit(STATUS_UNKNOWN);
    }

    sprintf(nsextenol_str, "%s.\"%s\"", nsextendol_pre, exec_name);
    sprintf(nsextendr_str, "%s.\"%s\"", nsextendr_pre, exec_name);

    if (!snmp_parse_oid(nsextenol_str, nsextendol_oid, &nsextendol_len)) {
        fprintf(stderr, "%s: Unknown Object Identifier\n", nsextenol_str);
        exit(STATUS_UNKNOWN);
    }
    if (!snmp_parse_oid(nsextendr_str, nsextendr_oid, &nsextendr_len)) {
        fprintf(stderr, "%s: Unknown Object Identifier\n", nsextendr_str);
        exit(STATUS_UNKNOWN);
    }

    ss = snmp_open(&session);
    if (!ss) {
        snmp_sess_perror("snmp_open", &session);
        exit(STATUS_UNKNOWN);
    }

    snmp_varlist_add_variable(&nsextend_var, nsextendol_oid, nsextendol_len, ASN_NULL, NULL, 0);
    snmp_varlist_add_variable(&nsextend_var, nsextendr_oid, nsextendr_len, ASN_NULL, NULL, 0);

    /* Query Entries  */
    query_status = netsnmp_query_get(nsextend_var, ss);
    if (query_status != SNMP_ERR_NOERROR) {
        if (query_status == STAT_TIMEOUT) {
            fprintf(stderr, "Timeout: No Response from %s\n", ss->peername);
        } else {
            fprintf(stderr, "Error in packet: %s\n", snmp_api_errstring(ss->s_snmp_errno));
        }
        exit(STATUS_UNKNOWN);
    }

    char exit_msg[STRMAX];
    exit_msg[0] = '\0';

    /* Retrieve Values */
    for (vp = nsextend_var; vp; vp = vp->next_variable) {
        if (vp->val_len != 0) {

            if (netsnmp_oid_equals(nsextendol_oid, nsextendol_len, vp->name, vp->name_length) == 0) {
                memcpy(exit_msg, vp->val.string, vp->val_len);
                exit_msg[vp->val_len] = '\0';

            } else if (netsnmp_oid_equals(nsextendr_oid, nsextendr_len, vp->name, vp->name_length) == 0) {
                exit_status = *vp->val.integer;
            }
        }
    }

    snmp_free_var(nsextend_var);
    snmp_close(ss);

    /* Prepare Output */
    printf("%s", exit_msg);
    return exit_status;
}
