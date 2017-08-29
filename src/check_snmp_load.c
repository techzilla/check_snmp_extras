/** @file check_snmp_load.c
 *  @brief Check SNMP Load
 *
 *  Check SNMP Load
 *
 *  @author J. M. Becker
 *  @date 7/27/17
 */

#include "check_snmp_extras_lib.h"

#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>

int warning = 85;
int critical = 95;

struct hrentry_t
{
    oid hrprind;
    long hrprload;

    char hrddesc[MAX_OCTETSTRING_64_LEN];

    struct hrentry_t *prev, *next;
};

void
usage(void)
{
    fprintf(stderr, "USAGE: check_snmp_load");
    snmp_parse_args_usage(stderr);
    fprintf(stderr, "\n\n");
    snmp_parse_args_descriptions(stderr);
    fprintf(stderr, "Application specific options.\n");
    fprintf(stderr, "  -C APPOPTS\n");
    fprintf(stderr, "\t\t\t  c:  Set the critical threshold.\n");
    fprintf(stderr, "\t\t\t  w:  Set the warning threshold.\n");
}

static void
opt_proc(int argc, char* const* argv, int opt)
{
    switch (opt) {
        case 'C':
            while (*optarg) {
                switch (*optarg++) {
                    case 'w':
                        optind++;
                        if (optind < argc) {
                            warning = atoi(argv[optind - 1]);
                        } else {
                            fprintf(stderr, "No number name passed to -Cw");
                            exit(STATUS_UNKNOWN);
                        }
                        break;
                    case 'c':
                        optind++;
                        if (optind < argc) {
                            critical = atoi(argv[optind - 1]);
                        } else {
                            fprintf(stderr, "No number name passed to -Cc");
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

struct hrentry_t*
attachentry(struct hrentry_t* hentry)
{
    struct hrentry_t* hnew = calloc(sizeof(struct hrentry_t), 1);
    if (hnew == NULL)
        return NULL;

    if (hentry != NULL) {
        while (hentry->next != NULL) {
            hentry = hentry->next;
        };
        hentry->next = hnew;
        hnew->prev = hentry;
    }
    return hnew;
}

void
querryentries(netsnmp_session* pss, struct hrentry_t* hentry)
{

    oid hrddesc_oid[] = { 1, 3, 6, 1, 2, 1, 25, 3, 2, 1, 3, 1 };

    size_t index_len = OID_LENGTH(hrddesc_oid);

    netsnmp_variable_list *vars, *vp;

    do {
        vars = NULL;
        hrddesc_oid[index_len - 1] = hentry->hrprind;

        snmp_varlist_add_variable(&vars, hrddesc_oid, index_len, ASN_NULL, NULL, 0);

        netsnmp_query_get(vars, pss);

        for (vp = vars; vp; vp = vp->next_variable) {

            if (netsnmp_oid_equals(hrddesc_oid, index_len, vp->name, vp->name_length) == 0) {
                memcpy(hentry->hrddesc, vp->val.string, vp->val_len);
            }
        }
        hentry = hentry->prev;
    } while (hentry);

    return;
}

int
main(int argc, char** argv)
{
    int arg;
    int query_status;
    int exit_status = STATUS_UNKNOWN;

    struct hrentry_t* hentry = NULL;
    struct hrentry_t* hfree = NULL;

    oid hrprload_oid[] = { 1, 3, 6, 1, 2, 1, 25, 3, 3, 1, 2 };
    size_t hrprload_len = OID_LENGTH(hrprload_oid);

    netsnmp_variable_list* hrprload_var = NULL;
    netsnmp_variable_list* hrpr_var = NULL;

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

    if (critical <= warning) {
        printf("Warning limit is greater than Critical limit\n");
        usage();
        exit(STATUS_UNKNOWN);
    }

    ss = snmp_open(&session);
    if (!ss) {
        snmp_sess_perror("snmp_open", &session);
        exit(STATUS_UNKNOWN);
    }

    /* Walk Indexes */
    snmp_varlist_add_variable(&hrprload_var, hrprload_oid, hrprload_len, ASN_NULL, NULL, 0);

    query_status = netsnmp_query_walk(hrprload_var, ss);
    if (query_status != SNMP_ERR_NOERROR) {
        if (query_status == STAT_TIMEOUT) {
            fprintf(stderr, "Timeout: No Response from %s\n", ss->peername);
        } else {
            fprintf(stderr, "Error in packet: %s\n", snmp_api_errstring(ss->s_snmp_errno));
        }
        exit(STATUS_UNKNOWN);
    }

    /* Retrieve indexes */
    for (hrpr_var = hrprload_var; hrpr_var; hrpr_var = hrpr_var->next_variable) {
        hentry = attachentry(hentry);

        hentry->hrprind = hrpr_var->name[hrpr_var->name_length - 1];
        hentry->hrprload = *hrpr_var->val.integer;
    }
    snmp_free_var(hrprload_var);

    /* Query Entries  */
    querryentries(ss, hentry);
    snmp_close(ss);

    /* Prepare Output */

    long hpload[MAX_ENTRIES];
    char hdesc[MAX_ENTRIES][MAX_OCTETSTRING_64_LEN];

    int i = -1;

    for (hfree = hentry; hfree; hfree = hfree->prev) {
        ++i;
        hpload[i] = hfree->hrprload;
        strcpy(&hdesc[i][0], hfree->hrddesc);

        char* p = strchr(hdesc[i], ':');
        if (p) {
            *p = '\0';
        }
    }

    for (hfree = hentry; hfree; hfree = hfree->prev) {
        free(hfree);
    }

    float hpload_avg = 0;
    long unsigned hpload_sum = 0;

    for (int n = 0; n <= i; ++n) {
        hpload_sum = hpload_sum + hpload[n];
    }
    if (i > 0 && hpload_sum > 0) {
        hpload_avg = hpload_sum / (i + 1);
    }

    exit_status = STATUS_OK;
    for (int n = 0; n <= i; ++n) {

        if (hpload_avg >= warning) {
            exit_status = STATUS_WARNING;
        }
        if (hpload_avg >= critical) {
            exit_status = STATUS_CRITICAL;
            break;
        }
    }

    const char* wexit_msg = "LOAD WARNING -";
    const char* cexit_msg = "LOAD CRITICAL -";
    const char* oexit_msg = "LOAD OK -";
    const char* exit_msg;

    switch (exit_status) {

        case STATUS_WARNING:
            exit_msg = wexit_msg;
            break;

        case STATUS_CRITICAL:
            exit_msg = cexit_msg;
            break;
        default:
            exit_msg = oexit_msg;
    }

    printf("%s avg load: %1.f%%, core load:", exit_msg, hpload_avg);

    for (int n = 0; n <= i; ++n) {
        printf(" %s_%d %lu%%;", hdesc[n], n, hpload[n]);
    }

    printf("|");

    for (int n = 0; n <= i; ++n) {
        printf(" '%s_%d'=%lu%%", hdesc[n], n, hpload[n]);
    }

    return exit_status;
}
