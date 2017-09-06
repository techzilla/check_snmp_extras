/** @file check_snmp_proc.c
 *  @brief Check SNMP Process
 *
 *  Check SNMP Process
 *
 *  @author J. M. Becker
 *  @date 7/27/17
 */

#include "check_snmp_extras_lib.h"

#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>
#include <net-snmp/types.h>

int warning = 1;
int critical = 1;
char exec_name[STRMAX];

struct hrentry_t
{
    oid hrswind;

    long hrswrpcpu;
    long hrswrpmem;
    long hrswrptype;

    char hrswrname[MAX_OCTETSTRING_64_LEN];
    char hrswrpath[MAX_OCTETSTRING_128_LEN];

    struct hrentry_t *prev, *next;
};

void
usage(void)
{
    fprintf(stderr, "USAGE: check_snmp_proc");
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

int
filterentry(struct hrentry_t* hentry)
{

    int status = 0;

    /* is not an application */
    if (hentry->hrswrptype != 4) {
        status = 1;
    }

    return status;
}

void
querryentries(netsnmp_session* pss, struct hrentry_t* hentry)
{

    oid hrswrpath_oid[] = { 1, 3, 6, 1, 2, 1, 25, 4, 2, 1, 4, 1 };
    oid hrswrtype_oid[] = { 1, 3, 6, 1, 2, 1, 25, 4, 2, 1, 6, 1 };
    oid hrswrpcpu_oid[] = { 1, 3, 6, 1, 2, 1, 25, 5, 1, 1, 1, 1 };
    oid hrswrpmem_oid[] = { 1, 3, 6, 1, 2, 1, 25, 5, 1, 1, 2, 1 };

    size_t index_len = OID_LENGTH(hrswrpath_oid);


    netsnmp_variable_list *vars, *vp;

    do {
        vars = NULL;

        hrswrpath_oid[index_len - 1] = hentry->hrswind;
        hrswrtype_oid[index_len - 1] = hentry->hrswind;
        hrswrpcpu_oid[index_len - 1] = hentry->hrswind;
        hrswrpmem_oid[index_len - 1] = hentry->hrswind;

        snmp_varlist_add_variable(&vars, hrswrpath_oid, index_len, ASN_NULL, NULL, 0);
        snmp_varlist_add_variable(&vars, hrswrtype_oid, index_len, ASN_NULL, NULL, 0);
        snmp_varlist_add_variable(&vars, hrswrpcpu_oid, index_len, ASN_NULL, NULL, 0);
        snmp_varlist_add_variable(&vars, hrswrpmem_oid, index_len, ASN_NULL, NULL, 0);

        netsnmp_query_get(vars, pss);

        for (vp = vars; vp; vp = vp->next_variable) {
            if (netsnmp_oid_equals(hrswrpath_oid, index_len, vp->name, vp->name_length) == 0) {
                memcpy(hentry->hrswrpath, vp->val.string, vp->val_len);
            }
            if (netsnmp_oid_equals(hrswrtype_oid, index_len, vp->name, vp->name_length) == 0) {
                hentry->hrswrptype = *vp->val.integer;
            }
            if (netsnmp_oid_equals(hrswrpcpu_oid, index_len, vp->name, vp->name_length) == 0) {
                hentry->hrswrpcpu = *vp->val.integer;
            }
            if (netsnmp_oid_equals(hrswrpmem_oid, index_len, vp->name, vp->name_length) == 0) {
                hentry->hrswrpmem = *vp->val.integer;
            }
        }
        hentry = hentry->prev;
    } while (hentry);

    return;
}

int
main(int argc, char** argv)
{
    exec_name[0] = '\0';

    int arg;
    int query_status;
    int exit_status = STATUS_UNKNOWN;


    struct hrentry_t* hentry = NULL;
    struct hrentry_t* hfree = NULL;

    oid hrswrname_oid[] = { 1, 3, 6, 1, 2, 1, 25, 4, 2, 1, 2 };
    size_t hrswrname_len = OID_LENGTH(hrswrname_oid);

    netsnmp_variable_list* hrswrtindex_var = NULL;
    netsnmp_variable_list* hrswrt_var = NULL;

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

    if (critical < warning) {
        printf("Warning limit is greater than Critical limit\n");
        usage();
        exit(STATUS_UNKNOWN);
    }

    if (exec_name[0] == '\0') {
        printf("Exec Name Required\n");
        usage();
        exit(STATUS_UNKNOWN);
    }

    ss = snmp_open(&session);
    if (!ss) {
        snmp_sess_perror("snmp_open", &session);
        exit(STATUS_UNKNOWN);
    }

    /* Walk Indexes */
    snmp_varlist_add_variable(&hrswrtindex_var, hrswrname_oid, hrswrname_len, ASN_NULL, NULL, 0);

    query_status = netsnmp_query_walk(hrswrtindex_var, ss);
    if (query_status != SNMP_ERR_NOERROR) {
        if (query_status == STAT_TIMEOUT) {
            fprintf(stderr, "Timeout: No Response from %s\n", ss->peername);
        } else {
            fprintf(stderr, "Error in packet: %s\n", snmp_api_errstring(ss->s_snmp_errno));
        }
        exit(STATUS_UNKNOWN);
    }

    /* Retrieve indexes */
    for (hrswrt_var = hrswrtindex_var; hrswrt_var; hrswrt_var = hrswrt_var->next_variable) {

        if (hrswrt_var->val.string && hrswrt_var->val_len) {
            if (strcmp(exec_name, (char *)hrswrt_var->val.string) == 0) {
                hentry = attachentry(hentry);
                hentry->hrswind = hrswrt_var->name[hrswrt_var->name_length - 1];
                memcpy(hentry->hrswrname, hrswrt_var->val.string, hrswrt_var->val_len);
            }
         }
    }

    snmp_free_var(hrswrtindex_var);

    /* Query Entries  */
    if (hentry) {
        querryentries(ss, hentry);
    }
    snmp_close(ss);

    /* Prepare Output */
    long hrswrpmem[MAX_ENTRIES];
    long hrswrpcpu[MAX_ENTRIES];

    char brpmem[MAX_ENTRIES][10];

    char hrswrname[MAX_ENTRIES][MAX_OCTETSTRING_64_LEN];
    char hrswrpath[MAX_ENTRIES][MAX_OCTETSTRING_128_LEN];

    int i = -1;

    for (hfree = hentry; hfree; hfree = hfree->prev) {
        if (filterentry(hfree)) {
            continue;
        }
        i++;
        hrswrpcpu[i] = hfree->hrswrpcpu;
        hrswrpmem[i] = (hfree->hrswrpmem * 1024);
        readable_fs((double)hrswrpmem[i], &brpmem[i][0]);

        strcpy(&hrswrname[i][0], hfree->hrswrname);
        strcpy(&hrswrpath[i][0], hfree->hrswrpath);

    }

    for (hfree = hentry; hfree; hfree = hfree->prev) {
        free(hfree);
    }

    int proc_count = i + 1;

    exit_status = STATUS_OK;
    if (proc_count < warning) {
        exit_status = STATUS_WARNING;
    }
    if (proc_count < critical) {
        exit_status = STATUS_CRITICAL;
    }


    const char* wexit_msg = "PROC WARNING -";
    const char* cexit_msg = "PROC CRITICAL -";
    const char* oexit_msg = "PROC OK -";
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

    printf("%s proc count: %d, proc mem:", exit_msg, proc_count);

    for (int n = 0; n <= i; ++n) {
        printf(" %s_%d %s;", hrswrname[n], n, brpmem[n]);
    }
    if (i == -1) {
        printf(" N/A");
    }

    printf("|");

    for (int n = 0; n <= i; ++n) {
        printf(" '%s_%d_mem'=%s", hrswrname[n], n, brpmem[n]);
        printf(" '%s_%d_cpu'=%li", hrswrname[n], n, hrswrpcpu[n]);
    }

    return exit_status;
}
