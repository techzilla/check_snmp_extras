/** @file check_snmp_ram.c
 *  @brief Check SNMP Ram
 *
 *  Check SNMP Ram
 *
 *  @author J. M. Becker
 *  @date 7/27/17
 */

#include "check_snmp_extras.h"

#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>

int warning = 80;
int critical = 90;

struct hrentry_t
{
    unsigned hrstind;

    long unsigned hrstaunit;
    long unsigned hrstsize;
    long unsigned hrstused;

    oid hrsttype[MAX_OID_LEN];
    size_t hrsttype_len;

    char hrstdesc[MAX_OCTETSTRING_LEN];

    struct hrentry_t *prev, *next;
};

void
usage(void)
{
    fprintf(stderr, "USAGE: check_snmp_ram ");
    snmp_parse_args_usage(stderr);
    fprintf(stderr, " [OID]\n\n");
    snmp_parse_args_descriptions(stderr);
    fprintf(stderr, "Application specific options.\n");
    fprintf(stderr, "  -C APPOPTS\n");
}

void
optProc(int argc, char* const* argv, int opt)
{
    return;
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
    oid hrstdesc_oid[] = { 1, 3, 6, 1, 2, 1, 25, 2, 3, 1, 3, 1 };
    oid hrstaunit_oid[] = { 1, 3, 6, 1, 2, 1, 25, 2, 3, 1, 4, 1 };
    oid hrstsize_oid[] = { 1, 3, 6, 1, 2, 1, 25, 2, 3, 1, 5, 1 };
    oid hrstused_oid[] = { 1, 3, 6, 1, 2, 1, 25, 2, 3, 1, 6, 1 };

    size_t index_len = OID_LENGTH(hrstdesc_oid);

    netsnmp_variable_list *vars, *vp;

    do {
        vars = NULL;
        hrstdesc_oid[index_len - 1] = hentry->hrstind;
        hrstaunit_oid[index_len - 1] = hentry->hrstind;
        hrstsize_oid[index_len - 1] = hentry->hrstind;
        hrstused_oid[index_len - 1] = hentry->hrstind;

        snmp_varlist_add_variable(&vars, hrstdesc_oid, index_len, ASN_NULL, NULL, 0);
        snmp_varlist_add_variable(&vars, hrstaunit_oid, index_len, ASN_NULL, NULL, 0);
        snmp_varlist_add_variable(&vars, hrstsize_oid, index_len, ASN_NULL, NULL, 0);
        snmp_varlist_add_variable(&vars, hrstused_oid, index_len, ASN_NULL, NULL, 0);

        netsnmp_query_get(vars, pss);

        for (vp = vars; vp; vp = vp->next_variable) {

            if (netsnmp_oid_equals(hrstdesc_oid, index_len, vp->name, vp->name_length) == 0) {
                memcpy(hentry->hrstdesc, vp->val.string, vp->val_len);
            }
            if (netsnmp_oid_equals(hrstaunit_oid, index_len, vp->name, vp->name_length) == 0) {
                hentry->hrstaunit = *vp->val.integer;
            }
            if (netsnmp_oid_equals(hrstsize_oid, index_len, vp->name, vp->name_length) == 0) {
                hentry->hrstsize = *vp->val.integer;
            }
            if (netsnmp_oid_equals(hrstused_oid, index_len, vp->name, vp->name_length) == 0) {
                hentry->hrstused = *vp->val.integer;
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
    int exit_status = STATUS_OK;

    struct hrentry_t* hentry = NULL;
    struct hrentry_t* hfree = NULL;

    oid hrsttype_oid[] = { 1, 3, 6, 1, 2, 1, 25, 2, 3, 1, 2 };
    size_t hrsttype_len = OID_LENGTH(hrsttype_oid);

    netsnmp_variable_list* hrsttype_var = NULL;
    netsnmp_variable_list* hrst_var = NULL;

    netsnmp_session session, *ss;

    init_snmp(argv[0]);
    snmp_sess_init(&session);

    switch (arg = snmp_parse_args(argc, argv, &session, "C:", optProc)) {
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
    snmp_varlist_add_variable(&hrsttype_var, hrsttype_oid, hrsttype_len, ASN_NULL, NULL, 0);

    query_status = netsnmp_query_walk(hrsttype_var, ss);
    if (query_status != SNMP_ERR_NOERROR) {
        if (query_status == STAT_TIMEOUT) {
            fprintf(stderr, "Timeout: No Response from %s\n", ss->peername);
        } else {
            fprintf(stderr, "Error in packet: %s\n", snmp_api_errstring(ss->s_snmp_errno));
        }
        exit(STATUS_UNKNOWN);
    }

    oid hrsttype_ram_oid[] = { 1, 3, 6, 1, 2, 1, 25, 2, 1, 2 };
    oid hrsttype_other_oid[] = { 1, 3, 6, 1, 2, 1, 25, 2, 1, 1 };

    size_t index_len = OID_LENGTH(hrsttype_ram_oid);

    /* Retrieve indexes */
    for (hrst_var = hrsttype_var; hrst_var; hrst_var = hrst_var->next_variable) {

        if ((netsnmp_oid_equals(hrsttype_ram_oid, index_len, hrst_var->val.objid, (hrst_var->val_len / sizeof(oid))) ==
             0) ||
            (netsnmp_oid_equals(
                 hrsttype_other_oid, index_len, hrst_var->val.objid, (hrst_var->val_len / sizeof(oid))) == 0)) {

            hentry = attachentry(hentry);
            hentry->hrstind = hrst_var->name[hrst_var->name_length - 1];
        }
    }

    snmp_free_var(hrsttype_var);

    /* Query Entries  */
    querryentries(ss, hentry);
    snmp_close(ss);

    /* Prepare Output */
    long unsigned total = 0;
    long unsigned total_used = 0;

    long unsigned buffers_used = 0;
    long unsigned cached_used = 0;

    char btotal[10];
    char btotal_used[10];

    float pused = 0;

    for (hfree = hentry; hfree; hfree = hfree->prev) {
        if (strcasestr(hfree->hrstdesc, "physical")) {
            total = (hfree->hrstaunit * hfree->hrstsize);
            total_used = (hfree->hrstaunit * hfree->hrstused);
        } else if (strcasestr(hfree->hrstdesc, "buffers")) {
            buffers_used = (hfree->hrstaunit * hfree->hrstused);
        } else if (strcasestr(hfree->hrstdesc, "Cached")) {
            cached_used = (hfree->hrstaunit * hfree->hrstused);
        }
    }

    for (hfree = hentry; hfree; hfree = hfree->prev) {
        free(hfree);
    }

    total_used = total_used - (buffers_used + cached_used);
    if (total_used > 0 && total > 0) {
        pused = (float)(total_used * 100) / total;
    }

    readable_fs(total, btotal);
    readable_fs(total_used, btotal_used);

    if (pused >= warning) {
        exit_status = STATUS_WARNING;
    }
    if (pused >= critical) {
        exit_status = STATUS_CRITICAL;
    }

    char* wexit_msg = "RAM WARNING -";
    char* cexit_msg = "RAM CRITICAL -";
    char* oexit_msg = "RAM OK -";
    char* exit_msg;

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

    printf("%s mem used: %s / %s (%1.f%%)", exit_msg, btotal_used, btotal, pused);
    printf("|");
    printf(" 'total_used'=%s total_size'=%s", btotal_used, btotal);

    return exit_status;
}
