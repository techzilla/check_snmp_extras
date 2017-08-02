/** @file check_snmp_disk.c
 *  @brief Check SNMP Disk
 *
 *  Check SNMP Disk
 *
 *  @author J. M. Becker
 *  @date 7/27/17
 */

#include "check_snmp_extras.h"

#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>

struct hrentry_t
{
    int hrstind;
    int hrfsind;

    size_t hrstaunit;
    unsigned long hrstsize;
    unsigned long hrstused;

    oid hrsttype[MAX_OID_LEN];
    size_t hrsttype_len;
    oid hrfstype[MAX_OID_LEN];
    size_t hrfstype_len;

    char hrstdesc[MAX_DISPLAYSTRING_LEN];

    struct hrentry_t *prev, *next;
};

void
usage(void)
{
    fprintf(stderr, "USAGE: check_snmp_disk ");
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

    oid hrsttype_fixed_oid[] = { 1, 3, 6, 1, 2, 1, 25, 2, 1, 4 };
    oid hrfstype_iso_oid[] = { 1, 3, 6, 1, 2, 1, 25, 3, 9, 12 };
    oid hrfstype_other_oid[] = { 1, 3, 6, 1, 2, 1, 25, 3, 9, 1 };

    size_t index_len = OID_LENGTH(hrsttype_fixed_oid);

    if (netsnmp_oid_equals(hrsttype_fixed_oid, index_len, hentry->hrsttype, hentry->hrsttype_len) != 0) {
        status = 1;
    } else if (netsnmp_oid_equals(hrfstype_iso_oid, index_len, hentry->hrfstype, hentry->hrfstype_len) == 0) {
        status = 1;
    } else if (netsnmp_oid_equals(hrfstype_other_oid, index_len, hentry->hrfstype, hentry->hrfstype_len) == 0) {
        status = 1;
    }

    return status;
}
int
laststroid(char* str_oid)
{

    int subid;
    subid = atoi((strrchr(str_oid, '.')) + 1);

    return subid;
}

void
querryentries(netsnmp_session* pss, struct hrentry_t* hentry)
{

    oid hrsttype_oid[] = { 1, 3, 6, 1, 2, 1, 25, 2, 3, 1, 2, 1 };
    oid hrstdesc_oid[] = { 1, 3, 6, 1, 2, 1, 25, 2, 3, 1, 3, 1 };
    oid hrstaunit_oid[] = { 1, 3, 6, 1, 2, 1, 25, 2, 3, 1, 4, 1 };
    oid hrstsize_oid[] = { 1, 3, 6, 1, 2, 1, 25, 2, 3, 1, 5, 1 };
    oid hrstused_oid[] = { 1, 3, 6, 1, 2, 1, 25, 2, 3, 1, 6, 1 };

    oid hrfstype_oid[] = { 1, 3, 6, 1, 2, 1, 25, 3, 8, 1, 4, 1 };

    size_t index_len = OID_LENGTH(hrsttype_oid);

    netsnmp_variable_list *vars, *vp;

    do {
        vars = NULL;
        hrsttype_oid[index_len - 1] = hentry->hrstind;
        hrstdesc_oid[index_len - 1] = hentry->hrstind;
        hrstaunit_oid[index_len - 1] = hentry->hrstind;
        hrstsize_oid[index_len - 1] = hentry->hrstind;
        hrstused_oid[index_len - 1] = hentry->hrstind;

        snmp_varlist_add_variable(&vars, hrsttype_oid, index_len, ASN_NULL, NULL, 0);
        snmp_varlist_add_variable(&vars, hrstdesc_oid, index_len, ASN_NULL, NULL, 0);
        snmp_varlist_add_variable(&vars, hrstaunit_oid, index_len, ASN_NULL, NULL, 0);
        snmp_varlist_add_variable(&vars, hrstsize_oid, index_len, ASN_NULL, NULL, 0);
        snmp_varlist_add_variable(&vars, hrstused_oid, index_len, ASN_NULL, NULL, 0);
        if (hentry->hrfsind != 0) {

            hrfstype_oid[index_len - 1] = hentry->hrfsind;

            snmp_varlist_add_variable(&vars, hrfstype_oid, index_len, ASN_NULL, NULL, 0);
        }

        netsnmp_query_get(vars, pss);

        for (vp = vars; vp; vp = vp->next_variable) {

            if (netsnmp_oid_equals(hrsttype_oid, index_len, vp->name, vp->name_length) == 0) {
                memcpy(hentry->hrsttype, vp->val.objid, vp->val_len);
                hentry->hrsttype_len = (vp->val_len / sizeof(oid));
            }
            if (netsnmp_oid_equals(hrstdesc_oid, index_len, vp->name, vp->name_length) == 0) {
                memcpy(hentry->hrstdesc, vp->val.string, vp->val_len);
            }
            if (netsnmp_oid_equals(hrstaunit_oid, index_len, vp->name, vp->name_length) == 0) {
                hentry->hrstaunit = (size_t)*vp->val.integer;
            }
            if (netsnmp_oid_equals(hrstsize_oid, index_len, vp->name, vp->name_length) == 0) {
                hentry->hrstsize = (unsigned long)*vp->val.integer;
            }
            if (netsnmp_oid_equals(hrstused_oid, index_len, vp->name, vp->name_length) == 0) {
                hentry->hrstused = (unsigned long)*vp->val.integer;
            }
            if (netsnmp_oid_equals(hrfstype_oid, index_len, vp->name, vp->name_length) == 0) {
                memcpy(hentry->hrfstype, vp->val.objid, vp->val_len);
                hentry->hrfstype_len = (vp->val_len / sizeof(oid));
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

    int hrst;
    int hrfsst;
    int query_status;

    int exit_status = STATUS_OK;
    char oidbuf[MAX_OID_LEN];
    struct hrentry_t* hentry = NULL;
    struct hrentry_t* hfree = NULL;

    oid hrstindex_oid[] = { 1, 3, 6, 1, 2, 1, 25, 2, 3, 1, 1 };
    size_t hrstindex_len = OID_LENGTH(hrstindex_oid);

    oid hrfsstindex_oid[] = { 1, 3, 6, 1, 2, 1, 25, 3, 8, 1, 7 };
    size_t hrfsstindex_len = OID_LENGTH(hrfsstindex_oid);

    netsnmp_variable_list* hrstindex_var = NULL;
    netsnmp_variable_list* hrfsstindex_var = NULL;
    netsnmp_variable_list* hrst_var = NULL;
    netsnmp_variable_list* hrfsst_var = NULL;

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
    snmp_varlist_add_variable(&hrstindex_var, hrstindex_oid, hrstindex_len, ASN_NULL, NULL, 0);

    query_status = netsnmp_query_walk(hrstindex_var, ss);
    if (query_status != SNMP_ERR_NOERROR) {
        if (query_status == STAT_TIMEOUT) {
            fprintf(stderr, "Timeout: No Response from %s\n", ss->peername);
        } else {
            fprintf(stderr, "Error in packet\nReason: %s\n", snmp_api_errstring(ss->s_snmp_errno));
        }
        exit(STATUS_UNKNOWN);
    }

    snmp_varlist_add_variable(&hrfsstindex_var, hrfsstindex_oid, hrfsstindex_len, ASN_NULL, NULL, 0);

    query_status = netsnmp_query_walk(hrfsstindex_var, ss);
    if (query_status != SNMP_ERR_NOERROR) {
        if (query_status == STAT_TIMEOUT) {
            fprintf(stderr, "Timeout: No Response from %s\n", ss->peername);
        } else {
            fprintf(stderr, "Error in packet\nReason: %s\n", snmp_api_errstring(ss->s_snmp_errno));
        }
        exit(STATUS_UNKNOWN);
    }

    /* Correlate indexes */
    for (hrst_var = hrstindex_var; hrst_var; hrst_var = hrst_var->next_variable) {
        hrst = (int)*hrst_var->val.integer;
        hrfsst = 0;

        for (hrfsst_var = hrfsstindex_var; hrfsst_var; hrfsst_var = hrfsst_var->next_variable) {
            if (hrst == (int)*hrfsst_var->val.integer) {
                snprint_objid(oidbuf, MAX_OID_LEN, hrfsst_var->name, hrfsst_var->name_length);
                hrfsst = laststroid(oidbuf);
                break;
            }
        }
        hentry = attachentry(hentry);
        hentry->hrstind = hrst;
        hentry->hrfsind = hrfsst;
    }
    snmp_free_var(hrstindex_var);
    snmp_free_var(hrfsstindex_var);

    /* Query Entries  */
    querryentries(ss, hentry);
    snmp_close(ss);

    /* Prepare Output */

    unsigned long hsize[MAX_ENTRIES];
    unsigned long hused[MAX_ENTRIES];
    char bhused[MAX_ENTRIES][10];

    float hpused[MAX_ENTRIES];

    char hrstdesc[MAX_ENTRIES][MAX_DISPLAYSTRING_LEN];
    int i = 0;

    for (hfree = hentry; hfree; hfree = hfree->prev) {
        if (filterentry(hfree)) {
            continue;
        }
        hsize[i] = (hfree->hrstaunit * hfree->hrstsize);
        hused[i] = (hfree->hrstaunit * hfree->hrstused);

        hpused[i] = (float)(hused[i] * 100) / hsize[i];

        readable_fs(hused[i], &bhused[i][0]);
        strcpy(&hrstdesc[i][0], hfree->hrstdesc);
        i++;
    }

    for (hfree = hentry; hfree; hfree = hfree->prev) {
        free(hfree);
    }

    for (int n = 0; n < i; ++n) {
        if (hpused[n] >= warning) {
            exit_status = STATUS_WARNING;
        }
        if (hpused[n] >= critical) {
            exit_status = STATUS_CRITICAL;
            break;
        }
    }

    char* wexit_msg = "DISK WARNING -";
    char* cexit_msg = "DISK CRITICAL -";
    char* oexit_msg = "DISK OK -";
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

    printf("%s", exit_msg);
    for (int n = 0; n < i; ++n) {
        printf(" used space: %s %s (%.1f%%);", hrstdesc[n], bhused[n], hpused[n]);
    }

    printf("|");

    for (int n = 0; n < i; ++n) {
        printf(" '%s'=%s", hrstdesc[n], bhused[n]);
    }

    return exit_status;
}
