

#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>
#include <stdio.h>
#include <string.h>

/* Define useful variables */
#define STATUS_OK 0
#define STATUS_WARNING 1
#define STATUS_CRITICAL 2
#define STATUS_UNKNOWN 3

int warn = 80;
int crit = 90;

struct oid_s
{
    const char* name;
    oid oid[MAX_OID_LEN];
    size_t oid_len;
};

/*
  Print usage info.
*/
void
usage(void)
{
    fprintf(stderr, "USAGE: check_linux_disk ");
    snmp_parse_args_usage(stderr);
    fprintf(stderr, " [OID]\n\n");
    snmp_parse_args_descriptions(stderr);
    fprintf(stderr, "Application specific options.\n");
    fprintf(stderr, "  -C APPOPTS\n");
    fprintf(stderr, "\t\t\t  c:  Set the critical threshold.\n");
    fprintf(stderr, "\t\t\t  w:  Set the warning threshold.\n");
}

void
checkObjid(struct oid_s* oid_p)
{
    oid_p->oid_len = sizeof(oid_p->oid) / sizeof(oid_p->oid[0]);
    if (!read_objid(oid_p->name, oid_p->oid, &oid_p->oid_len)) {
        snmp_perror("read_objid");
        exit(STATUS_UNKNOWN);
    }
    return;
}

void
optProc(int argc, char* const* argv, int opt)
{
    switch (opt) {
        case 'C':
            while (*optarg) {
                switch (*optarg++) {
                    case 'c':
                        crit = atoi(argv[optind++]);
                        break;
                    case 'w':
                        warn = atoi(argv[optind++]);
                        break;
                    default:
                        fprintf(stderr, "Unknown flag passed to -C: %c\n", optarg[-1]);
                        exit(STATUS_UNKNOWN);
                }
            }
            break;
    }
}

/* Main program */
int
main(int argc, char* argv[])
{
    char arg;
    int running;
    int snmp_status;
    int exit_status = STATUS_OK;
    oid name[MAX_OID_LEN];
    size_t name_length;

    netsnmp_session session, *ss;
    netsnmp_pdu *pdu, *response;
    netsnmp_variable_list* vars;

    init_snmp("check_snmp_disk");

    snmp_sess_init(&session);

    switch (arg = snmp_parse_args(argc, argv, &session, "C:", optProc)) {
        case -3:
            exit(1);
        case -2:
            exit(0);
        case -1:
            usage();
            exit(1);
        default:
            break;
    }

    /* Check warning/critical test values to verify they are within the
     * appropriate ranges */
    if (crit > 100) {
        printf("Critical threshold should be less than 100!\n");
        usage();
        exit(STATUS_UNKNOWN);
    } else if (crit < 0) {
        printf("Critical threshould must be greater than 0!\n");
        usage();
        exit(STATUS_UNKNOWN);
    } else if (warn < 0) {
        printf("Warning threshold must be greater than or equal to 0!\n");
        usage();
        exit(STATUS_UNKNOWN);
    } else if (warn > crit) {
        printf("Warning threshold must not be greater than critical threshold!\n");
        usage();
        exit(STATUS_UNKNOWN);
    }

    /* Open snmp session */
    ss = snmp_open(&session);
    if (ss == NULL) {
        /*
         * diagnose snmp_open errors
         */
        snmp_sess_perror("snmp_open", &session);
        exit(STATUS_UNKNOWN);
    }

    struct oid_s storage_indexv = { "HOST-RESOURCES-MIB:hrStorageIndex" };
    struct oid_s* storage_index = &storage_indexv;
    // struct oid_s fs_indexv = {"HOST-RESOURCES-MIB:hrFSIndex"};

    // struct oid_s storage_index { };
    // oid_s fs_index = {"HOST-RESOURCES-MIB:hrFSIndex"};
    checkObjid(storage_index);
    // checkObjid(fs_index);

    memmove(name, storage_index->oid, storage_index->oid_len * sizeof(oid));
    name_length = storage_index->oid_len;

    running = 1;
    while (running < 10) {
        /*
         * create PDU for GETNEXT request and add object name to request
         */
        pdu = snmp_pdu_create(SNMP_MSG_GETNEXT);
        snmp_add_null_var(pdu, name, name_length);

        snmp_status = snmp_synch_response(ss, pdu, &response);

        for (vars = response->variables; vars; vars = vars->next_variable) {
            print_variable(vars->name, vars->name_length, vars);
            memmove(name, vars->name, vars->name_length * sizeof(oid));
            name_length = vars->name_length;
        }
        running++;
    }

    snmp_close(ss);

    return exit_status;
}

// char *checkDISK(netsnmp_session *ss) {

//  oid_s storage_index = {"HOST-RESOURCES-MIB:hrStorageIndex"};
//  oid_s fs_index = {"HOST-RESOURCES-MIB:hrFSIndex"};

//   { "HOST-RESOURCES-MIB:hrStorageType" },
//   { "HOST-RESOURCES-MIB:hrStorageDescr" },
//   { "HOST-RESOURCES-MIB:hrStorageAllocationUnits" },
//   { "HOST-RESOURCES-MIB:hrStorageSize" },
//   { "HOST-RESOURCES-MIB:hrStorageUsed" },
//   { NULL }
// };

// netsnmp_pdu *pdu;
// netsnmp_pdu *response;
// oid base[MAX_OID_LEN];
// size_t base_length;
// netsnmp_variable_list *saved = NULL, *vlp = saved, *vlp2;
// int status;
// char partstr[1024], perfString[100];
// unsigned long totalDiskUsed = 0, totatDisk = 0;
// int testVal = STATUS_OK;
// char human_size_used[10];

// pdu = snmp_pdu_create(SNMP_MSG_GETNEXT);
// base_length = add(pdu, "HOST-RESOURCES-MIB:hrStorageIndex", NULL, 0);
// memcpy(base, pdu->variables->name, base_length * sizeof(oid));

// vlp = collect(ss, pdu, base, base_length);

// while (vlp) {
//   size_t units;
//   unsigned long hssize, hsused;
//   char descr[SPRINT_MAX_LEN];
//   char hstype[1024];

//   pdu = snmp_pdu_create(SNMP_MSG_GET);

//   add(pdu, "HOST-RESOURCES-MIB:hrStorageType", &(vlp->name[base_length]),
//       vlp->name_lengthgth - base_length);
//   add(pdu, "HOST-RESOURCES-MIB:hrStorageDescr", &(vlp->name[base_length]),
//       vlp->name_lengthgth - base_length);
//   add(pdu, "HOST-RESOURCES-MIB:hrStorageAllocationUnits",
//       &(vlp->name[base_length]), vlp->name_lengthgth - base_length);
//   add(pdu, "HOST-RESOURCES-MIB:hrStorageSize", &(vlp->name[base_length]),
//       vlp->name_lengthgth - base_length);
//   add(pdu, "HOST-RESOURCES-MIB:hrStorageUsed", &(vlp->name[base_length]),
//       vlp->name_lengthgth - base_length);

//   status = snmp_synch_response(ss, pdu, &response);
//   if (status == STAT_ERROR) {
//     printf("ERROR - Problem while querying device!\n");
//     exit(STATUS_CRITICAL);
//   } else if (status == STAT_TIMEOUT) {
//     printf("ERROR - Connection timed out!\n");
//     exit(STATUS_CRITICAL);
//   } else if (response->errstat != SNMP_ERR_NOERROR) {
//     switch (response->errstat) {
//     case SNMP_ERR_NOSUCHNAME:
//       printf("ERROR - Device does not support that feature!\n");
//       break;
//     case SNMP_ERR_TOOBIG:
//       printf("ERROR - Result generated too much data!\n");
//       break;
//     case SNMP_ERR_READONLY:
//       printf("ERROR - Value is read only!\n");
//       break;
//     case SNMP_ERR_BADVALUE:
//     case SNMP_ERR_GENERR:
//     case SNMP_ERR_NOACCESS:
//     case SNMP_ERR_WRONGTYPE:
//     case SNMP_ERR_WRONGLENGTH:
//     case SNMP_ERR_WRONGENCODING:
//     case SNMP_ERR_WRONGVALUE:
//     case SNMP_ERR_NOCREATION:
//     case SNMP_ERR_INCONSISTENTVALUE:
//     case SNMP_ERR_RESOURCEUNAVAILABLE:
//     case SNMP_ERR_COMMITFAILED:
//     case SNMP_ERR_UNDOFAILED:
//     case SNMP_ERR_AUTHORIZATIONERROR:
//     case SNMP_ERR_NOTWRITABLE:
//     case SNMP_ERR_INCONSISTENTNAME:
//     default:
//       printf("ERROR - Unknown error!\n");
//     }
//     exit(STATUS_CRITICAL);
//   }

//   vlp2 = response->variables;

//   vlp2 = vlp2->next_variable;
//   memcpy(descr, vlp2->val.string, vlp2->val_len);
//   descr[vlp2->val_len] = '\0';

//   vlp2 = vlp2->next_variable;
//   units = vlp2->val.integer ? *(vlp2->val.integer) : 0;

//   vlp2 = vlp2->next_variable;
//   hssize = units * (vlp2->val.integer ? *(vlp2->val.integer) : 0);

//   vlp2 = vlp2->next_variable;
//   hsused = units * (vlp2->val.integer ? *(vlp2->val.integer) : 0);

//   totalDiskUsed += hsused;
//   totatDisk += hssize;

//   float usedPercent = (float)(hsused * 100) / hssize;
//   // human_size_used = readable_fs(totalDiskUsed, human_size_used);
//   // human_disk_size = readable_fs(totatDisk, human_disk_size);
//   if (usedPercent > crit) {
//     testVal = STATUS_CRITICAL;
//     sprintf(partstr, "%s %s(%.1f%%); ", descr,
//             readable_fs(totalDiskUsed, human_size_used), usedPercent);
//   } else if (usedPercent > warn) {
//     testVal = STATUS_WARNING;
//     sprintf(partstr, "%s %s(%.1f%%); ", descr,
//             readable_fs(totalDiskUsed, human_size_used), usedPercent);
//   } else {
//     testVal = STATUS_OK;
//     sprintf(partstr, "%s %s(%.1f%%); ", descr,
//             readable_fs(totalDiskUsed, human_size_used), usedPercent);
//   }
//   strcat(retstr, partstr);

//   vlp = vlp->next_variable;
//   if (testVal == STATUS_CRITICAL) {
//     exitVal = testVal;
//   } else if (testVal == STATUS_WARNING) {
//     exitVal = testVal;
//   }
//   snmp_free_pdu(response);
// }
// if (exitVal == STATUS_CRITICAL) {
//   sprintf(finalstr, "CRITICAL - %s", retstr);
// } else if (exitVal == STATUS_WARNING) {
//   sprintf(finalstr, "WARNING - %s", retstr);
// } else {
//   sprintf(finalstr, "OK - %s", retstr);
// }
// sprintf(perfString, " |  totalDiskUsed=%luB totatDisk=%luB\n",
// totalDiskUsed,
//         totatDisk);
// strcat(finalstr, perfString);
// return finalstr;
