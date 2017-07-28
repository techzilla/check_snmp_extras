
add_executable(check_snmp_disks check_snmp_disks.c)

target_link_libraries(check_snmp_disks ${NETSNMP_LIBRARIES})


install(TARGETS check_snmp_disks
  ARCHIVE DESTINATION ${ARCHIVE_DIR}
  LIBRARY DESTINATION ${LIBRARY_DIR}
  RUNTIME DESTINATION ${RUNTIME_DIR}
)
