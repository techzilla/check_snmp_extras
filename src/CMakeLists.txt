
add_executable(check_snmp_disk check_snmp_disk.c)
add_executable(check_snmp_load check_snmp_load.c)

target_link_libraries(check_snmp_disk ${NETSNMP_LIBRARIES})
target_link_libraries(check_snmp_load ${NETSNMP_LIBRARIES})


install(TARGETS check_snmp_disk check_snmp_load
  ARCHIVE DESTINATION ${ARCHIVE_DIR}
  LIBRARY DESTINATION ${LIBRARY_DIR}
  RUNTIME DESTINATION ${RUNTIME_DIR}
)
