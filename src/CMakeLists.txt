
add_library(check_snmp_extras_lib STATIC check_snmp_extras_lib.c)

add_executable(check_snmp_disk check_snmp_disk.c)
add_executable(check_snmp_load check_snmp_load.c)
add_executable(check_snmp_ram check_snmp_ram.c)

target_link_libraries(check_snmp_disk check_snmp_extras_lib ${NETSNMP_LIBRARIES})
target_link_libraries(check_snmp_load check_snmp_extras_lib ${NETSNMP_LIBRARIES})
target_link_libraries(check_snmp_ram check_snmp_extras_lib ${NETSNMP_LIBRARIES})

install(TARGETS check_snmp_disk check_snmp_load check_snmp_ram
  ARCHIVE DESTINATION ${ARCHIVE_DIR}
  LIBRARY DESTINATION ${LIBRARY_DIR}
  RUNTIME DESTINATION ${RUNTIME_DIR}
)
