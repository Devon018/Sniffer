# Additional clean files
cmake_minimum_required(VERSION 3.16)

if("${CONFIG}" STREQUAL "" OR "${CONFIG}" STREQUAL "Debug")
  file(REMOVE_RECURSE
  "CMakeFiles\\SmartSniffer_autogen.dir\\AutogenUsed.txt"
  "CMakeFiles\\SmartSniffer_autogen.dir\\ParseCache.txt"
  "SmartSniffer_autogen"
  )
endif()
