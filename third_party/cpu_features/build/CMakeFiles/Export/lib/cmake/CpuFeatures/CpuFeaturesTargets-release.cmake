#----------------------------------------------------------------
# Generated CMake target import file for configuration "Release".
#----------------------------------------------------------------

# Commands may need to know the format version.
set(CMAKE_IMPORT_FILE_VERSION 1)

# Import target "CpuFeatures::cpu_features" for configuration "Release"
set_property(TARGET CpuFeatures::cpu_features APPEND PROPERTY IMPORTED_CONFIGURATIONS RELEASE)
set_target_properties(CpuFeatures::cpu_features PROPERTIES
  IMPORTED_LINK_INTERFACE_LANGUAGES_RELEASE "C"
  IMPORTED_LOCATION_RELEASE "${_IMPORT_PREFIX}/lib/libcpu_features.a"
  )

list(APPEND _IMPORT_CHECK_TARGETS CpuFeatures::cpu_features )
list(APPEND _IMPORT_CHECK_FILES_FOR_CpuFeatures::cpu_features "${_IMPORT_PREFIX}/lib/libcpu_features.a" )

# Import target "CpuFeatures::list_cpu_features" for configuration "Release"
set_property(TARGET CpuFeatures::list_cpu_features APPEND PROPERTY IMPORTED_CONFIGURATIONS RELEASE)
set_target_properties(CpuFeatures::list_cpu_features PROPERTIES
  IMPORTED_LOCATION_RELEASE "${_IMPORT_PREFIX}/bin/list_cpu_features"
  )

list(APPEND _IMPORT_CHECK_TARGETS CpuFeatures::list_cpu_features )
list(APPEND _IMPORT_CHECK_FILES_FOR_CpuFeatures::list_cpu_features "${_IMPORT_PREFIX}/bin/list_cpu_features" )

# Commands beyond this point should not need to know the version.
set(CMAKE_IMPORT_FILE_VERSION)
