cmake_minimum_required (VERSION 3.10)
project (vapoursynth)

include (GNUInstallDirs)
include (ExternalProject)

find_package (PkgConfig)
pkg_check_modules (ZIMG REQUIRED zimg)

find_package (PythonLibs 3.6 REQUIRED)

find_program(WINECC winegcc)
if (WINECC STREQUAL "WINECC-NOTFOUND")
    message (FATAL_ERROR "No winegcc found")
else ()
    message (STATUS "Found winegcc: ${WINECC}")
endif ()
find_program(WINECXX wineg++)
if (WINECXX STREQUAL "WINECXX-NOTFOUND")
    message (FATAL_ERROR "No wineg++ found")
else ()
    message (STATUS "Found wineg++: ${WINECXX}")
endif ()

enable_language (ASM_NASM)

set (VS_PLUGINDIR "${CMAKE_INSTALL_FULL_LIBDIR}/vapoursynth" CACHE PATH "VapourSynth global plugin path")

add_definitions (-DNDEBUG)
add_definitions (-DVS_TARGET_OS_LINUX)
add_definitions (-DVS_TARGET_CPU_X86)
add_definitions (-DVS_CORE_EXPORTS)
add_definitions (-DVS_HAVE_AVSUBTITLERECT_AVPICTURE)
add_definitions (-DVS_PATH_PLUGINDIR="${VS_PLUGINDIR}")

set (CMAKE_C_COMPILER ${WINECC})
set (CMAKE_CXX_COMPILER ${WINECXX})
set (CMAKE_C_FLAGS "-Wall -Wextra -Wno-unused-parameter -Wno-unused-function -O3 -fvisibility=hidden -std=c99")
set (CMAKE_CXX_FLAGS "-Wall -Wextra -Wno-unused-parameter -Wno-unused-function -O3 -fvisibility=hidden -std=c++11")
set (CMAKE_ASM_NASM_FLAGS "-DARCH_X86_64=1 -DPIC -w -Worphan-labels -Wunrecognized-char -Dprivate_prefix=vs -I${CMAKE_CURRENT_SOURCE_DIR}/include/")

include_directories (PUBLIC include)

ExternalProject_Add (vapoursynth_libs
    SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR}
    CONFIGURE_COMMAND autoreconf -fiv <SOURCE_DIR> && <SOURCE_DIR>/configure --prefix=<INSTALL_DIR> --disable-static --disable-vspipe --with-plugindir=${VS_PLUGINDIR}
    BUILD_COMMAND make
    INSTALL_COMMAND make install)
ExternalProject_Get_Property (vapoursynth_libs INSTALL_DIR)
link_directories (${INSTALL_DIR}/lib)
set (vapoursynth_libs_INSTALL_DIR ${INSTALL_DIR})

add_library (vapoursynth SHARED
    src/core/boxblurfilter.cpp
    src/core/cachefilter.cpp
    src/core/cachefilter.h
    src/core/cpufeatures.c
    src/core/cpufeatures.h
    src/core/exprfilter.cpp
    src/core/filtershared.h
    src/core/genericfilters.cpp
    src/core/internalfilters.h
    src/core/jitasm.h
    src/core/lutfilters.cpp
    src/core/mergefilters.c
    src/core/reorderfilters.c
    src/core/settings.cpp
    src/core/settings.h
    src/core/simplefilters.c
    src/core/ter-116n.h
    src/core/textfilter.cpp
    src/core/transpose.c
    src/core/version.h
    src/core/vsapi.cpp
    src/core/vsapi_wine.cpp
    src/core/vscore.cpp
    src/core/vscore.h
    src/core/vslog.cpp
    src/core/vslog.h
    src/core/vsresize.cpp
    src/core/vsthreadpool.cpp
    src/core/x86utils.h
    src/core/asm/x86/check.asm
    src/core/asm/x86/cpu.asm
    src/core/asm/x86/merge.asm)
set_target_properties (vapoursynth PROPERTIES LINK_FLAGS "-no-undefined -avoid-version")
target_link_libraries (vapoursynth dl pthread ${ZIMG_LIBRARIES})

add_executable (vspipe src/vspipe/vspipe.cpp)
if (PYTHONLIBS_FOUND)
    get_filename_component (PYTHON_SONAME ${PYTHON_LIBRARY} NAME)
    target_compile_definitions (vspipe PRIVATE PYTHON_SONAME=\"${PYTHON_SONAME}\")
endif (PYTHONLIBS_FOUND)
target_link_libraries (vspipe dl pthread vapoursynth-script ${ZIMG_LIBRARIES} ${PYTHON_LIBRARIES})
add_dependencies (vspipe vapoursynth_libs)

install (DIRECTORY ${vapoursynth_libs_INSTALL_DIR}/lib/ DESTINATION ${CMAKE_INSTALL_LIBDIR} USE_SOURCE_PERMISSIONS
    PATTERN "libvapoursynth.so" EXCLUDE
    PATTERN "vapoursynth" EXCLUDE
    PATTERN "*.la" EXCLUDE)
install (DIRECTORY ${vapoursynth_libs_INSTALL_DIR}/lib/vapoursynth/ DESTINATION ${VS_PLUGINDIR} USE_SOURCE_PERMISSIONS)
install (PROGRAMS ${CMAKE_BINARY_DIR}/libvapoursynth.dll.so DESTINATION ${CMAKE_INSTALL_LIBDIR} RENAME libvapoursynth.so)
install (PROGRAMS ${CMAKE_BINARY_DIR}/vspipe.exe.so DESTINATION ${CMAKE_INSTALL_BINDIR})
install (PROGRAMS ${CMAKE_BINARY_DIR}/vspipe.exe DESTINATION ${CMAKE_INSTALL_BINDIR} RENAME vspipe)
