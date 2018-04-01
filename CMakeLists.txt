cmake_minimum_required (VERSION 2.8.11)

project (libvapoursynth)
enable_language(ASM_NASM)

find_package(PkgConfig)
pkg_check_modules(ZIMG zimg)

add_definitions(-DNDEBUG)
add_definitions(-DVS_TARGET_OS_LINUX)
add_definitions(-DVS_TARGET_CPU_X86)
add_definitions(-DVS_CORE_EXPORTS)
add_definitions(-DVS_HAVE_AVSUBTITLERECT_AVPICTURE)
add_definitions(-DVS_PATH_PLUGINDIR="/usr/lib/vapoursynth")

set(CMAKE_ASM_NASM_FLAGS "-DARCH_X86_64=1 -DPIC -w -Worphan-labels -Wunrecognized-char -Dprivate_prefix=vs -I${CMAKE_CURRENT_SOURCE_DIR}/include/")

set(CMAKE_C_COMPILER /usr/bin/winegcc)
set(CMAKE_CXX_COMPILER /usr/bin/wineg++)
set(CMAKE_C_FLAGS "-Wall -Wextra -Wno-unused-parameter -Wno-unused-function -O3 -fvisibility=hidden -std=c99")
set(CMAKE_CXX_FLAGS "-Wall -Wextra -Wno-unused-parameter -Wno-unused-function -O3 -fvisibility=hidden -std=c++11")

include_directories (PUBLIC include)

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
target_link_libraries (vapoursynth zimg dl pthread)

add_executable (vspipe src/vspipe/vspipe.cpp)
target_link_libraries (vspipe zimg dl pthread vapoursynth-script)
