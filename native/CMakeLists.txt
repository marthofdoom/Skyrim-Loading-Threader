# LoadingThreader (LT-2b timing probe). Structure copied from MSRF
# (marth-save-reload-fix/native), which copied MFO/MEO/MAO, which copied the
# SkyrimDev/HelloWorld-using-CommonLibSSE-NG template. Doctrine: adapt working
# sources, never write a build system from memory.
#
# Deliberately minimal dependencies: CommonLibSSE-NG only (it brings spdlog).
cmake_minimum_required(VERSION 3.21)

project(LoadingThreader VERSION 0.2.0 LANGUAGES CXX)

find_package(CommonLibSSE CONFIG REQUIRED)

add_commonlibsse_plugin(${PROJECT_NAME} SOURCES
    plugin.cpp
    Probe.cpp
    Report.cpp
    Oracle.cpp
)

target_compile_features(${PROJECT_NAME} PRIVATE cxx_std_23)
target_precompile_headers(${PROJECT_NAME} PRIVATE PCH.h)

# Emit a PDB even in Release so a field crash symbolizes to a source line
# (Linux-Native-Tools/deploy-and-logs.md, "Symbolize a crash frame").
target_compile_options(${PROJECT_NAME} PRIVATE $<$<CXX_COMPILER_ID:MSVC>:/Zi>)
target_link_options(${PROJECT_NAME} PRIVATE $<$<CXX_COMPILER_ID:MSVC>:/DEBUG /OPT:REF /OPT:ICF>)
target_include_directories(${PROJECT_NAME} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
