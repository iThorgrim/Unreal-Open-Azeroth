cmake_minimum_required(VERSION 3.15)
project(UnrealOpenAzeroth CXX C ASM_MASM)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

file(GLOB DLL_SOURCES CONFIGURE_DEPENDS src/dll/*.cpp)

add_library(UnrealOpenAzeroth SHARED
    ${DLL_SOURCES}
    src/dll/WorldKeyStub.asm
    third_party/minhook/src/buffer.c
    third_party/minhook/src/hook.c
    third_party/minhook/src/trampoline.c
    third_party/minhook/src/hde/hde64.c
)
target_include_directories(UnrealOpenAzeroth PRIVATE third_party/minhook/include)
target_compile_definitions(UnrealOpenAzeroth PRIVATE _CRT_SECURE_NO_WARNINGS)
target_link_libraries(UnrealOpenAzeroth PRIVATE ws2_32)

add_executable(patcher src/patcher/Patcher.cpp)
target_compile_definitions(patcher PRIVATE _CRT_SECURE_NO_WARNINGS)

# cmake -B build -A x64
# cmake --build build --config Release
