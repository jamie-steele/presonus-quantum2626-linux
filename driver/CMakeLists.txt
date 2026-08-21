# SPDX-License-Identifier: GPL
# SPDX-FileCopyrightText: 2026 Raphaël Doursenaud
# Original from https://gitlab.com/phip1611/cmake-kernel-module
cmake_minimum_required(VERSION 4.0.0 FATAL_ERROR)

project("PreSonus Quantum Thunderbolt Family Linux Kernel Module with CLion IDE support / CMake" VERSION 0.1.0 LANGUAGES C)
set(CMAKE_C_STANDARD 90)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Find kernel headers
list(APPEND CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake")
find_package(KernelHeaders REQUIRED)


# find MODULE_LICENSE("GPL"), MODULE_AUTHOR() etc.
# thanks to "merseyviking" from stack overflow
add_definitions(-D__KERNEL__ -DMODULE)

# this is needed in order for CLion IDE to provide syntax highlighting
# this is independent from the actual kernel object that is built
add_executable(dummy
        # add all *.h and *.c files here that # CLion should cover
        snd-quantum.c
)

# CLion IDE will find symbols from <linux/*>
target_include_directories("dummy" PRIVATE ${KERNELHEADERS_INCLUDE_DIRS})

# Force module name definition which will be resolved at build time
add_definitions(-DKBUILD_MODNAME="snd_quantum")
