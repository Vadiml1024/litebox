# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

# Builds the SEH (Structured Exception Handling) test programs for Windows
# (x86_64) using the MinGW cross-compiler that ships with most Linux
# distributions.
#
# seh_c_test  – plain-C program testing Windows SEH runtime APIs and
#               setjmp/longjmp (GCC/MinGW does not support MSVC's
#               __try/__except syntax in C mode).
# seh_cpp_test – C++ program testing C++ exceptions (try/catch/throw),
#               which on Windows x64 use the SEH .pdata/.xdata machinery.
#
# Usage:
#   make                  # build all programs
#   make seh_c_test.exe   # build only the C test
#   make seh_cpp_test.exe # build only the C++ test
#   make clean            # remove compiled executables
#
# Prerequisites (Ubuntu/Debian):
#   sudo apt install -y mingw-w64

CC      := x86_64-w64-mingw32-gcc
CXX     := x86_64-w64-mingw32-g++

CFLAGS   := -Wall -Wextra -std=c11   -O2 -DWIN32_LEAN_AND_MEAN
CXXFLAGS := -Wall -Wextra -std=c++17 -O2 -DWIN32_LEAN_AND_MEAN -fexceptions

LDFLAGS  := -static-libgcc -static-libstdc++

PROGRAMS := seh_c_test.exe seh_cpp_test.exe

.PHONY: all clean

all: $(PROGRAMS)

seh_c_test.exe: seh_c_test.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

seh_cpp_test.exe: seh_cpp_test.cpp
	$(CXX) $(CXXFLAGS) -o $@ $< $(LDFLAGS)

clean:
	rm -f $(PROGRAMS)
