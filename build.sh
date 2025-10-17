#!/bin/bash
# build.sh — kompilacja programu loracrypt

# Ścieżka do katalogu Homebrew (dla architektury ARM/M2)
BREW_PREFIX=$(brew --prefix)

# Kompilacja C + C++ razem
gcc loracrypt.c server_commands.cpp -o loracrypt \
    -I"$BREW_PREFIX/include" \
    -L"$BREW_PREFIX/lib" \
    -lsodium -lpthread -lncurses
