#!/bin/bash
# build.cmd — kompilacja programu LoRaLink

# Ścieżka do katalogu Homebrew (dla architektury ARM/M2)
BREW_PREFIX=$(brew --prefix)

gcc Loralink.c -o loralink \
    -I"$BREW_PREFIX/include" \
    -L"$BREW_PREFIX/lib" \
    -lsodium -lpthread