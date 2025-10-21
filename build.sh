#!/bin/bash
# build.sh — Universal build script for loracrypt (macOS/Linux)

# Stop the script immediately if any command fails
set -e

# Define compiler and linker flags (empty by default)
CFLAGS=""
LDFLAGS=""
# Libraries are the same on both systems
LIBS="-lsodium -lpthread -lncurses"

# Detect the Operating System
OS_TYPE=$(uname -s)

case "$OS_TYPE" in
    ####################################################################
    # macOS (Darwin)
    ####################################################################
    Darwin)
        echo "💻 Detected macOS (Darwin)."
        
        # Check if Homebrew is installed
        if ! command -v brew &> /dev/null; then
            echo "❌ Homebrew (brew) is not installed."
            echo "   Please install it by running the command from: https://brew.sh"
            exit 1
        fi
        
        echo "🍺 Checking Homebrew dependencies..."
        
        # Check if packages are installed
        # We use `brew list`... or `brew install`...
        if ! brew list libsodium &> /dev/null || ! brew list ncurses &> /dev/null; then
            echo "🔔 Installing missing dependencies (libsodium, ncurses) via Homebrew..."
            brew install libsodium ncurses
        else
            echo "✅ Homebrew dependencies (libsodium, ncurses) are already installed."
        fi
        
        # Set compiler flags for Homebrew
        BREW_PREFIX=$(brew --prefix)
        CFLAGS="-I${BREW_PREFIX}/include"
        LDFLAGS="-L${BREW_PREFIX}/lib"
        ;;

    ####################################################################
    # Linux
    ####################################################################
    Linux)
        echo "🐧 Detected Linux."
        
        # Check if this is an APT-based system (Debian/Ubuntu)
        if ! command -v apt &> /dev/null; then
            echo "⚠️ 'apt' command not found. This might not be a Debian/Ubuntu-based system."
            echo "   Please ensure you have the development packages installed:"
            echo "   libsodium-dev, libncurses-dev (or equivalents for your distribution)."
            # Continue, assuming libraries are in standard paths
        else
            echo "📦 Checking APT dependencies..."
            
            # Check for development packages (header files)
            # We use dpkg-query -W (status) instead of dpkg -l (slower parsing)
            # Redirect errors, as dpkg-query returns an error if the package is missing
            if ! dpkg-query -W -f='${Status}' libsodium-dev 2>/dev/null | grep -q "installed" || \
               ! dpkg-query -W -f='${Status}' libncurses-dev 2>/dev/null | grep -q "installed"; then
                
                echo "🔔 Missing development packages detected."
                echo "   'libsodium-dev' and 'libncurses-dev' are required for compilation."
                
                # Check for sudo
                if ! command -v sudo &> /dev/null; then
                    echo "❌ 'sudo' command not found."
                    echo "   Please install the packages manually: apt install libsodium-dev libncurses-dev"
                    exit 1
                fi
                
                echo "   Running: sudo apt update && sudo apt install -y libsodium-dev libncurses-dev"
                sudo apt update
                sudo apt install -y libsodium-dev libncurses-dev
            else
                echo "✅ APT dependencies (libsodium-dev, libncurses-dev) are already installed."
            fi
        fi
        
        # On Linux, CFLAGS and LDFLAGS are usually not needed,
        # as packages install to standard paths (/usr/include, /usr/lib)
        ;;

    ####################################################################
    # Other Systems
    ####################################################################
    *)
        echo "⚠️ Unknown Operating System: $OS_TYPE."
        echo "   Proceeding with compilation without checking dependencies."
        echo "   Please ensure libsodium and ncurses are available to the compiler."
        ;;
esac

# Build the final compilation command
COMPILE_CMD="gcc loracrypt.c server_commands.c -o loracrypt $CFLAGS $LDFLAGS $LIBS"

echo ""
echo "🔧 Running build command:"
echo "$ $COMPILE_CMD"
echo ""

# Execute the compilation
gcc loracrypt.c server_commands.c -o loracrypt $CFLAGS $LDFLAGS $LIBS

echo ""
echo "✅ Done! The program has been compiled to: ./loracrypt"