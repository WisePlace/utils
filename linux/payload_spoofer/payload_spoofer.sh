#!/bin/bash

BLUE='\033[1;34m'
YELLOW='\033[1;33m'
WHITE='\033[1;37m'
GREEN='\033[1;32m'
RED='\033[1;31m'
NC='\033[0m'
PREFIX="[·]"
script_name=$(basename "$0")

METADATA_DIR="metadata"
ICONS_DIR="icons"
OUTPUT=""
TYPE=""
SOURCE_FILE=""
ARCH="64"
USE_HIDDEN=false
USE_AES=false
EXTRA_FILES=()

show_help() {
  echo -e "---------------------------------------"
  echo -e "${BLUE}${PREFIX} Usage:${NC} ./payload_spoofer.sh <source.c/.cpp> --type <spoof_type> [options]"
  echo -e "${BLUE}${PREFIX} Description:${NC} Compile a Windows payload with spoofed icon and metadata."
  echo -e "${BLUE}${PREFIX} Options:${NC}"
  echo -e "  --type <name>      Required. Spoof type (must match files in icons/ and metadata/)"
  echo -e "  --output <name>    Optional. Output binary name (default: <type>.exe)"
  echo -e "  --hidden           Optional. Hide console window (adds -mwindows)"
  echo -e "  --aes              Optional. Include /bin/aes.c during compilation"
  echo -e "  --add-file <file>  Optional. Add extra source file to compile"
  echo -e "  --list             Show available spoof types"
  echo -e "  -h, --help         Show this help message"
  echo -e "---------------------------------------"
  exit 0
}

list_spoofers() {
  echo -e "${BLUE}${PREFIX} Available spoofers:${NC}"
  for icon in "$ICONS_DIR"/*.ico; do
    base=$(basename "$icon" .ico)
    if [[ -f "$METADATA_DIR/$base.rc" ]]; then
      echo -e "  - $base"
    fi
  done
  exit 0
}

check_dependencies() {
  MISSING=false
  for pkg in mingw-w64 binutils-mingw-w64; do
    if ! dpkg -s "$pkg" &>/dev/null; then
      echo -e "${YELLOW}${PREFIX} Installing missing package: ${WHITE}${pkg}${NC}"
      if ! apt-get install -y "$pkg" &>/dev/null; then
        echo -e "${RED}${PREFIX} Failed to install ${pkg}. Please install it manually.${NC}"
        exit 1
      fi
    fi
  done
}
check_dependencies

if [[ ! -d "$ICONS_DIR" || ! -d "$METADATA_DIR" ]]; then
  echo -e "${RED}${PREFIX} Required folders '${ICONS_DIR}' or '${METADATA_DIR}' not found. Exiting.${NC}"
  exit 1
fi

while [[ $# -gt 0 ]]; do
  case "$1" in
    -h|--help|--h)
      show_help
      ;;
    --type)
      TYPE="$2"
      shift 2
      ;;
    --output)
      OUTPUT="$2"
      shift 2
      ;;
    --hidden)
      USE_HIDDEN=true
      shift
      ;;
    --aes)
      USE_AES=true
      shift
      ;;
    --add-file)
      EXTRA_FILES+=("$2")
      shift 2
      ;;
    --list)
      list_spoofers
      ;;
    *.c|*.cpp)
      SOURCE_FILE="$1"
      shift
      ;;
    *)
      echo -e "${RED}${PREFIX} Unknown option or argument: $1${NC}"
      show_help
      ;;
  esac
done

if [[ -z "$SOURCE_FILE" ]]; then
  echo -e "${RED}${PREFIX} No source file provided.${NC}"
  show_help
fi
if [[ ! -f "$SOURCE_FILE" ]]; then
  echo -e "${RED}${PREFIX} File '$SOURCE_FILE' does not exist.${NC}"
  exit 1
fi

if grep -qi "WOW64\|IsWow64Process\|__i386__" "$SOURCE_FILE"; then
  ARCH="32"
fi

EXT="${SOURCE_FILE##*.}"
IS_CPP=false
if [[ "$EXT" == "cpp" ]]; then
  IS_CPP=true
fi

if [[ -z "$TYPE" ]]; then
  echo -e "${RED}${PREFIX} No spoof type provided.${NC}"
  show_help
fi

ICON_PATH="$ICONS_DIR/${TYPE}.ico"
RC_PATH="$METADATA_DIR/${TYPE}.rc"
RES_PATH="/tmp/${TYPE}_resource.res"

if [[ ! -f "$ICON_PATH" || ! -f "$RC_PATH" ]]; then
  echo -e "${RED}${PREFIX} Spoof type '${TYPE}' not found in icons or metadata.${NC}"
  exit 1
fi

if [[ -z "$OUTPUT" ]]; then
  OUTPUT="${TYPE}.exe"
fi

echo -e "${BLUE}${PREFIX} Compiling resource file...${NC}"
if ! x86_64-w64-mingw32-windres "$RC_PATH" -O coff -o "$RES_PATH"; then
  echo -e "${RED}${PREFIX} Failed to compile resource file.${NC}"
  exit 1
fi

if [[ "$ARCH" == "32" ]]; then
  COMPILER=$([[ "$IS_CPP" == true ]] && echo "i686-w64-mingw32-g++" || echo "i686-w64-mingw32-gcc")
else
  COMPILER=$([[ "$IS_CPP" == true ]] && echo "x86_64-w64-mingw32-g++" || echo "x86_64-w64-mingw32-gcc")
fi

CMD=("$COMPILER" "$SOURCE_FILE" "$RES_PATH")

if $USE_AES; then
  if [[ -f "/bin/aes.c" ]]; then
    CMD+=("/bin/aes.c")
  else
    echo -e "${RED}${PREFIX} AES option was requested but /bin/aes.c is missing.${NC}"
    exit 1
  fi
fi

for file in "${EXTRA_FILES[@]}"; do
  if [[ -f "$file" ]]; then
    CMD+=("$file")
  else
    echo -e "${RED}${PREFIX} Extra file '$file' does not exist. Skipping.${NC}"
  fi
done

if $USE_HIDDEN; then
  CMD+=("-mwindows")
fi

CMD+=("-o" "$OUTPUT")

echo -e "${BLUE}${PREFIX} Compiling payload as ${ARCH}-bit ${IS_CPP:+C++} binary...${NC}"
if "${CMD[@]}"; then
  echo -e "${GREEN}${PREFIX} Compilation successful: ${WHITE}${OUTPUT}${NC}"
else
  echo -e "${RED}${PREFIX} Compilation failed.${NC}"
  exit 1
fi
