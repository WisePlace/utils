#!/bin/bash

BLUE='\033[1;34m'
YELLOW='\033[1;33m'
WHITE='\033[1;37m'
GREEN='\033[1;32m'
RED='\033[1;31m'
NC='\033[0m'
PREFIX="[·]"
script_name=$(basename "$0")
DRY_RUN=false
SILENT=false
TMP_LOGS=()

cleanup() {
  for log in "${TMP_LOGS[@]}"; do
    rm -f "$log"
  done
}
trap cleanup EXIT

show_help() {
  echo -e "---------------------------------------"
  echo -e "${BLUE}${PREFIX} Usage:${NC} sudo $script_name -i <package1> <package2> [...] [--dry-run] [--silent]"
  echo -e "${BLUE}${PREFIX} Description:${NC} Installs the specified packages if not already installed."
  echo -e "${BLUE}${PREFIX} Options:${NC}"
  echo -e "  -i             List of packages to install (required)"
  echo -e "  --dry-run      Simulate actions without installing anything"
  echo -e "  --silent       Suppress non-error output (useful for scripting)"
  echo -e "  -h, --help     Show this help message"
  echo -e "---------------------------------------"
  exit 0
}

if [[ "$EUID" -ne 0 ]]; then
  echo -e "${RED}${PREFIX} Please run this script as root (use sudo).${NC}"
  exit 1
fi

if [[ $# -eq 0 ]]; then
  show_help
fi

PACKAGES=()
while [[ $# -gt 0 ]]; do
  case "$1" in
    -i)
      shift
      while [[ $# -gt 0 && "$1" != --* && "$1" != -h && "$1" != "--help" && "$1" != "--h" ]]; do
        PACKAGES+=("$1")
        shift
      done
      ;;
    --dry-run)
      DRY_RUN=true
      shift
      ;;
    --silent)
      SILENT=true
      shift
      ;;
    -h|--help|--h)
      show_help
      ;;
    *)
      echo -e "${RED}${PREFIX} Unknown option: $1${NC}"
      show_help
      ;;
  esac
done

if [[ ${#PACKAGES[@]} -eq 0 ]]; then
  echo -e "${RED}${PREFIX} No packages specified.${NC}"
  show_help
fi

for pkg in "${PACKAGES[@]}"; do
  if dpkg -s "$pkg" &> /dev/null; then
    $SILENT || echo -e "${BLUE}${PREFIX} Package ${pkg} already present.${NC}"
  else
    if $DRY_RUN; then
      $SILENT || echo -e "${YELLOW}${PREFIX} Would install package ${WHITE}${pkg}${YELLOW}.${NC}"
      continue
    fi

    $SILENT || echo -e "${YELLOW}${PREFIX} Installing package ${WHITE}${pkg}${YELLOW}...${NC}"
    log_file="/tmp/install_${pkg}_$$.log"
    TMP_LOGS+=("$log_file")

    if apt-get install -y "$pkg" &> "$log_file"; then
      $SILENT || echo -e "${GREEN}${PREFIX} ${pkg} successfully installed.${NC}"
    else
      err=$(tail -n 5 "$log_file" | tr '\n' ' ')
      echo -e "${RED}${PREFIX} Error while installing ${pkg}: $err${NC}"
    fi
  fi
done
