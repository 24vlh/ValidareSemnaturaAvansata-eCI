#!/usr/bin/env sh
set -eu

usage() {
    cat <<'EOF'
Usage:
  ./scripts/build-release.sh [--target all|folder|portable] [--version <x.y.z>]

Examples:
  ./scripts/build-release.sh --target all
  ./scripts/build-release.sh --version 2.0.3 --target all
  ./scripts/build-release.sh --version 2.0.3 --target folder
  ./scripts/build-release.sh --version 2.0.3 --target portable
EOF
}

TARGET="all"
VERSION=""

while [ "$#" -gt 0 ]; do
    case "$1" in
        --target)
            [ "$#" -ge 2 ] || { echo "--target requires a value" >&2; exit 2; }
            TARGET="$2"
            shift 2
            ;;
        --version)
            [ "$#" -ge 2 ] || { echo "--version requires a value" >&2; exit 2; }
            VERSION="$2"
            shift 2
            ;;
        --help|-h)
            usage
            exit 0
            ;;
        *)
            echo "Unknown argument: $1" >&2
            usage >&2
            exit 2
            ;;
    esac
done

case "$TARGET" in
    all|folder|portable)
        ;;
    *)
        echo "Invalid --target value: $TARGET" >&2
        exit 2
        ;;
esac

if ! command -v wslpath >/dev/null 2>&1; then
    echo "wslpath is required to invoke the Windows PowerShell build script." >&2
    exit 1
fi

if command -v powershell.exe >/dev/null 2>&1; then
    POWERSHELL_BIN="powershell.exe"
elif command -v pwsh.exe >/dev/null 2>&1; then
    POWERSHELL_BIN="pwsh.exe"
else
    echo "Neither powershell.exe nor pwsh.exe is available in this WSL environment." >&2
    exit 1
fi

SCRIPT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd -P)
POWERSHELL_SCRIPT=$(wslpath -w "$SCRIPT_DIR/build-release.ps1")

set -- "$POWERSHELL_BIN" -NoProfile -ExecutionPolicy Bypass -File "$POWERSHELL_SCRIPT" -Target "$TARGET"

if [ -n "$VERSION" ]; then
    set -- "$@" -Version "$VERSION"
fi

exec "$@"
