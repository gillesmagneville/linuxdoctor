#!/bin/bash
# SPDX-License-Identifier: GPL-3.0-only
set -euo pipefail

# ============================================================
# LinuxDoctor - build-deb.sh
#
# Builds a .deb package (Debian, Ubuntu, ...) with fpm.
# Same principles as planche-contact's build-deb.sh:
#   - version bumped interactively or with a flag (--major/--minor/--patch)
#   - VERSION and Cargo.toml updated only after a successful build
#   - clean staging in a temporary folder, normalized permissions
#
# Difference from planche-contact: no venv/pip, the code is compiled
# with cargo. No .desktop file or icon either: LinuxDoctor is a CLI/TUI
# tool for sysadmins, not a graphical application.
# ============================================================

PACKAGE_NAME="linuxdoctor"
MAINTAINER="Your Name <you@example.com>"   # <-- to customize
DESCRIPTION="Fast, explainable Linux health diagnostics"
URL="https://github.com/gillesmagneville/linuxdoctor"   # <-- to check

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUILD_DIR="$HOME/linuxdoctor-build/deb"
VERSION_FILE="$PROJECT_DIR/VERSION"
CARGO_TOML="$PROJECT_DIR/Cargo.toml"

show_help() {
  cat <<EOF
Usage: ./build-deb.sh [options]

Builds a .deb package for LinuxDoctor.

  --major               Bump the major number (1.2.3 -> 2.0.0)
  --minor               Bump the minor number (1.2.3 -> 1.3.0)
  --patch               Bump the patch number (1.2.3 -> 1.2.4)
  --no-version-change   Rebuild without changing the version
  --yes, -y             Do not ask for confirmation before building
  --clean               Remove the build folder and the generated .deb files
  --help, -h            Show this help

Without a version option: interactive mode (needs a terminal).
EOF
}

INCREMENT=""
NO_VERSION_CHANGE=false
ASSUME_YES=false
CLEAN=false

while [[ $# -gt 0 ]]; do
  case $1 in
    --major) INCREMENT="major"; shift ;;
    --minor) INCREMENT="minor"; shift ;;
    --patch) INCREMENT="patch"; shift ;;
    --no-version-change) NO_VERSION_CHANGE=true; shift ;;
    --yes|-y) ASSUME_YES=true; shift ;;
    --clean) CLEAN=true; shift ;;
    --help|-h) show_help; exit 0 ;;
    *) echo "Unknown option: $1"; show_help; exit 1 ;;
  esac
done

if [ "$CLEAN" = true ]; then
  echo ">>> Cleaning the build folder and the generated .deb files..."
  rm -rf "$BUILD_DIR"
  rm -f "$PROJECT_DIR"/*.deb
  echo ">>> Done."
  exit 0
fi

# --- Checking the required tools ---
if ! command -v fpm &> /dev/null; then
  echo "Error: fpm is not installed."
  echo "Install it with: gem install --user-install fpm"
  exit 1
fi
if ! command -v cargo &> /dev/null; then
  echo "Error: cargo (Rust) is not installed. See https://rustup.rs"
  exit 1
fi
if ! command -v dpkg-deb &> /dev/null; then
  echo "Error: dpkg-deb not found (needed to generate a .deb)."
  exit 1
fi

# --- Reading the current version ---
CURRENT_VERSION="0.1.0"
[ -f "$VERSION_FILE" ] && CURRENT_VERSION=$(tr -d '[:space:]' < "$VERSION_FILE")

IFS='.' read -r MAJOR MINOR PATCH <<< "$CURRENT_VERSION"
MAJOR=${MAJOR:-0}; MINOR=${MINOR:-0}; PATCH=${PATCH:-0}

# --- Interactive mode if no version argument was given ---
# With no version flag AND no interactive terminal, there is no way to
# know what to do: better to fail clearly here than to let `read` hit a
# silent EOF further down (which, with `set -e`, killed the script
# without a message before even compiling -- VERSION and Cargo.toml were
# therefore left unchanged with no explanation).
if [ -z "$INCREMENT" ] && [ "$NO_VERSION_CHANGE" = false ]; then
  if [ ! -t 0 ]; then
    echo "Error: no version flag given (--major/--minor/--patch/"
    echo "--no-version-change) and no interactive terminal available for"
    echo "the choice menu. Run again with one of these flags."
    exit 1
  fi
  echo ""
  echo "Current version: $CURRENT_VERSION"
  echo ""
  echo "  1) major (-> $((MAJOR + 1)).0.0)"
  echo "  2) minor (-> $MAJOR.$((MINOR + 1)).0)"
  echo "  3) patch (-> $MAJOR.$MINOR.$((PATCH + 1)))"
  echo "  4) no-version-change (rebuild as $CURRENT_VERSION)"
  echo ""
  read -p "Choice [1/2/3/4]: " CHOICE
  case $CHOICE in
    1) INCREMENT="major" ;;
    2) INCREMENT="minor" ;;
    3) INCREMENT="patch" ;;
    4) NO_VERSION_CHANGE=true ;;
    *) echo "Invalid choice. Cancelled."; exit 1 ;;
  esac
fi

if [ "$NO_VERSION_CHANGE" = true ]; then
  NEW_VERSION="$CURRENT_VERSION"
else
  case $INCREMENT in
    major) MAJOR=$((MAJOR + 1)); MINOR=0; PATCH=0 ;;
    minor) MINOR=$((MINOR + 1)); PATCH=0 ;;
    patch) PATCH=$((PATCH + 1)) ;;
  esac
  NEW_VERSION="${MAJOR}.${MINOR}.${PATCH}"
fi

echo ""
echo "========================================"
echo " Package  : $PACKAGE_NAME"
echo " Version  : $CURRENT_VERSION -> $NEW_VERSION"
echo " Format   : .deb"
echo "========================================"
echo ""
# At this point, either a version flag was given explicitly (in which
# case stdin may be non-interactive: that is a legitimate scripted/CI
# use), or the interactive menu above has already confirmed that a
# terminal is available. Only ask for confirmation if an answer can
# actually be read -- otherwise `read` fails silently on EOF and, with
# `set -e`, killed the script without a message before even compiling.
if [ "$ASSUME_YES" = true ]; then
  echo "Automatic confirmation (--yes)."
elif [ -t 0 ]; then
  read -p "Build? [y/N] " CONFIRM
  if [[ ! "$CONFIRM" =~ ^[yY]$ ]]; then
    echo "Build cancelled. No file was modified."
    exit 0
  fi
else
  echo "No interactive terminal: automatic confirmation (a version flag was given explicitly)."
fi

# --- Temporary update of Cargo.toml BEFORE compiling, so that the
#     binary embeds the right number through `linuxdoctor --version`
#     (clap reads CARGO_PKG_VERSION at compile time). Reverted if a
#     step fails. ---
if [ "$NEW_VERSION" != "$CURRENT_VERSION" ]; then
  sed -i "s/^version = \".*\"/version = \"$NEW_VERSION\"/" "$CARGO_TOML"
fi

echo ""
echo ">>> Compiling in release mode (cargo build --release)..."
BUILD_LOG=$(mktemp)
if (cd "$PROJECT_DIR" && cargo build --release --quiet) > "$BUILD_LOG" 2>&1; then
  rm -f "$BUILD_LOG"
  echo ">>> Compilation succeeded."
else
  echo ""
  echo "Error: the compilation failed."
  echo ""
  sed 's/^/  /' "$BUILD_LOG"
  rm -f "$BUILD_LOG"
  sed -i "s/^version = \".*\"/version = \"$CURRENT_VERSION\"/" "$CARGO_TOML"
  echo ""
  echo "Build cancelled: Cargo.toml restored, no package generated."
  exit 1
fi

BINARY="$PROJECT_DIR/target/release/linuxdoctor"
if [ ! -f "$BINARY" ]; then
  echo "Error: binary not found after compilation ($BINARY)."
  sed -i "s/^version = \".*\"/version = \"$CURRENT_VERSION\"/" "$CARGO_TOML"
  exit 1
fi

# --- Staging ---
echo ">>> Creating the staging tree..."
rm -rf "$BUILD_DIR"
mkdir -p "$BUILD_DIR/usr/bin"
mkdir -p "$BUILD_DIR/usr/share/doc/$PACKAGE_NAME"

cp "$BINARY" "$BUILD_DIR/usr/bin/linuxdoctor"
for doc in README.md CHANGELOG.md PROJECT_CONTEXT.md ARCHITECTURE.md LICENSE; do
  [ -f "$PROJECT_DIR/$doc" ] && cp "$PROJECT_DIR/$doc" "$BUILD_DIR/usr/share/doc/$PACKAGE_NAME/"
done

# docs/: the images that the README displays (relative links docs/...).
# They go next to the README, so the links stay valid in the package.
if [ -d "$PROJECT_DIR/docs" ]; then
  cp -r "$PROJECT_DIR/docs" "$BUILD_DIR/usr/share/doc/$PACKAGE_NAME/"
fi

# Manual page and completions: generated by the binary that was just
# compiled (`man` and `completions` subcommands), so they always match
# the real options of this version.
#   - manual page: compressed with gzip -9n (no date or file name in the
#     gzip header, hence reproducible), as the Debian policy requires;
#   - zsh: Debian/Ubuntu: folder of the completions provided by packages
#     (vendor-completions), already in zsh's fpath.
# The commands are chained with && (and not separated by newlines)
# because `set -e` is ignored inside an `if` condition: without this,
# only the last command would count. If a generation fails, Cargo.toml
# is restored as for the other steps.
echo ">>> Generating the manual page and the completions..."
MAN_DIR="$BUILD_DIR/usr/share/man/man1"
BASH_COMP_DIR="$BUILD_DIR/usr/share/bash-completion/completions"
ZSH_COMP_DIR="$BUILD_DIR/usr/share/zsh/vendor-completions"
FISH_COMP_DIR="$BUILD_DIR/usr/share/fish/vendor_completions.d"
if ! {
  mkdir -p "$MAN_DIR" "$BASH_COMP_DIR" "$ZSH_COMP_DIR" "$FISH_COMP_DIR" &&
  "$BINARY" man | gzip -9n > "$MAN_DIR/linuxdoctor.1.gz" &&
  "$BINARY" completions bash > "$BASH_COMP_DIR/linuxdoctor" &&
  "$BINARY" completions zsh > "$ZSH_COMP_DIR/_linuxdoctor" &&
  "$BINARY" completions fish > "$FISH_COMP_DIR/linuxdoctor.fish"
}; then
  echo "Error: could not generate the manual page or the completions."
  sed -i "s/^version = \".*\"/version = \"$CURRENT_VERSION\"/" "$CARGO_TOML"
  exit 1
fi

# Permission normalization: cp applies the build machine's current
# umask, not the permissions of the source. Consistent permissions are
# therefore forced, as in planche-contact's build-deb.sh.
echo ">>> Normalizing permissions..."
find "$BUILD_DIR" -type d -exec chmod 755 {} +
find "$BUILD_DIR" -type f -exec chmod 644 {} +
chmod +x "$BUILD_DIR/usr/bin/linuxdoctor"

# --- Building the package ---
echo ""
echo ">>> Building the .deb package (fpm)..."
rm -f "$PROJECT_DIR"/*.deb

if (cd "$PROJECT_DIR" && fpm -s dir -t deb \
  -n "$PACKAGE_NAME" \
  -v "$NEW_VERSION" \
  --license "GPL-3.0-only" \
  --maintainer "$MAINTAINER" \
  --description "$DESCRIPTION" \
  --url "$URL" \
  -C "$BUILD_DIR" \
  usr/); then

  # --- Version recorded only after a fully successful build ---
  echo "$NEW_VERSION" > "$VERSION_FILE"
  echo ""
  echo "Package generated:"
  ls -1 "$PROJECT_DIR"/*.deb | sed 's/^/   /'
  echo "Version recorded: $NEW_VERSION (VERSION + Cargo.toml)"
else
  echo ""
  echo "Error: fpm failed."
  sed -i "s/^version = \".*\"/version = \"$CURRENT_VERSION\"/" "$CARGO_TOML"
  rm -rf "$BUILD_DIR"
  echo "Build cancelled: Cargo.toml restored."
  exit 1
fi
