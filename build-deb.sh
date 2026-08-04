#!/bin/bash
set -euo pipefail

# ============================================================
# LinuxDoctor - build-deb.sh
#
# Construit un paquet .deb (Debian, Ubuntu, ...) avec fpm.
# Repris des memes principes que build-deb.sh de planche-contact :
#   - versionnage interactif ou par flag (--major/--minor/--patch)
#   - VERSION et Cargo.toml mis a jour uniquement apres un build reussi
#   - staging propre dans un dossier temporaire, permissions normalisees
#
# Difference avec planche-contact : pas de venv/pip, on compile avec
# cargo. Pas de .desktop/icone non plus : LinuxDoctor est un outil
# CLI/TUI pour sysadmins, pas une application graphique.
# ============================================================

PACKAGE_NAME="linuxdoctor"
MAINTAINER="Your Name <you@example.com>"   # <-- a personnaliser
DESCRIPTION="Fast, explainable Linux health diagnostics"
URL="https://github.com/gillesmagneville/linuxdoctor"   # <-- a verifier

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUILD_DIR="$HOME/linuxdoctor-build/deb"
VERSION_FILE="$PROJECT_DIR/VERSION"
CARGO_TOML="$PROJECT_DIR/Cargo.toml"

show_help() {
  cat <<EOF
Usage: ./build-deb.sh [options]

Construit un paquet .deb pour LinuxDoctor.

  --major               Incremente le numero majeur (1.2.3 -> 2.0.0)
  --minor               Incremente le numero mineur (1.2.3 -> 1.3.0)
  --patch               Incremente le numero de patch (1.2.3 -> 1.2.4)
  --no-version-change   Reconstruit sans changer la version
  --clean               Nettoie le dossier de build et les .deb generes
  --help, -h            Affiche cette aide

Sans argument de version : mode interactif.
EOF
}

INCREMENT=""
NO_VERSION_CHANGE=false
CLEAN=false

while [[ $# -gt 0 ]]; do
  case $1 in
    --major) INCREMENT="major"; shift ;;
    --minor) INCREMENT="minor"; shift ;;
    --patch) INCREMENT="patch"; shift ;;
    --no-version-change) NO_VERSION_CHANGE=true; shift ;;
    --clean) CLEAN=true; shift ;;
    --help|-h) show_help; exit 0 ;;
    *) echo "Option inconnue : $1"; show_help; exit 1 ;;
  esac
done

if [ "$CLEAN" = true ]; then
  echo ">>> Nettoyage du dossier de build et des .deb generes..."
  rm -rf "$BUILD_DIR"
  rm -f "$PROJECT_DIR"/*.deb
  echo ">>> Termine."
  exit 0
fi

# --- Verification des outils requis ---
if ! command -v fpm &> /dev/null; then
  echo "Erreur : fpm n'est pas installe."
  echo "Installe-le avec : gem install --user-install fpm"
  exit 1
fi
if ! command -v cargo &> /dev/null; then
  echo "Erreur : cargo (Rust) n'est pas installe. Voir https://rustup.rs"
  exit 1
fi
if ! command -v dpkg-deb &> /dev/null; then
  echo "Erreur : dpkg-deb introuvable (necessaire pour generer un .deb)."
  exit 1
fi

# --- Lecture de la version actuelle ---
CURRENT_VERSION="0.1.0"
[ -f "$VERSION_FILE" ] && CURRENT_VERSION=$(tr -d '[:space:]' < "$VERSION_FILE")

IFS='.' read -r MAJOR MINOR PATCH <<< "$CURRENT_VERSION"
MAJOR=${MAJOR:-0}; MINOR=${MINOR:-0}; PATCH=${PATCH:-0}

# --- Mode interactif si aucun argument de version fourni ---
if [ -z "$INCREMENT" ] && [ "$NO_VERSION_CHANGE" = false ]; then
  echo ""
  echo "Version actuelle : $CURRENT_VERSION"
  echo ""
  echo "  1) major (-> $((MAJOR + 1)).0.0)"
  echo "  2) minor (-> $MAJOR.$((MINOR + 1)).0)"
  echo "  3) patch (-> $MAJOR.$MINOR.$((PATCH + 1)))"
  echo "  4) no-version-change (reconstruire en $CURRENT_VERSION)"
  echo ""
  read -p "Choix [1/2/3/4] : " CHOICE
  case $CHOICE in
    1) INCREMENT="major" ;;
    2) INCREMENT="minor" ;;
    3) INCREMENT="patch" ;;
    4) NO_VERSION_CHANGE=true ;;
    *) echo "Choix invalide. Annulation."; exit 1 ;;
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
echo " Paquet   : $PACKAGE_NAME"
echo " Version  : $CURRENT_VERSION -> $NEW_VERSION"
echo " Format   : .deb"
echo "========================================"
echo ""
read -p "Construire ? [o/N] " CONFIRM
if [[ ! "$CONFIRM" =~ ^[oOyY]$ ]]; then
  echo "Construction annulee. Aucun fichier n'a ete modifie."
  exit 0
fi

# --- Mise a jour temporaire de Cargo.toml AVANT compilation, pour que le
#     binaire embarque le bon numero via `linuxdoctor --version` (clap lit
#     CARGO_PKG_VERSION a la compilation). Reverti si une etape echoue. ---
if [ "$NEW_VERSION" != "$CURRENT_VERSION" ]; then
  sed -i "s/^version = \".*\"/version = \"$NEW_VERSION\"/" "$CARGO_TOML"
fi

echo ""
echo ">>> Compilation en mode release (cargo build --release)..."
BUILD_LOG=$(mktemp)
if (cd "$PROJECT_DIR" && cargo build --release --quiet) > "$BUILD_LOG" 2>&1; then
  rm -f "$BUILD_LOG"
  echo ">>> Compilation reussie."
else
  echo ""
  echo "Erreur : la compilation a echoue."
  echo ""
  sed 's/^/  /' "$BUILD_LOG"
  rm -f "$BUILD_LOG"
  sed -i "s/^version = \".*\"/version = \"$CURRENT_VERSION\"/" "$CARGO_TOML"
  echo ""
  echo "Construction annulee : Cargo.toml restaure, aucun paquet genere."
  exit 1
fi

BINARY="$PROJECT_DIR/target/release/linuxdoctor"
if [ ! -f "$BINARY" ]; then
  echo "Erreur : binaire introuvable apres compilation ($BINARY)."
  sed -i "s/^version = \".*\"/version = \"$CURRENT_VERSION\"/" "$CARGO_TOML"
  exit 1
fi

# --- Staging ---
echo ">>> Creation de l'arborescence de staging..."
rm -rf "$BUILD_DIR"
mkdir -p "$BUILD_DIR/usr/bin"
mkdir -p "$BUILD_DIR/usr/share/doc/$PACKAGE_NAME"

cp "$BINARY" "$BUILD_DIR/usr/bin/linuxdoctor"
for doc in README.md CHANGELOG.md PROJECT_CONTEXT.md ARCHITECTURE.md LICENSE; do
  [ -f "$PROJECT_DIR/$doc" ] && cp "$PROJECT_DIR/$doc" "$BUILD_DIR/usr/share/doc/$PACKAGE_NAME/"
done

# Normalisation des permissions : cp applique l'umask courant de la
# machine de build, pas les permissions de la source. On force donc des
# permissions coherentes, comme dans build-deb.sh de planche-contact.
echo ">>> Normalisation des permissions..."
find "$BUILD_DIR" -type d -exec chmod 755 {} +
find "$BUILD_DIR" -type f -exec chmod 644 {} +
chmod +x "$BUILD_DIR/usr/bin/linuxdoctor"

# --- Construction du paquet ---
echo ""
echo ">>> Construction du paquet .deb (fpm)..."
rm -f "$PROJECT_DIR"/*.deb

if (cd "$PROJECT_DIR" && fpm -s dir -t deb \
  -n "$PACKAGE_NAME" \
  -v "$NEW_VERSION" \
  --license "GPL-3.0-or-later" \
  --maintainer "$MAINTAINER" \
  --description "$DESCRIPTION" \
  --url "$URL" \
  -C "$BUILD_DIR" \
  usr/); then

  # --- Version enregistree seulement apres un build complet reussi ---
  echo "$NEW_VERSION" > "$VERSION_FILE"
  echo ""
  echo "Paquet genere :"
  ls -1 "$PROJECT_DIR"/*.deb | sed 's/^/   /'
  echo "Version enregistree : $NEW_VERSION (VERSION + Cargo.toml)"
else
  echo ""
  echo "Erreur : fpm a echoue."
  sed -i "s/^version = \".*\"/version = \"$CURRENT_VERSION\"/" "$CARGO_TOML"
  rm -rf "$BUILD_DIR"
  echo "Construction annulee : Cargo.toml restaure."
  exit 1
fi
