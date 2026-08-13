#!/usr/bin/env sh
#
# Orisan Recorder installer.
#
#   curl -fsSL https://get.orisan.dev/install.sh | sh
#
# POSIX sh, not bash: this has to run on a minimal image where /bin/sh is dash
# and bash may not exist at all. No arrays, no [[ ]], no local -n.
#
# What it does, in order, and nothing else:
#   1. checks for Node 20+, and stops with a readable message if it is missing
#   2. installs the package into ~/.orisan/app (never globally, never sudo)
#   3. runs `orisan-rec start`
#
# It does not ask for a key, a token, or an account, because the first run does
# not need one.

set -eu

ORISAN_HOME="${ORISAN_HOME:-$HOME/.orisan}"
APP_DIR="$ORISAN_HOME/app"
PKG="${ORISAN_PKG:-orisan-recorder}"
MIN_NODE_MAJOR=20

say() { printf '%s\n' "$*"; }
die() { printf '\n  %s\n\n' "$*" >&2; exit 1; }

say ""
say "  Orisan Recorder"
say ""

# ---- 1. node ---------------------------------------------------------------
if ! command -v node >/dev/null 2>&1; then
  die "Node.js $MIN_NODE_MAJOR or newer is required and was not found.
  Install it from https://nodejs.org (the LTS build is fine), then run this again."
fi

NODE_MAJOR=$(node -p 'process.versions.node.split(".")[0]' 2>/dev/null || echo 0)
if [ "$NODE_MAJOR" -lt "$MIN_NODE_MAJOR" ]; then
  die "Node.js $MIN_NODE_MAJOR or newer is required. Found $(node -v).
  Upgrade from https://nodejs.org, then run this again."
fi

if ! command -v npm >/dev/null 2>&1; then
  die "npm was not found. It normally ships with Node.js — reinstall from https://nodejs.org."
fi

say "  Node $(node -v)"

# ---- 2. install ------------------------------------------------------------
# Into its own directory, so this never touches a global prefix and never needs
# sudo. Removing ~/.orisan removes every trace except recorded logs, which live
# under it too and are deliberately not deleted by an upgrade.
mkdir -p "$APP_DIR"
cd "$APP_DIR"

if [ ! -f package.json ]; then
  printf '{"name":"orisan-recorder-install","private":true,"version":"0.0.0"}\n' > package.json
fi

say "  Installing into $APP_DIR"
if [ -n "${ORISAN_LOCAL_TARBALL:-}" ]; then
  # Used by the repo's own packaging test: install the built tarball rather
  # than reaching for the registry.
  npm install --silent --no-audit --no-fund "$ORISAN_LOCAL_TARBALL" >/dev/null
else
  npm install --silent --no-audit --no-fund "$PKG" >/dev/null
fi

BIN="$APP_DIR/node_modules/.bin/orisan-rec"
[ -x "$BIN" ] || die "Install finished but $BIN is missing. Please report this."

# ---- 3. a shim on PATH, if we can put one somewhere sensible ---------------
for d in "$HOME/.local/bin" "$HOME/bin"; do
  if [ -d "$d" ]; then
    printf '#!/usr/bin/env sh\nexec "%s" "$@"\n' "$BIN" > "$d/orisan-rec"
    chmod +x "$d/orisan-rec"
    say "  Command installed: $d/orisan-rec"
    break
  fi
done

say ""
say "  Starting…"
exec "$BIN" start
