#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
#
# Fetch Freedoom Phase 1 (freedoom1.wad) for the Doom example and the
# benchmark matrix. Freedoom is free content under a BSD-style license
# (https://freedoom.github.io/), so it can be downloaded automatically and
# is pinned here by release and SHA-256. It is game data, not source, and is
# deliberately never committed to this repository.
#
# A commercial or shareware DOOM IWAD works the same way — pass its path to
# the Doom example's `doom` executable directly. The engine receives exactly
# the verified bytes staged by the host; framebuffer repeatability is measured
# separately by the Doom regression and is not a property of this helper.
#
# Usage: tools/fetch-doom-wad.sh [DEST_PATH]
# Prints the path of the verified WAD on success.
set -euo pipefail

FREEDOOM_VERSION="0.13.0"
# Keep this release and archive digest in sync with freedoomArchive in
# flake.nix; Nix spells the same SHA-256 digest in SRI/base64 form.
ZIP_URL="https://github.com/freedoom/freedoom/releases/download/v${FREEDOOM_VERSION}/freedoom-${FREEDOOM_VERSION}.zip"
ZIP_SHA256="3f9b264f3e3ce503b4fb7f6bdcb1f419d93c7b546f4df3e874dd878db9688f59"
WAD_SHA256="7323bcc168c5a45ff10749b339960e98314740a734c30d4b9f3337001f9e703d"

dest=${1:-${XDG_CACHE_HOME:-$HOME/.cache}/bpf-capsule/freedoom1.wad}

check() { echo "${2}  ${1}" | sha256sum --check --status; }

if [[ -f ${dest} ]] && check "${dest}" "${WAD_SHA256}"; then
    echo "${dest}"
    exit 0
fi

work=$(mktemp -d)
trap 'rm -rf "${work}"' EXIT

if command -v curl >/dev/null; then
    curl -fsSL --max-time 300 -o "${work}/freedoom.zip" "${ZIP_URL}"
elif command -v wget >/dev/null; then
    wget -q -O "${work}/freedoom.zip" "${ZIP_URL}"
else
    echo "fetch-doom-wad: need curl or wget" >&2
    exit 1
fi
check "${work}/freedoom.zip" "${ZIP_SHA256}" || {
    echo "fetch-doom-wad: checksum mismatch for ${ZIP_URL}" >&2
    exit 1
}

if command -v unzip >/dev/null; then
    unzip -q -o "${work}/freedoom.zip" -d "${work}"
elif command -v bsdtar >/dev/null; then
    bsdtar -xf "${work}/freedoom.zip" -C "${work}"
else
    echo "fetch-doom-wad: need unzip or bsdtar" >&2
    exit 1
fi
wad=$(find "${work}" -name freedoom1.wad -print -quit)
[[ -n ${wad} ]] || { echo "fetch-doom-wad: no freedoom1.wad in archive" >&2; exit 1; }
check "${wad}" "${WAD_SHA256}" || {
    echo "fetch-doom-wad: extracted WAD checksum mismatch" >&2
    exit 1
}

mkdir -p "$(dirname "${dest}")"
mv "${wad}" "${dest}"
echo "${dest}"
