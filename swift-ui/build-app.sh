#!/usr/bin/env bash
# Build the Swift UI into a proper macOS .app bundle so it shows a real
# Dock icon + Finder identity instead of inheriting the shell's.
#
# Usage:
#   ./build-app.sh            # release bundle at .build/Sandkasten.app
#   ./build-app.sh --open     # also open it after building
#
# Install into /Applications:
#   cp -R .build/Sandkasten.app /Applications/
#
# Run in-place (no install):
#   open .build/Sandkasten.app

set -euo pipefail
cd "$(dirname "$0")"

BUILD_MODE="${BUILD_MODE:-release}"
BUNDLE_NAME="Sandkasten"
BUNDLE_ID="com.sandkasten.app"
BUNDLE_VERSION="0.1.0"
APP_DIR=".build/${BUNDLE_NAME}.app"

echo "── building executable (${BUILD_MODE}) ──"
swift build -c "${BUILD_MODE}"

BIN_PATH="$(swift build --show-bin-path -c "${BUILD_MODE}")/SandkastenApp"
if [ ! -f "${BIN_PATH}" ]; then
    echo "ERROR: build did not produce ${BIN_PATH}" >&2
    exit 1
fi

echo "── assembling ${APP_DIR} ──"
rm -rf "${APP_DIR}"
mkdir -p "${APP_DIR}/Contents/MacOS"
mkdir -p "${APP_DIR}/Contents/Resources"
cp "${BIN_PATH}" "${APP_DIR}/Contents/MacOS/${BUNDLE_NAME}"

# Embed the `sandkasten` CLI next to the UI binary so the .app is
# self-contained — `open`-launched apps get no $PATH, so this avoids
# "sandkasten not found" errors. Probe candidate paths in order.
CLI=""
for candidate in \
    "../target/release/sandkasten" \
    "$(which sandkasten 2>/dev/null)" \
    "/opt/homebrew/bin/sandkasten" \
    "/usr/local/bin/sandkasten" \
; do
    if [ -n "${candidate}" ] && [ -x "${candidate}" ]; then
        CLI="${candidate}"
        break
    fi
done

if [ -n "${CLI}" ]; then
    # Install under Contents/Resources/ — macOS default filesystems are
    # case-insensitive, so `Contents/MacOS/sandkasten` would collide
    # with the UI's binary `Sandkasten` on the same path.
    cp "${CLI}" "${APP_DIR}/Contents/Resources/sandkasten"
    chmod +x "${APP_DIR}/Contents/Resources/sandkasten"
    echo "  ✓ embedded CLI from ${CLI} → Contents/Resources/sandkasten"
else
    echo "  ! no sandkasten CLI found to embed — the app will fall back"
    echo "    to \$PATH / Homebrew / dev paths at runtime."
fi

cat > "${APP_DIR}/Contents/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleDevelopmentRegion</key>      <string>en</string>
    <key>CFBundleExecutable</key>             <string>${BUNDLE_NAME}</string>
    <key>CFBundleIdentifier</key>             <string>${BUNDLE_ID}</string>
    <key>CFBundleInfoDictionaryVersion</key>  <string>6.0</string>
    <key>CFBundleName</key>                   <string>${BUNDLE_NAME}</string>
    <key>CFBundleDisplayName</key>            <string>sandkasten</string>
    <key>CFBundlePackageType</key>            <string>APPL</string>
    <key>CFBundleShortVersionString</key>     <string>${BUNDLE_VERSION}</string>
    <key>CFBundleVersion</key>                <string>${BUNDLE_VERSION}</string>
    <key>CFBundleSignature</key>              <string>????</string>
    <key>LSMinimumSystemVersion</key>         <string>14.0</string>
    <key>LSApplicationCategoryType</key>      <string>public.app-category.developer-tools</string>
    <key>NSHighResolutionCapable</key>        <true/>
    <key>NSSupportsAutomaticTermination</key> <true/>
    <key>NSSupportsSuddenTermination</key>    <true/>
    <!-- No LSUIElement: we want the Dock icon + Cmd-Tab presence. -->
    <key>NSHumanReadableCopyright</key>
    <string>MIT OR Apache-2.0</string>
    <key>CFBundleIconFile</key>               <string>AppIcon</string>
</dict>
</plist>
PLIST

# Optional: if the user dropped an AppIcon.icns in the Resources/ seed
# directory, copy it. Otherwise the app uses the generic macOS icon.
if [ -f "icon/AppIcon.icns" ]; then
    cp "icon/AppIcon.icns" "${APP_DIR}/Contents/Resources/AppIcon.icns"
fi

echo "── ad-hoc code signature ──"
codesign --force --sign - "${APP_DIR}" 2>/dev/null || {
    echo "  (codesign failed — app will still run locally, but Gatekeeper"
    echo "   will prompt on first open when moved across user accounts)"
}

echo ""
echo "✓ built ${APP_DIR}"
echo "  run in place:   open ${APP_DIR}"
echo "  install:        cp -R ${APP_DIR} /Applications/"

if [ "${1:-}" = "--open" ]; then
    open "${APP_DIR}"
fi
