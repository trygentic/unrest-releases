#!/bin/bash
# Apple code signing and notarization for the macOS apps in a release.
# Used by .github/workflows/release.yml for the Unrest Launcher (Unrest.app)
# and for GameGen (GameGen.app, taken out of its archive and put back).
#
#   apple-sign.sh import-cert              make a temporary keychain from MAC_CERT_P12
#   apple-sign.sh sign App.app [helper-entitlements.plist]
#   apple-sign.sh notarize App.app         submit to Apple, wait, staple the ticket
#   apple-sign.sh verify App.app           the checks a user's Mac will make
#   apple-sign.sh cleanup                  delete the keychain and the API key file
#
# Settings (repository secrets; each is given only to the step that needs it):
#   MAC_CERT_P12        base64 of a .p12 holding a "Developer ID Application" certificate and its key
#   MAC_CERT_PASSWORD   that .p12's password
#   APPLE_API_KEY_P8    App Store Connect API key (.p8), base64 or the PEM text itself
#   APPLE_API_KEY_ID    that key's ID
#   APPLE_API_ISSUER    the issuer ID of the App Store Connect team
#
# To try the signing order without a certificate, on any Mac:
#   APPLE_SIGN_IDENTITY=- apple-sign.sh sign Some.app && APPLE_SIGN_IDENTITY=- apple-sign.sh verify Some.app
# "-" is an ad-hoc signature: same order and options, but no timestamp, and
# nothing Apple or Gatekeeper will accept.
set -euo pipefail

work="${RUNNER_TEMP:-${TMPDIR:-/tmp}}"
keychain="${APPLE_KEYCHAIN:-$work/unrest-signing.keychain-db}"
api_key_file="$work/unrest-notary-key.p8"
p12="$work/unrest-cert.p12"
# Secrets written to disk are removed however the script ends.
trap 'rm -f "$api_key_file" "$p12"' EXIT

die() { echo "::error::$*"; exit 1; }

import_cert() {
  [[ -n "${MAC_CERT_P12:-}" && -n "${MAC_CERT_PASSWORD:-}" ]] || die "MAC_CERT_P12 and MAC_CERT_PASSWORD are required"
  local password
  printf '%s' "$MAC_CERT_P12" | base64 -D > "$p12" 2>/dev/null \
    || die "MAC_CERT_P12 is not base64. Store the output of: base64 -i certificate.p12"
  password=$(openssl rand -hex 24)
  security create-keychain -p "$password" "$keychain"
  # Stay unlocked for six hours, longer than any job here.
  security set-keychain-settings -lut 21600 "$keychain"
  security unlock-keychain -p "$password" "$keychain"
  security import "$p12" -k "$keychain" -f pkcs12 -P "$MAC_CERT_PASSWORD" -T /usr/bin/codesign >/dev/null \
    || die "Could not import the certificate. MAC_CERT_PASSWORD does not open MAC_CERT_P12, or the file is not a .p12."
  # Let codesign use the key without a dialog nobody can click.
  security set-key-partition-list -S apple-tool:,apple: -s -k "$password" "$keychain" >/dev/null
  # codesign looks in the search list; put this keychain first and keep the rest.
  security list-keychains -d user | tr -d '"' | sed 's/^ *//' > "$work/unrest-keychains-before.txt"
  # shellcheck disable=SC2046
  security list-keychains -d user -s "$keychain" $(cat "$work/unrest-keychains-before.txt")
  # Only a Developer ID Application certificate can be notarized for download.
  local identity
  identity=$(security find-identity -v -p codesigning "$keychain" | awk '/"Developer ID Application: /{print $2; exit}')
  if [[ -z "$identity" ]]; then
    echo "Code signing identities found in MAC_CERT_P12:"
    security find-identity -v -p codesigning "$keychain" | sed 's/^ *[0-9]*) [0-9A-F]* /  /'
    die "MAC_CERT_P12 holds no \"Developer ID Application\" certificate with its private key. Export that certificate and its key together from Keychain Access."
  fi
  echo "Signing as: $(security find-identity -v -p codesigning "$keychain" | awk -F'"' '/"Developer ID Application: /{print $2; exit}')"
  if [[ -n "${GITHUB_ENV:-}" ]]; then
    # The certificate's fingerprint: public, and names exactly one identity.
    echo "APPLE_SIGN_IDENTITY=$identity" >> "$GITHUB_ENV"
    echo "APPLE_KEYCHAIN=$keychain" >> "$GITHUB_ENV"
  fi
}

# Sign one file or bundle. Hardened runtime and a secure timestamp are both
# required for notarization. Ad-hoc ("-") cannot be timestamped.
sign_one() { # path [entitlements]
  local args=(--force --options runtime --sign "$APPLE_SIGN_IDENTITY")
  if [[ "$APPLE_SIGN_IDENTITY" == "-" ]]; then args+=(--timestamp=none); else args+=(--timestamp); fi
  if [[ -n "${APPLE_KEYCHAIN:-}" && "$APPLE_SIGN_IDENTITY" != "-" ]]; then args+=(--keychain "$APPLE_KEYCHAIN"); fi
  if [[ -n "${2:-}" ]]; then args+=(--entitlements "$2"); fi
  codesign "${args[@]}" "$1"
}

# True when a file already carries someone else's complete Developer ID
# signature (hardened runtime for programs, secure timestamp, intact).
# Apple notarizes those as they are. Re-signing them would change who the
# program is: for example the bundled `claude` program would no longer be the
# one the user's Keychain already trusts with their sign-in.
keeps_own_signature() { # path kind
  local info
  info=$(codesign -dvv "$1" 2>&1) || return 1
  grep -q '^Authority=Developer ID Application: ' <<<"$info" || return 1
  grep -q '^Timestamp=' <<<"$info" || return 1
  if [[ "$2" == exe ]]; then grep -Eq '^CodeDirectory .*flags=0x[0-9a-f]+\(([a-z-]+,)*runtime(,[a-z-]+)*\)' <<<"$info" || return 1; fi
  codesign --verify --strict "$1" 2>/dev/null
}

sign_app() {
  local app="${1:?usage: apple-sign.sh sign App.app [helper-entitlements.plist]}" helper_entitlements="${2:-}"
  [[ -n "${APPLE_SIGN_IDENTITY:-}" ]] || die "APPLE_SIGN_IDENTITY is not set; run import-cert first"
  [[ -d "$app/Contents/MacOS" ]] || die "$app is not an app bundle"
  [[ -z "$helper_entitlements" || -f "$helper_entitlements" ]] || die "no such entitlements file: $helper_entitlements"
  app="${app%/}"
  local main list signed=0 kept=0 path kind
  main="$app/Contents/MacOS/$(/usr/libexec/PlistBuddy -c 'Print :CFBundleExecutable' "$app/Contents/Info.plist")"
  [[ -f "$main" ]] || die "main executable not found in $app"
  list=$(mktemp)

  # INSIDE-OUT. A signature covers the bytes of everything beneath it, so
  # anything signed after its container breaks the container's signature.
  #
  # 1. Every program and library inside the app, deepest first: the daemon,
  #    the memory helper, the Node runtime, native add-ons. Apple refuses to
  #    notarize an app that holds any unsigned program. `file` tells us what
  #    is Mach-O; the main executable is left for step 3.
  find "$app" -type f -print0 | xargs -0 file -N --no-pad -F '::KIND::' \
    | grep -E '::KIND:: Mach-O .*(executable|dynamically linked shared library|bundle)' \
    | grep -v ' (for architecture ' \
    | awk -F'::KIND:: ' '{ kind = ($2 ~ /executable/) ? "exe" : "lib"; print kind "\t" $1 }' > "$list"
  while IFS=$'\t' read -r _ kind path; do
    [[ "$path" == "$main" ]] && continue
    if keeps_own_signature "$path" "$kind"; then
      kept=$((kept + 1)); echo "kept    ${path#"$app"/}  ($(codesign -dvv "$path" 2>&1 | sed -n 's/^Authority=Developer ID Application: //p' | head -1))"
    else
      # Entitlements belong to programs; a library runs under its program's.
      if [[ "$kind" == exe ]]; then sign_one "$path" "$helper_entitlements"; else sign_one "$path"; fi
      signed=$((signed + 1)); echo "signed  ${path#"$app"/}"
    fi
  done < <(awk -F'\t' '{ print split($2, parts, "/") "\t" $1 "\t" $2 }' "$list" | sort -t$'\t' -k1,1nr -k3,3)
  rm -f "$list"

  # 2. Bundles in the places macOS treats as nested code (frameworks, helper
  #    apps), deepest first, now that everything inside each one is signed.
  #    Folders under Resources are sealed as plain files by step 3, and their
  #    programs were signed one by one in step 1.
  local nested
  for nested in Frameworks PlugIns Helpers XPCServices Library/LoginItems; do
    [[ -d "$app/Contents/$nested" ]] || continue
    while IFS=$'\t' read -r _ path; do
      sign_one "$path"; signed=$((signed + 1)); echo "signed  ${path#"$app"/}/"
    done < <(find "$app/Contents/$nested" -type d \( -name '*.app' -o -name '*.framework' -o -name '*.xpc' -o -name '*.appex' \) \
      | awk -F/ '{ print NF "\t" $0 }' | sort -t$'\t' -k1,1nr -k2,2)
  done

  # 3. Last, the app itself: its main executable and the seal over every file
  #    in it. It needs no entitlements: the window is the system WebView.
  sign_one "$app"
  echo "signed  $(basename "$app") (the app), after $signed nested items; kept $kept signed by their own developer"
}

notarize_app() {
  local app="${1:?usage: apple-sign.sh notarize App.app}"
  [[ -n "${APPLE_API_KEY_P8:-}" && -n "${APPLE_API_KEY_ID:-}" && -n "${APPLE_API_ISSUER:-}" ]] \
    || die "APPLE_API_KEY_P8, APPLE_API_KEY_ID and APPLE_API_ISSUER are required"
  app="${app%/}"
  local zip result id status
  zip="$work/notarize-$(basename "$app" .app).zip"
  result="$work/notarize-$(basename "$app" .app).json"
  ( umask 077
    if [[ "$APPLE_API_KEY_P8" == *"BEGIN PRIVATE KEY"* ]]; then printf '%s\n' "$APPLE_API_KEY_P8" > "$api_key_file"
    else printf '%s' "$APPLE_API_KEY_P8" | base64 -D > "$api_key_file" 2>/dev/null || die "APPLE_API_KEY_P8 is neither the .p8 text nor its base64"; fi )
  grep -q 'BEGIN PRIVATE KEY' "$api_key_file" || die "APPLE_API_KEY_P8 does not decode to a .p8 private key"
  local auth=(--key "$api_key_file" --key-id "$APPLE_API_KEY_ID" --issuer "$APPLE_API_ISSUER")
  # Apple takes a zip of the app. The ticket is stapled to the app afterwards.
  /usr/bin/ditto -c -k --keepParent "$app" "$zip"
  echo "Submitting $(basename "$app") to Apple and waiting for the result..."
  # No `set -e` exit here: a rejection must still print Apple's log below.
  xcrun notarytool submit "$zip" "${auth[@]}" --wait --timeout 60m --output-format json > "$result" || true
  id=$(/usr/bin/plutil -extract id raw -o - "$result" 2>/dev/null || true)
  status=$(/usr/bin/plutil -extract status raw -o - "$result" 2>/dev/null || true)
  echo "Apple's answer: ${status:-none} (submission ${id:-none})"
  if [[ "$status" != "Accepted" ]]; then
    if [[ -n "$id" ]]; then
      echo "----- Apple's notarization log -----"
      xcrun notarytool log "$id" "${auth[@]}" || true
      echo "----- end of log -----"
    else
      echo "Apple returned no submission. The usual causes: a wrong APPLE_API_KEY_ID or APPLE_API_ISSUER, a revoked key, or an agreement waiting to be accepted at developer.apple.com."
      cat "$result" 2>/dev/null || true
    fi
    die "Apple did not notarize $(basename "$app") (${status:-no answer}). Nothing unsigned is released; fix the cause and run again."
  fi
  rm -f "$zip"
  # Staple, so the app opens on a Mac that is offline the first time.
  xcrun stapler staple "$app"
}

verify_app() {
  local app="${1:?usage: apple-sign.sh verify App.app}"
  app="${app%/}"
  # Every signature, nested ones included, and the seal over every file.
  codesign --verify --deep --strict --verbose=2 "$app"
  codesign -dvv "$app" 2>&1 | grep -E '^(Identifier|Authority|TeamIdentifier|Timestamp|CodeDirectory)' || true
  if [[ "${APPLE_SIGN_IDENTITY:-}" == "-" ]]; then
    echo "Ad-hoc trial: skipping the Gatekeeper and notarization-ticket checks."
    return
  fi
  # What Gatekeeper decides on a user's Mac. Expect "source=Notarized Developer ID".
  spctl -a -vv -t exec "$app"
  # The ticket is attached, so the first launch needs no network.
  xcrun stapler validate "$app"
}

cleanup() {
  rm -f "$api_key_file" "$p12"
  if [[ -f "$work/unrest-keychains-before.txt" ]]; then
    # shellcheck disable=SC2046
    security list-keychains -d user -s $(cat "$work/unrest-keychains-before.txt") || true
    rm -f "$work/unrest-keychains-before.txt"
  fi
  security delete-keychain "$keychain" 2>/dev/null || true
  echo "Removed the temporary keychain and key file."
}

case "${1:-}" in
  import-cert) import_cert ;;
  sign) shift; sign_app "$@" ;;
  notarize) shift; notarize_app "$@" ;;
  verify) shift; verify_app "$@" ;;
  cleanup) cleanup ;;
  *) echo "usage: apple-sign.sh import-cert | sign App.app [entitlements] | notarize App.app | verify App.app | cleanup" >&2; exit 2 ;;
esac
