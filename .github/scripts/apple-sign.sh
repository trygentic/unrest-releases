#!/bin/bash
# Apple code signing and notarization for the macOS apps in a release.
# Used by .github/workflows/release.yml for the Unrest Launcher (Unrest.app)
# and for GameGen (GameGen.app, taken out of its archive and put back).
#
#   apple-sign.sh import-cert              make a temporary keychain from MAC_CERT_P12
#   apple-sign.sh check-notary             ask Apple whether the notarization key works
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
p12_repacked="$work/unrest-cert-repacked.p12"
# Secrets written to disk are removed however the script ends.
trap 'rm -f "$api_key_file" "$p12" "$p12_repacked"' EXIT

die() { echo "::error::$*"; exit 1; }

# An OpenSSL to inspect and re-pack the .p12 with. Homebrew's OpenSSL 3 when
# it is there (GitHub's Macs have it); otherwise whatever `openssl` is, which
# on a plain Mac is LibreSSL and has no legacy provider.
find_openssl() {
  local candidate
  # APPLE_SIGN_OPENSSL names one to use instead, for trying this script.
  if [[ -n "${APPLE_SIGN_OPENSSL:-}" ]]; then echo "$APPLE_SIGN_OPENSSL"; return; fi
  for candidate in /opt/homebrew/opt/openssl@3/bin/openssl /usr/local/opt/openssl@3/bin/openssl; do
    if [[ -x "$candidate" ]]; then echo "$candidate"; return; fi
  done
  command -v openssl
}

# Does OpenSSL open this .p12 with the password in the named environment
# variable? Tried plainly, then with the legacy provider for old RC2 files.
# Prints nothing: the answer is the exit status.
p12_opens() { # file, name of the variable holding the password
  "$ossl" pkcs12 -in "$1" -passin "env:$2" -nokeys -noout >/dev/null 2>&1 && return 0
  "$ossl" pkcs12 -legacy -in "$1" -passin "env:$2" -nokeys -noout >/dev/null 2>&1
}

keychain_import() { # file, password; quiet, the caller explains a failure
  security import "$1" -k "$keychain" -f pkcs12 -P "$2" -T /usr/bin/codesign >/dev/null 2>&1
}

import_cert() {
  [[ -n "${MAC_CERT_P12:-}" ]] || die "MAC_CERT_P12 is empty. Store the output of: base64 -i certificate.p12"
  [[ -n "${MAC_CERT_PASSWORD:-}" ]] || die "MAC_CERT_PASSWORD is empty."
  umask 077
  local password size ossl legacy
  ossl=$(find_openssl)
  echo "Inspecting with: $("$ossl" version | cut -d' ' -f1-2)"

  # ---- 1. Decode. Only sizes and kinds are ever printed, never contents.
  if [[ "$MAC_CERT_P12" == *"-----BEGIN"* ]]; then
    die "MAC_CERT_P12 holds PEM text, not a .p12. Export the Developer ID Application certificate WITH its private key as a .p12 from Keychain Access, and store: base64 -i certificate.p12"
  fi
  # Line breaks and spaces inside the base64 are fine; anything else is not base64.
  if printf '%s' "$MAC_CERT_P12" | tr -d ' \n\r\t' | LC_ALL=C grep -q '[^A-Za-z0-9+/=]'; then
    die "MAC_CERT_P12 is not base64. Store the output of: base64 -i certificate.p12"
  fi
  printf '%s' "$MAC_CERT_P12" | tr -d ' \n\r\t' | base64 -D > "$p12" 2>/dev/null \
    || die "MAC_CERT_P12 is not base64. Store the output of: base64 -i certificate.p12"
  size=$(wc -c < "$p12" | tr -d ' ')
  echo "MAC_CERT_P12 decodes to $size bytes."
  [[ "$size" -gt 0 ]] || die "MAC_CERT_P12 decodes to nothing."
  if head -c 64 "$p12" | grep -q -- '-----BEGIN'; then
    die "MAC_CERT_P12 is the base64 of a PEM file, not of a .p12. Store: base64 -i certificate.p12"
  fi
  # A PKCS#12 file is a DER sequence that starts with version 3 and a
  # pkcs7-data block. A lone certificate (.cer) or anything else is not.
  if ! "$ossl" asn1parse -inform DER -in "$p12" 2>/dev/null | head -4 | grep -q 'pkcs7-data'; then
    die "MAC_CERT_P12 is not a PKCS#12 (.p12) file. A certificate alone (.cer) is not enough: export the certificate together with its private key as a .p12."
  fi

  # ---- 2. The temporary keychain.
  password=$(openssl rand -hex 24)
  security create-keychain -p "$password" "$keychain"
  # Stay unlocked for six hours, longer than any job here.
  security set-keychain-settings -lut 21600 "$keychain"
  security unlock-keychain -p "$password" "$keychain"

  # ---- 3. Import. macOS reads only the older .p12 encryption (3DES with a
  # SHA-1 MAC). A .p12 written by OpenSSL 3 uses AES-256 and SHA-256, and
  # macOS then reports a wrong password although the password is right. So
  # when the plain import fails, ask OpenSSL which of three cases this is.
  export UNREST_P12_PASSWORD="$MAC_CERT_PASSWORD"
  if keychain_import "$p12" "$UNREST_P12_PASSWORD"; then
    echo "Imported the certificate as it is."
  else
    echo "macOS could not import the .p12 as it is. Finding out why..."
    if ! p12_opens "$p12" UNREST_P12_PASSWORD; then
      # A password pasted with a line break or space after it is a common slip.
      local trimmed="${MAC_CERT_PASSWORD%"${MAC_CERT_PASSWORD##*[![:space:]]}"}"
      export UNREST_P12_PASSWORD="$trimmed"
      if [[ "$trimmed" != "$MAC_CERT_PASSWORD" ]] && p12_opens "$p12" UNREST_P12_PASSWORD; then
        echo "::warning::MAC_CERT_PASSWORD ends with a space or line break. The password without it opens the file; re-enter the secret without the trailing character."
      else
        # Case (b): nothing opens it. The two secrets do not belong together.
        die "MAC_CERT_PASSWORD does not open MAC_CERT_P12 (OpenSSL cannot open it either, so this is not a format problem). The two secrets do not match: export the .p12 again with a password you choose, then set BOTH secrets from that one export (MAC_CERT_P12 = base64 -i certificate.p12, MAC_CERT_PASSWORD = that password, no trailing newline)."
      fi
    fi
    # The password is right. Either it only needed trimming, or (case a) the
    # file's encryption is one macOS cannot read.
    if keychain_import "$p12" "$UNREST_P12_PASSWORD"; then
      echo "Imported the certificate with the trimmed password."
    else
      echo "The password opens the .p12, so its format is the problem. How it is protected:"
      "$ossl" pkcs12 -in "$p12" -passin env:UNREST_P12_PASSWORD -nokeys -noout -info 2>&1 | grep -E '^(MAC:|PKCS7|Shrouded Keybag)' | sort -u | sed 's/^/  /' || true
      # Re-pack with the encryption macOS reads. The unprotected key is held
      # in this shell's memory and handed to OpenSSL through pipes; it is never
      # written to disk. (OpenSSL reads the key and the certificates
      # separately, so one pipe is not enough.) All certificates are kept.
      legacy=()
      "$ossl" pkcs12 -in "$p12" -passin env:UNREST_P12_PASSWORD -nokeys -noout >/dev/null 2>&1 || legacy=(-legacy)
      local pem
      pem=$("$ossl" pkcs12 ${legacy[@]+"${legacy[@]}"} -in "$p12" -passin env:UNREST_P12_PASSWORD -nodes 2>/dev/null) \
        || die "Could not read the .p12 to re-pack it."
      "$ossl" pkcs12 -export -inkey <(printf '%s\n' "$pem") -in <(printf '%s\n' "$pem") \
        -certpbe PBE-SHA1-3DES -keypbe PBE-SHA1-3DES -macalg sha1 -passout env:UNREST_P12_PASSWORD -out "$p12_repacked" >/dev/null 2>&1 \
        || { pem=""; die "Could not re-pack the .p12 for macOS. Export it again from Keychain Access on a Mac, or with OpenSSL's -legacy option."; }
      pem=""
      keychain_import "$p12_repacked" "$UNREST_P12_PASSWORD" \
        || die "macOS refuses the .p12 even after re-packing it with 3DES and SHA-1. Export it again from Keychain Access on a Mac and store that file."
      echo "Imported the certificate after re-packing it for macOS (3DES, SHA-1 MAC). To avoid this step, export the .p12 from Keychain Access, or with OpenSSL's -legacy option."
    fi
  fi
  unset UNREST_P12_PASSWORD
  rm -f "$p12" "$p12_repacked"

  # Let codesign use the key without a dialog nobody can click.
  security set-key-partition-list -S apple-tool:,apple: -s -k "$password" "$keychain" >/dev/null
  # codesign looks in the search list; put this keychain first and keep the
  # rest. (APPLE_SIGN_KEEP_SEARCH_LIST=1 leaves the list alone, for trying the
  # import on a person's own Mac.)
  if [[ -z "${APPLE_SIGN_KEEP_SEARCH_LIST:-}" ]]; then
    security list-keychains -d user | tr -d '"' | sed 's/^ *//' > "$work/unrest-keychains-before.txt"
    # shellcheck disable=SC2046
    security list-keychains -d user -s "$keychain" $(cat "$work/unrest-keychains-before.txt")
  fi

  # ---- 4. What was in it. Names of identities are not secret.
  # Only a Developer ID Application certificate can be notarized for download.
  local identity all
  all=$(security find-identity -p codesigning "$keychain")
  identity=$(security find-identity -v -p codesigning "$keychain" | awk '/"Developer ID Application: /{print $2; exit}')
  if [[ -z "$identity" ]]; then
    # Without -v the list also shows certificates macOS will not sign with.
    echo "Code signing identities in MAC_CERT_P12 (valid or not):"
    grep -E '^ +[0-9]+\) ' <<<"$all" | sed -E 's/^ *[0-9]+\) [0-9A-F]+ /  /' | sort -u || true
    if grep -q '"Developer ID Application: ' <<<"$all"; then
      die "MAC_CERT_P12 holds a \"Developer ID Application\" certificate, but macOS does not accept it for signing: it is expired or revoked, or Apple's Developer ID intermediate certificate is missing on this machine."
    fi
    if grep -Eq '"(Apple Development|Mac Developer|Apple Distribution|3rd Party Mac Developer|iPhone)' <<<"$all"; then
      die "MAC_CERT_P12 holds a development or App Store certificate. Apple only notarizes apps signed with a \"Developer ID Application\" certificate: create one at developer.apple.com (Certificates > Developer ID Application) and export it with its key."
    fi
    die "MAC_CERT_P12 holds no \"Developer ID Application\" certificate with its private key. Export that certificate and its key together from Keychain Access."
  fi
  echo "Signing as: $(security find-identity -v -p codesigning "$keychain" | awk -F'"' '/"Developer ID Application: /{print $2; exit}')"
  if [[ -n "${GITHUB_ENV:-}" ]]; then
    # The certificate's fingerprint: public, and names exactly one identity.
    echo "APPLE_SIGN_IDENTITY=$identity" >> "$GITHUB_ENV"
    echo "APPLE_KEYCHAIN=$keychain" >> "$GITHUB_ENV"
  fi
}

# Write the App Store Connect key to its file (removed when the script ends).
write_api_key() {
  [[ -n "${APPLE_API_KEY_P8:-}" && -n "${APPLE_API_KEY_ID:-}" && -n "${APPLE_API_ISSUER:-}" ]] \
    || die "APPLE_API_KEY_P8, APPLE_API_KEY_ID and APPLE_API_ISSUER are required"
  ( umask 077
    if [[ "$APPLE_API_KEY_P8" == *"BEGIN PRIVATE KEY"* ]]; then printf '%s\n' "$APPLE_API_KEY_P8" > "$api_key_file"
    else printf '%s' "$APPLE_API_KEY_P8" | tr -d ' \n\r\t' | base64 -D > "$api_key_file" 2>/dev/null || die "APPLE_API_KEY_P8 is neither the .p8 text nor its base64"; fi )
  grep -q 'BEGIN PRIVATE KEY' "$api_key_file" || die "APPLE_API_KEY_P8 does not decode to a .p8 private key"
}

# Ask Apple for this team's past submissions: a read-only call that succeeds
# only when the key, its ID and the issuer are all right. Nothing is uploaded.
check_notary() {
  write_api_key
  local out
  if out=$(xcrun notarytool history --key "$api_key_file" --key-id "$APPLE_API_KEY_ID" --issuer "$APPLE_API_ISSUER" --output-format json 2>&1); then
    echo "Apple accepts the notarization key (APPLE_API_KEY_P8, APPLE_API_KEY_ID, APPLE_API_ISSUER)."
  else
    # Apple's error text names no secret; a JSON answer could list submissions, so only errors are shown.
    grep -iE 'error|status code|unauthenticated|forbidden|agreement' <<<"$out" | head -5 || true
    die "Apple does not accept the notarization key. Check APPLE_API_KEY_ID and APPLE_API_ISSUER against App Store Connect (Users and Access > Integrations > Team Keys), that the key is not revoked, and that no agreement is waiting at developer.apple.com."
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
  app="${app%/}"
  local zip result id status
  zip="$work/notarize-$(basename "$app" .app).zip"
  result="$work/notarize-$(basename "$app" .app).json"
  write_api_key
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
  rm -f "$api_key_file" "$p12" "$p12_repacked"
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
  check-notary) check_notary ;;
  sign) shift; sign_app "$@" ;;
  notarize) shift; notarize_app "$@" ;;
  verify) shift; verify_app "$@" ;;
  cleanup) cleanup ;;
  *) echo "usage: apple-sign.sh import-cert | check-notary | sign App.app [entitlements] | notarize App.app | verify App.app | cleanup" >&2; exit 2 ;;
esac
