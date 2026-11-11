#!/bin/bash
set -euo pipefail
# Only use disposable, self-signed test identities. No developer credentials.
mkdir -p "$RUNNER_TEMP/identities"
for name in first second; do
  openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
    -subj "/CN=Setup Keychain Test $name" \
    -addext 'keyUsage=digitalSignature' -addext 'extendedKeyUsage=codeSigning' \
    -keyout "$RUNNER_TEMP/identities/$name.key" -out "$RUNNER_TEMP/identities/$name.pem"
  password='test-password'
  if [ "$name" = second ]; then password=''; fi
  openssl pkcs12 -export -legacy -inkey "$RUNNER_TEMP/identities/$name.key" \
    -in "$RUNNER_TEMP/identities/$name.pem" -out "$RUNNER_TEMP/identities/$name.p12" -passout "pass:$password"
done
encoded=$(base64 < "$RUNNER_TEMP/identities/second.p12" | tr -d '\n')
printf '::add-mask::%s\n' "$encoded"
printf 'SECOND_CERTIFICATE=%s\n' "$encoded" >> "$GITHUB_ENV"
