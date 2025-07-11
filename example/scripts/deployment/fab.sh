#!/bin/bash

set -eu

cd "$( dirname "$0" )"

SERVER_ADDRESS=web-eid.eu
SERVER_USER=username
SERVER_PORT=22

export WEBEID_DIR='web-eid/test-server-web-eid-authtoken-validation-java/example'

. venv/bin/activate
~/.local/bin/fab -e -H ${SERVER_USER}@${SERVER_ADDRESS}:${SERVER_PORT} "$@"
