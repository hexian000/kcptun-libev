#!/bin/sh

set -ex

: r -c server.json
: r -c client.json

gdb build/src/kcptun-libev
