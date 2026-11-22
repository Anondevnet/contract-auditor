#!/bin/sh
# Honor PORT so the same image can run on hosts that assign the listen port.
set -eu
exec python3 audit.py dashboard --host 0.0.0.0 --port "${PORT:-8080}"
