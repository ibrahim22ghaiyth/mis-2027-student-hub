#!/usr/bin/env bash
set -e
cd "$(dirname "$0")"
export PORT=8127
export HOST=127.0.0.1
echo 'MIS 2027: http://127.0.0.1:8127'
python3 server.py
