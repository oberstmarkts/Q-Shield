#!/usr/bin/env bash
set -euo pipefail
python -m app.main --mode offline
pytest -q
