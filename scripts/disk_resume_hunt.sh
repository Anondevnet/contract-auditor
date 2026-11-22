#!/bin/zsh
# DEPRECATED competing scheduler — heavy pause/resume is owned by
# auditor.disk_pressure inside Hunter.cycle / run_hunt.sh / panel.
# This script only prints status; it never launches hunt jobs.
set -euo pipefail
cd "$(dirname "$0")/.."
export PATH="$HOME/.pyenv/versions/3.11.9/bin:/opt/homebrew/bin:$PATH"
python3 - <<'PY'
from auditor.disk_pressure import get_controller
import json
print(json.dumps(get_controller().status(), indent=2, default=str))
PY
