#!/usr/bin/env python3
"""Repository launcher for the self-contained laz-masque-ops Skill."""

import runpy
from pathlib import Path


SCRIPT = (
    Path(__file__).resolve().parent.parent
    / ".agents"
    / "skills"
    / "laz-masque-ops"
    / "scripts"
    / "laz-masque-ops.py"
)

runpy.run_path(str(SCRIPT), run_name="__main__")
