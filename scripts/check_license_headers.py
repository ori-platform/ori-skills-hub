#!/usr/bin/env python3
# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import sys
from pathlib import Path

HEADER = "SPDX-License-Identifier: Apache-2.0"
missing = [str(Path(p)) for p in sys.argv[1:] if HEADER not in Path(p).read_text()]
if missing:
    print("Missing Apache-2.0 header:")
    for path in missing:
        print(f"  {path}")
    raise SystemExit(1)
