#!/usr/bin/env python3
"""One-release compatibility launcher for the corrected portal spelling."""

from __future__ import annotations

import os
import pathlib
import sys


target = pathlib.Path(__file__).with_name("hypr-agent-portal-mcp.py")
os.execv(sys.executable, [sys.executable, str(target), *sys.argv[1:]])
