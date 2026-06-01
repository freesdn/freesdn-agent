#!/usr/bin/env python3
"""
Development runner script for FreeSDN Agent.

Usage:
    python run.py

Or:
    python -m freesdn_agent
"""

import sys
from pathlib import Path

# Add src to path
src_path = Path(__file__).parent / "src"
sys.path.insert(0, str(src_path))

if __name__ == "__main__":
    from freesdn_agent.main import main
    sys.exit(main())
