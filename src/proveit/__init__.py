"""ProveIt: check AI-generated bug reports against the real code."""

from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DATA_DIR = ROOT / "data"
CACHE_DIR = DATA_DIR / "cache"
VENDOR_DIR = ROOT / "vendor"
