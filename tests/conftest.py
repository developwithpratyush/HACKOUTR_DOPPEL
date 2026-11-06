"""Test-wide settings."""

import os

# Tests never call Gemini: the Vision AI uses a recorded answer (runs/deep/vlm_cache) or its offline fallback.
os.environ.setdefault("DOPPEL_OFFLINE", "1")
