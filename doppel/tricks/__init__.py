"""Trick Detector (P4, SIG): visual edit distance, combosquat parsing, level-squat and TLD-swap detection."""

from doppel.tricks.align import Alignment, align
from doppel.tricks.detector import TAU_CLOSE, TrickDetector, TrickResult, default_detector, trick_detector

__all__ = ["Alignment", "TAU_CLOSE", "TrickDetector", "TrickResult", "align", "default_detector", "trick_detector"]
