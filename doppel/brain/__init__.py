"""The brain (P5, SIG): deterministic orchestrator, automatic Quick -> Standard -> Deep escalation, decision trace."""

from doppel.brain.brain import Brain, investigate
from doppel.brain.scan import read_inputs, scan

__all__ = ["Brain", "investigate", "read_inputs", "scan"]
