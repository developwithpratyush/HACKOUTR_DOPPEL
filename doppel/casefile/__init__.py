"""Case-File Writer (P10): a verdict -> a grounded, plain-language analyst case file (English or Hindi).

The LLM (Groq) only words the evidence; every sentence must cite evidence IDs and pass a validator
(``writer.py``); the label, risk and actions never come from it. ``report.py`` renders printable HTML.
"""

from doppel.casefile.writer import CaseFile, CaseFileRefused, write  # noqa: F401
