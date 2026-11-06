"""Campaign Radar (P13, SIG): C18, typed links between flagged domains, and the campaigns they form.

Per-domain tools see N unrelated alerts. Campaign Radar asks "who made these?" from four kinds of evidence,
each a typed edge with its own weight:

=================  ======  ==============================================================================
edge               weight  meaning
=================  ======  ==============================================================================
shared_cert        1.0     one certificate names both (the CA validated one operator for both: certain)
cert_recipe        0.6     the same SAN shape on their certificates, overlapping CAs, first certificates
                           within 96 h (0.9 within 1 h)
naming_template    0.6     the same learned template, for the same brand (`in-<B>.<tld>`), and specific
                           enough (a literal token, or 4+ labels); never a hand-written regex per campaign
nrd_week           0.15    both in the same newly-registered-domains snapshot (shown; never joins alone)
=================  ======  ==============================================================================

Pairs whose summed weight reaches ``JOIN`` (0.5) are linked; connected components of 2+ domains are campaigns.
A campaign is a **weak, bounded** signal in the brain (C18, ``campaign_member``): it raises review priority,
it never decides a label. Modules: ``template``, ``recipe``, ``radar`` (graph + cards), ``index`` (for the brain).
"""

from doppel.contract import REPO_ROOT

CAMPAIGN_DIR = REPO_ROOT / "data" / "campaigns"
