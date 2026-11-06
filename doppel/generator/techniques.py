"""Technique codes, as defined in docs/ps08-attack-catalog.md section 2."""

TECHNIQUES = {
    "T1": "typosquat (missing, extra, swapped or neighbouring-key letter)",
    "T2": "twin letters (ASCII look-alikes: rn/m, vv/w, 0/o)",
    "T3": "homoglyph (foreign-script letters)",
    "T4": "combosquat (brand + lure words)",
    "T5": "ending swap (TLD swap)",
    "T6": "level-squat (genuine address as a prefix of another owner)",
    "T7": "trust-signal mimicry (bank-in, gov-in, blog-google)",
    "T8": "brand-less clone (page-level; not generated as names)",
    "T9": "sleeper (a status, not a naming trick)",
    "T10": "genuine but odd (negatives that must stay green)",
    "T11": "free-hosting subdomain",
    "T12": "soundsquat (sounds the same)",
    "T13": "bitsquat (one flipped bit)",
}

# Techniques the generator produces as look-alike names.
GENERATED = ["T1", "T2", "T3", "T4", "T5", "T6", "T7", "T11", "T12", "T13"]

# Attacker-registrable endings: the most common TLDs in our NRD snapshot (data/STATS.json)
# plus the ones Indian smishing campaigns use (.in, .co.in, .icu, .top, .click; attack catalog).
ATTACKER_TLDS = [
    "com", "in", "co.in", "net", "org", "online", "top", "xyz", "shop", "site", "info", "icu",
    "live", "click", "link", "co", "me", "vip", "cc", "buzz", "sbs", "cfd", "bond", "lol", "cyou",
]

# Free-hosting platforms: the top PSL private suffixes among PhiUSIIL phishing rows, plus
# common site builders (doppel/address/free_hosting_extra.txt).
HOSTING_PLATFORMS = [
    "web.app", "firebaseapp.com", "repl.co", "workers.dev", "pages.dev", "netlify.app", "vercel.app",
    "github.io", "glitch.me", "weeblysite.com", "godaddysites.com", "000webhostapp.com", "square.site",
    "blogspot.com", "mystrikingly.com", "jimdosite.com",
]
