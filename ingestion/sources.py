"""
ingestion/sources.py — Curated list of threat intelligence sources.

This is your competitive moat.
Quality curation matters more than quantity.
A Tier 1 source with 10 articles beats a Tier 3 with 100 noise articles.

Tier 1 = Original research, high signal, low noise
Tier 2 = Good quality, some noise
Tier 3 = High volume news, useful for awareness not deep analysis
"""

SOURCES = [

    # ── Tier 1: Vendor Research ───────────────────────────────────────────────
    {
        "name": "Mandiant Blog",
        "url":  "https://www.mandiant.com/resources/blog/rss.xml",
        "type": "vendor_research",
        "tier": 1,
        "tags": ["apt", "malware", "incident-response"]
    },
    {
        "name": "CrowdStrike Blog",
        "url":  "https://www.crowdstrike.com/blog/feed/",
        "type": "vendor_research",
        "tier": 1,
        "tags": ["apt", "ransomware", "threat-actor"]
    },
    {
        "name": "Unit 42 (Palo Alto)",
        "url":  "https://unit42.paloaltonetworks.com/feed/",
        "type": "vendor_research",
        "tier": 1,
        "tags": ["malware", "apt", "campaign"]
    },
    {
        "name": "Talos Intelligence",
        "url":  "https://blog.talosintelligence.com/feeds/posts/default",
        "type": "vendor_research",
        "tier": 1,
        "tags": ["malware", "vulnerability", "campaign"]
    },
    {
        "name": "Microsoft Security Blog",
        "url":  "https://www.microsoft.com/en-us/security/blog/feed/",
        "type": "vendor_research",
        "tier": 1,
        "tags": ["apt", "ransomware", "vulnerability"]
    },
    {
        "name": "Google TAG",
        "url":  "https://blog.google/threat-analysis-group/rss/",
        "type": "vendor_research",
        "tier": 1,
        "tags": ["apt", "0day", "nation-state"]
    },
    {
        "name": "Checkpoint Research",
        "url":  "https://research.checkpoint.com/feed/",
        "type": "vendor_research",
        "tier": 1,
        "tags": ["malware", "apt", "vulnerability"]
    },
    {
        "name": "Kaspersky Securelist",
        "url":  "https://securelist.com/feed/",
        "type": "vendor_research",
        "tier": 1,
        "tags": ["apt", "malware", "campaign"]
    },
    {
        "name": "SentinelOne Labs",
        "url":  "https://www.sentinelone.com/blog/feed/",
        "type": "vendor_research",
        "tier": 1,
        "tags": ["malware", "ransomware", "apt"]
    },
    {
        "name": "Elastic Security Labs",
        "url":  "https://www.elastic.co/security-labs/rss/feed.xml",
        "type": "vendor_research",
        "tier": 1,
        "tags": ["malware", "detection", "hunting"]
    },
    {
        "name": "Recorded Future Blog",
        "url":  "https://www.recordedfuture.com/feed",
        "type": "vendor_research",
        "tier": 1,
        "tags": ["threat-actor", "apt", "geopolitics"]
    },
    {
        "name": "Sekoia TDR",
        "url":  "https://blog.sekoia.io/feed/",
        "type": "vendor_research",
        "tier": 1,
        "tags": ["apt", "malware", "campaign"]
    },
    {
        "name": "Hunt.io Blog",
        "url":  "https://hunt.io/feed.xml",
        "type": "vendor_research",
        "tier": 1,
        "tags": ["infrastructure", "apt", "ioc"]
    },
    {
        "name": "Secureworks CTU",
        "url":  "https://www.secureworks.com/rss?feed=blog",
        "type": "vendor_research",
        "tier": 1,
        "tags": ["apt", "threat-actor", "campaign"]
    },
    {
        "name": "Rapid7 Blog",
        "url":  "https://www.rapid7.com/blog/feed/",
        "type": "vendor_research",
        "tier": 1,
        "tags": ["vulnerability", "ransomware", "exploit"]
    },

    # ── Tier 1: Government / CERT ─────────────────────────────────────────────
    {
        "name": "CISA Advisories",
        "url":  "https://www.cisa.gov/cybersecurity-advisories/all.xml",
        "type": "government",
        "tier": 1,
        "tags": ["advisory", "ics", "critical-infrastructure"]
    },
    {
        "name": "NCSC UK",
        "url":  "https://www.ncsc.gov.uk/api/1/services/v1/report-rss-feed.xml",
        "type": "government",
        "tier": 1,
        "tags": ["advisory", "apt", "uk"]
    },
    {
        "name": "US-CERT",
        "url":  "https://www.cisa.gov/uscert/ncas/current-activity.xml",
        "type": "government",
        "tier": 1,
        "tags": ["advisory", "vulnerability", "malware"]
    },

    # ── Tier 1: CVE / Vulnerability ───────────────────────────────────────────
    {
        "name": "NVD Recent CVEs",
        "url":  "https://nvd.nist.gov/feeds/xml/cve/misc/nvd-rss.xml",
        "type": "cve_feed",
        "tier": 1,
        "tags": ["cve", "vulnerability"]
    },
    {
        "name": "Exploit-DB",
        "url":  "https://www.exploit-db.com/rss.xml",
        "type": "cve_feed",
        "tier": 1,
        "tags": ["exploit", "poc", "vulnerability"]
    },
    {
        "name": "GitHub Security Advisories",
        "url":  "https://github.com/advisories.atom",
        "type": "cve_feed",
        "tier": 1,
        "tags": ["cve", "open-source", "vulnerability"]
    },

    # ── Tier 2: Independent Research ──────────────────────────────────────────
    {
        "name": "Malwarebytes Labs",
        "url":  "https://www.malwarebytes.com/blog/feed/index.xml",
        "type": "independent_research",
        "tier": 2,
        "tags": ["malware", "ransomware", "consumer"]
    },
    {
        "name": "SANS Internet Stormcast",
        "url":  "https://isc.sans.edu/rssfeed_full.xml",
        "type": "independent_research",
        "tier": 2,
        "tags": ["daily", "vulnerability", "exploit"]
    },
    {
        "name": "Krebs on Security",
        "url":  "https://krebsonsecurity.com/feed/",
        "type": "independent_research",
        "tier": 2,
        "tags": ["crime", "fraud", "breach"]
    },
    {
        "name": "Zscaler ThreatLabz",
        "url":  "https://www.zscaler.com/blogs/security-research/feed",
        "type": "vendor_research",
        "tier": 2,
        "tags": ["malware", "apt", "cloud"]
    },
    {
        "name": "Proofpoint Threat Insight",
        "url":  "https://www.proofpoint.com/us/rss.xml",
        "type": "vendor_research",
        "tier": 2,
        "tags": ["phishing", "email", "apt"]
    },
    {
        "name": "Trend Micro Research",
        "url":  "https://www.trendmicro.com/en_us/research.rss",
        "type": "vendor_research",
        "tier": 2,
        "tags": ["malware", "apt", "cloud"]
    },
    {
        "name": "ESET WeLiveSecurity",
        "url":  "https://www.welivesecurity.com/feed/",
        "type": "vendor_research",
        "tier": 2,
        "tags": ["malware", "apt", "research"]
    },
    {
        "name": "Red Canary Blog",
        "url":  "https://redcanary.com/blog/feed/",
        "type": "vendor_research",
        "tier": 2,
        "tags": ["detection", "threat-hunting", "endpoint"]
    },
    {
        "name": "Huntress Labs Blog",
        "url":  "https://www.huntress.com/blog/rss.xml",
        "type": "vendor_research",
        "tier": 2,
        "tags": ["smb", "ransomware", "detection"]
    },
    {
        "name": "Any.run Blog",
        "url":  "https://any.run/cybersecurity-blog/feed/",
        "type": "malware_analysis",
        "tier": 2,
        "tags": ["malware", "sandbox", "analysis"]
    },
    {
        "name": "MalwareBazaar Blog",
        "url":  "https://bazaar.abuse.ch/blog/feed/",
        "type": "malware_analysis",
        "tier": 2,
        "tags": ["malware", "ioc", "sample"]
    },

    # ── Tier 3: News / High Volume ────────────────────────────────────────────
    {
        "name": "Bleeping Computer",
        "url":  "https://www.bleepingcomputer.com/feed/",
        "type": "news",
        "tier": 3,
        "tags": ["news", "ransomware", "breach"]
    },
    {
        "name": "The Hacker News",
        "url":  "https://feeds.feedburner.com/TheHackersNews",
        "type": "news",
        "tier": 3,
        "tags": ["news", "breach", "vulnerability"]
    },
    {
        "name": "Dark Reading",
        "url":  "https://www.darkreading.com/rss.xml",
        "type": "news",
        "tier": 3,
        "tags": ["news", "breach", "vulnerability"]
    },
    {
        "name": "SecurityWeek",
        "url":  "https://feeds.feedburner.com/securityweek",
        "type": "news",
        "tier": 3,
        "tags": ["news", "breach", "industry"]
    },
    {
        "name": "Help Net Security",
        "url":  "https://www.helpnetsecurity.com/feed/",
        "type": "news",
        "tier": 3,
        "tags": ["news", "product", "breach"]
    },
]
