# Threat Intelligence Aggregator

A Python CLI that enriches IPs, domains, and file hashes using **only free API tiers**.
Results are cached for 24 hours to protect rate limits and written to a structured JSON report
plus a self-contained HTML dashboard.

---

## Free services used

| Service | Free limit | Key required |
|---|---|---|
| VirusTotal | 500 requests/day · 4 req/min | Yes |
| Shodan | 100 query credits/month | Yes |
| AbuseIPDB | 1,000 requests/day | Yes |
| ip-api.com | 45 req/min (non-commercial only) | **No** |
| python-whois | Unlimited (public WHOIS servers) | **No** |

---

## Step-by-step: obtaining free API keys

### 1. VirusTotal (500 req/day, 4 req/min)

1. Go to <https://www.virustotal.com/gui/sign-in> and click **Join us**.
2. Fill in your email and password and verify your email address.
3. Once logged in, click your avatar → **API key** (or go to your profile page).
4. Copy the **API key** shown under *Personal API key*.
5. Paste it into your `.env` file as `VIRUSTOTAL_API_KEY=<your key>`.

> **Free tier note:** The free key is limited to 4 requests per minute and 500 per day.
> The aggregator enforces these limits automatically with a token-bucket rate limiter.

---

### 2. Shodan (100 query credits/month)

1. Go to <https://account.shodan.io/register> and create an account.
2. Once registered, visit <https://account.shodan.io> and scroll to **API Key**.
3. Copy the key.
4. Paste it into your `.env` file as `SHODAN_API_KEY=<your key>`.

> **Free tier note:** Each IP/host lookup costs 1 query credit. The free tier provides 100
> credits per month. The aggregator caches results for 24 hours so the same IP is never
> queried twice within a day. Shodan returns remaining credit information in API response
> headers; the aggregator logs this after every call.

---

### 3. AbuseIPDB (1,000 req/day)

1. Go to <https://www.abuseipdb.com/register> and create a free account.
2. After verifying your email, log in and visit **Account → API**.
3. Click **Create Key**, give it a name (e.g. "threat-intel"), and copy the key.
4. Paste it into your `.env` file as `ABUSEIPDB_API_KEY=<your key>`.

> **Free tier note:** 1,000 checks per day is generous for individual use.
> The aggregator caches results to avoid repeating lookups within 24 hours.

---

### 4. ip-api.com — no key required

ip-api.com is free for non-commercial use up to 45 requests per minute with no registration.
Simply use the tool; rate limiting is handled automatically.

---

### 5. WHOIS — no key required

Domain WHOIS data is fetched via the `python-whois` library which queries public WHOIS servers
directly. No account or key is needed.

---

## Installation

```bash
# 1. Clone / download the project
cd threat-intel-aggregator

# 2. Create and activate a virtual environment (recommended)
python -m venv .venv
# Windows PowerShell:
.venv\Scripts\Activate.ps1
# macOS / Linux:
source .venv/bin/activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Copy the example env file and fill in your keys
copy .env.example .env   # Windows
# cp .env.example .env   # macOS / Linux
# Then open .env and replace placeholder values with your real API keys
```

---

## Usage

### Enrich a single IOC

```bash
# IPv4 address
python cli.py --ioc 185.220.101.34

# Domain
python cli.py --ioc malware-c2.example.com

# File hash (MD5, SHA-1, or SHA-256)
python cli.py --ioc 44d88612fea8a8f36de82e1278abb02f
```

### Enrich a list of IOCs from a JSON file

Create a file `iocs.json`:
```json
["185.220.101.34", "malware-c2.example.com", "44d88612fea8a8f36de82e1278abb02f"]
```

Then run:
```bash
python cli.py --input-file iocs.json
```

### Custom output paths

```bash
python cli.py --ioc 8.8.8.8 --output-json results.json --output-html results.html
```

### Generate a dashboard from an existing report

```bash
python dashboard.py report_20240611_120000.json dashboard.html
```

---

## Output

### JSON report (`report_<timestamp>.json`)

Each entry contains:
- `ioc` – the original indicator
- `ioc_type` – `ip`, `domain`, or `hash`
- `risk_score` – computed 0-100 composite score
- `enrichments` – nested results from each service (virustotal, shodan, abuseipdb, geolocation, whois)
- `resolved_ip` – (domain only) the IP the domain resolved to at query time

### HTML dashboard (`dashboard_<timestamp>.html`)

A self-contained single file with:
- Summary cards: total IOCs, high / medium / low risk counts, average score
- Searchable, sortable table of all enriched IOCs
- Color-coded rows: red = high risk (≥70), yellow = medium (30-69), green = low/clean
- Filters by IOC type and risk level
- No internet connection required to view it (no external CDN)

---

## Caching

All API responses are cached as JSON files in the `.cache/` directory with a 24-hour TTL.
The same IOC will never be queried again within 24 hours, protecting your daily and monthly
free quotas. To force a fresh lookup, delete the relevant file from `.cache/` or clear the
entire directory.

---

## Rate limiting behaviour

| Service | Enforced limit | Strategy |
|---|---|---|
| VirusTotal | 4 req/min | Token bucket; sleeps until token available |
| Shodan | 1 req/2 s (conservative) | Token bucket |
| AbuseIPDB | 30 req/min (conservative) | Token bucket |
| ip-api.com | 45 req/min | Token bucket |

On a **429 Too Many Requests** response the tool waits 60 seconds and retries once before
giving up. All errors are returned as `{"error": "..."}` inside the enrichment result so
processing continues for the remaining IOCs.

---

## Environment variables

| Variable | Service | Required |
|---|---|---|
| `VIRUSTOTAL_API_KEY` | VirusTotal | Yes |
| `SHODAN_API_KEY` | Shodan | Yes |
| `ABUSEIPDB_API_KEY` | AbuseIPDB | Yes |

Missing keys cause the relevant enrichment function to return `{"error": "... not set"}` and
processing continues — you will still get results from the other services.

---

## Project structure

```
.
├── cli.py            # CLI entry point (argparse)
├── enricher.py       # All API query functions + unified enrich()
├── dashboard.py      # HTML dashboard generator
├── cache.py          # File-based TTL cache
├── ratelimiter.py    # Token-bucket rate limiters
├── requirements.txt
├── .env.example
├── README.md
└── .cache/           # Auto-created; stores cached API responses (git-ignored)
```

---

## Disclaimer

This tool is intended for **defensive security research and threat analysis** on infrastructure
you are authorised to investigate. Respect each service's terms of use. The free tiers are
for personal, non-commercial, and research use — do not use this tool for bulk commercial
intelligence gathering.
