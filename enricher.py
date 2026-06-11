"""IOC enrichment functions.

Each function returns a dict on success or a dict with an 'error' key on failure.
Results are cached for 24 hours to protect free-tier rate limits.
"""

import re
import os
import time
import socket
import logging
from typing import Literal

import requests
import whois

import cache
import ratelimiter

log = logging.getLogger(__name__)

_SESSION = requests.Session()
_SESSION.headers["User-Agent"] = "ThreatIntelAggregator/1.0"

# --------------------------------------------------------------------------- #
#  IOC type detection
# --------------------------------------------------------------------------- #

_RE_IPV4 = re.compile(
    r"^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)$"
)
_RE_MD5 = re.compile(r"^[a-fA-F0-9]{32}$")
_RE_SHA1 = re.compile(r"^[a-fA-F0-9]{40}$")
_RE_SHA256 = re.compile(r"^[a-fA-F0-9]{64}$")


def detect_ioc_type(ioc: str) -> Literal["ip", "domain", "hash", "unknown"]:
    ioc = ioc.strip()
    if _RE_IPV4.match(ioc):
        return "ip"
    if _RE_MD5.match(ioc) or _RE_SHA1.match(ioc) or _RE_SHA256.match(ioc):
        return "hash"
    # Simple heuristic: contains a dot and no spaces → domain
    if "." in ioc and " " not in ioc:
        return "domain"
    return "unknown"


# --------------------------------------------------------------------------- #
#  VirusTotal  (free: 500 req/day, 4 req/min)
# --------------------------------------------------------------------------- #

_VT_BASE = "https://www.virustotal.com/api/v3"


def _vt_headers() -> dict:
    key = os.getenv("VIRUSTOTAL_API_KEY", "")
    if not key:
        raise EnvironmentError("VIRUSTOTAL_API_KEY not set")
    return {"x-apikey": key}


def _vt_get(path: str) -> dict:
    ratelimiter.virustotal.wait_and_consume()
    try:
        resp = _SESSION.get(f"{_VT_BASE}{path}", headers=_vt_headers(), timeout=20)
        if resp.status_code == 429:
            # Back off and retry once
            log.warning("VirusTotal rate-limited (429). Waiting 60 s…")
            time.sleep(60)
            ratelimiter.virustotal.wait_and_consume()
            resp = _SESSION.get(f"{_VT_BASE}{path}", headers=_vt_headers(), timeout=20)
        resp.raise_for_status()
        return resp.json()
    except requests.exceptions.Timeout:
        return {"error": "timeout"}
    except requests.exceptions.HTTPError as exc:
        return {"error": str(exc)}
    except EnvironmentError as exc:
        return {"error": str(exc)}


def _vt_parse_stats(attrs: dict) -> dict:
    stats = attrs.get("last_analysis_stats", {})
    total = sum(stats.values())
    malicious = stats.get("malicious", 0) + stats.get("suspicious", 0)
    return {
        "positives": malicious,
        "total": total,
        "reputation": attrs.get("reputation", None),
        "scan_date": attrs.get("last_analysis_date", None),
        "tags": attrs.get("tags", []),
    }


def query_virustotal(ioc: str) -> dict:
    ioc = ioc.strip()
    cached = cache.get("virustotal", ioc)
    if cached is not None:
        return cached

    ioc_type = detect_ioc_type(ioc)
    if ioc_type == "ip":
        raw = _vt_get(f"/ip_addresses/{ioc}")
    elif ioc_type == "domain":
        raw = _vt_get(f"/domains/{ioc}")
    elif ioc_type == "hash":
        raw = _vt_get(f"/files/{ioc}")
    else:
        return {"error": f"unsupported IOC type: {ioc_type}"}

    if "error" in raw:
        return raw

    attrs = raw.get("data", {}).get("attributes", {})
    result = {"source": "virustotal", "ioc": ioc, "ioc_type": ioc_type}
    result.update(_vt_parse_stats(attrs))

    # Extra context per type
    if ioc_type == "ip":
        result["country"] = attrs.get("country", "")
        result["asn"] = attrs.get("asn", "")
        result["as_owner"] = attrs.get("as_owner", "")
    elif ioc_type == "domain":
        result["registrar"] = attrs.get("registrar", "")
        result["creation_date"] = attrs.get("creation_date", "")

    cache.put("virustotal", ioc, result)
    return result


# --------------------------------------------------------------------------- #
#  Shodan  (free: 100 query credits/month)
# --------------------------------------------------------------------------- #

_SHODAN_BASE = "https://api.shodan.io"


def _shodan_key() -> str:
    key = os.getenv("SHODAN_API_KEY", "")
    if not key:
        raise EnvironmentError("SHODAN_API_KEY not set")
    return key


def query_shodan(ip: str) -> dict:
    ip = ip.strip()
    cached = cache.get("shodan", ip)
    if cached is not None:
        return cached

    try:
        key = _shodan_key()
    except EnvironmentError as exc:
        return {"error": str(exc)}

    ratelimiter.shodan.wait_and_consume()
    try:
        resp = _SESSION.get(
            f"{_SHODAN_BASE}/shodan/host/{ip}",
            params={"key": key},
            timeout=20,
        )
        # Shodan returns remaining credits in headers when available
        remaining = resp.headers.get("X-Shodan-Credits-Remaining")
        if remaining is not None:
            log.info("Shodan credits remaining: %s", remaining)

        if resp.status_code == 429:
            log.warning("Shodan rate-limited (429). Waiting 60 s…")
            time.sleep(60)
            return query_shodan(ip)

        if resp.status_code == 404:
            result = {"source": "shodan", "ip": ip, "found": False}
            cache.put("shodan", ip, result)
            return result

        resp.raise_for_status()
        data = resp.json()
    except requests.exceptions.Timeout:
        return {"error": "timeout"}
    except requests.exceptions.HTTPError as exc:
        return {"error": str(exc)}

    ports = sorted({item["port"] for item in data.get("data", [])})
    services = []
    for item in data.get("data", []):
        svc = {
            "port": item.get("port"),
            "transport": item.get("transport", "tcp"),
            "product": item.get("product", ""),
            "version": item.get("version", ""),
        }
        if svc not in services:
            services.append(svc)

    vulns = list(data.get("vulns", {}).keys())

    result = {
        "source": "shodan",
        "ip": ip,
        "found": True,
        "org": data.get("org", ""),
        "isp": data.get("isp", ""),
        "os": data.get("os", ""),
        "country": data.get("country_name", ""),
        "city": data.get("city", ""),
        "open_ports": ports,
        "services": services,
        "vulnerabilities": vulns,
        "hostnames": data.get("hostnames", []),
        "last_update": data.get("last_update", ""),
    }
    cache.put("shodan", ip, result)
    return result


# --------------------------------------------------------------------------- #
#  AbuseIPDB  (free: 1000 req/day)
# --------------------------------------------------------------------------- #

_ABUSE_BASE = "https://api.abuseipdb.com/api/v2"


def query_abuseipdb(ip: str) -> dict:
    ip = ip.strip()
    cached = cache.get("abuseipdb", ip)
    if cached is not None:
        return cached

    key = os.getenv("ABUSEIPDB_API_KEY", "")
    if not key:
        return {"error": "ABUSEIPDB_API_KEY not set"}

    ratelimiter.abuseipdb.wait_and_consume()
    try:
        resp = _SESSION.get(
            f"{_ABUSE_BASE}/check",
            headers={"Key": key, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": 90, "verbose": ""},
            timeout=20,
        )
        if resp.status_code == 429:
            log.warning("AbuseIPDB rate-limited (429). Waiting 60 s…")
            time.sleep(60)
            return query_abuseipdb(ip)
        resp.raise_for_status()
        data = resp.json().get("data", {})
    except requests.exceptions.Timeout:
        return {"error": "timeout"}
    except requests.exceptions.HTTPError as exc:
        return {"error": str(exc)}

    result = {
        "source": "abuseipdb",
        "ip": ip,
        "abuse_confidence_score": data.get("abuseConfidenceScore", 0),
        "country_code": data.get("countryCode", ""),
        "usage_type": data.get("usageType", ""),
        "isp": data.get("isp", ""),
        "domain": data.get("domain", ""),
        "total_reports": data.get("totalReports", 0),
        "num_distinct_users": data.get("numDistinctUsers", 0),
        "last_reported_at": data.get("lastReportedAt", ""),
        "is_whitelisted": data.get("isWhitelisted", False),
    }
    cache.put("abuseipdb", ip, result)
    return result


# --------------------------------------------------------------------------- #
#  ip-api.com  (free non-commercial, 45 req/min, no key required)
# --------------------------------------------------------------------------- #

_IPAPI_FIELDS = (
    "status,message,country,countryCode,region,regionName,"
    "city,zip,lat,lon,timezone,isp,org,as,query"
)


def geolocate(ip: str) -> dict:
    ip = ip.strip()
    cached = cache.get("ipapi", ip)
    if cached is not None:
        return cached

    ratelimiter.ipapi.wait_and_consume()
    try:
        resp = _SESSION.get(
            f"http://ip-api.com/json/{ip}",
            params={"fields": _IPAPI_FIELDS},
            timeout=10,
        )
        if resp.status_code == 429:
            log.warning("ip-api.com rate-limited (429). Waiting 65 s…")
            time.sleep(65)
            return geolocate(ip)
        resp.raise_for_status()
        data = resp.json()
    except requests.exceptions.Timeout:
        return {"error": "timeout"}
    except requests.exceptions.HTTPError as exc:
        return {"error": str(exc)}

    if data.get("status") == "fail":
        result = {"source": "ipapi", "ip": ip, "error": data.get("message", "failed")}
    else:
        result = {
            "source": "ipapi",
            "ip": ip,
            "country": data.get("country", ""),
            "country_code": data.get("countryCode", ""),
            "region": data.get("regionName", ""),
            "city": data.get("city", ""),
            "lat": data.get("lat"),
            "lon": data.get("lon"),
            "timezone": data.get("timezone", ""),
            "isp": data.get("isp", ""),
            "org": data.get("org", ""),
            "asn": data.get("as", ""),
        }
    cache.put("ipapi", ip, result)
    return result


# --------------------------------------------------------------------------- #
#  WHOIS  (python-whois, free, no key)
# --------------------------------------------------------------------------- #

def whois_lookup(domain: str) -> dict:
    domain = domain.strip().lower()
    cached = cache.get("whois", domain)
    if cached is not None:
        return cached

    try:
        w = whois.whois(domain)
    except Exception as exc:
        return {"source": "whois", "domain": domain, "error": str(exc)}

    def _str(v):
        if isinstance(v, list):
            return [str(i) for i in v]
        return str(v) if v is not None else ""

    result = {
        "source": "whois",
        "domain": domain,
        "registrar": _str(w.registrar),
        "creation_date": _str(w.creation_date),
        "expiration_date": _str(w.expiration_date),
        "updated_date": _str(w.updated_date),
        "name_servers": _str(w.name_servers),
        "status": _str(w.status),
        "emails": _str(w.emails),
        "org": _str(w.org),
        "country": _str(w.country),
    }
    cache.put("whois", domain, result)
    return result


# --------------------------------------------------------------------------- #
#  Unified enrichment entry point
# --------------------------------------------------------------------------- #

def enrich(ioc: str) -> dict:
    """Run all applicable enrichment services for a given IOC."""
    ioc = ioc.strip()
    ioc_type = detect_ioc_type(ioc)
    record: dict = {"ioc": ioc, "ioc_type": ioc_type, "enrichments": {}}

    if ioc_type == "ip":
        record["enrichments"]["virustotal"] = query_virustotal(ioc)
        record["enrichments"]["shodan"] = query_shodan(ioc)
        record["enrichments"]["abuseipdb"] = query_abuseipdb(ioc)
        record["enrichments"]["geolocation"] = geolocate(ioc)

    elif ioc_type == "domain":
        record["enrichments"]["virustotal"] = query_virustotal(ioc)
        record["enrichments"]["whois"] = whois_lookup(ioc)
        # Try to resolve to IP for geo/abuse lookups
        try:
            resolved_ip = socket.gethostbyname(ioc)
            record["resolved_ip"] = resolved_ip
            record["enrichments"]["geolocation"] = geolocate(resolved_ip)
            record["enrichments"]["abuseipdb"] = query_abuseipdb(resolved_ip)
        except socket.gaierror:
            record["resolved_ip"] = None

    elif ioc_type == "hash":
        record["enrichments"]["virustotal"] = query_virustotal(ioc)

    else:
        record["error"] = "Unrecognised IOC type. Supported: IPv4, domain, MD5/SHA1/SHA256."

    # Compute a composite risk score (0–100) for dashboard coloring
    record["risk_score"] = _compute_risk(record["enrichments"])
    return record


def _compute_risk(enrichments: dict) -> int:
    """Derive a 0-100 risk score from available enrichment data."""
    scores = []

    vt = enrichments.get("virustotal", {})
    if vt and "positives" in vt and "total" in vt and vt["total"]:
        ratio = vt["positives"] / vt["total"]
        vt_score = int(min(100, ratio * 130))
        scores.append(vt_score)
        # Detection ratio is authoritative for files — skip reputation averaging
        # when detections clearly indicate malicious (avoids EICAR-style false-low)
        if vt_score < 70 and vt.get("reputation") is not None:
            rep = vt["reputation"]
            normalized = max(0, min(100, 50 - rep))
            scores.append(normalized)
    elif vt and vt.get("reputation") is not None:
        rep = vt["reputation"]
        scores.append(max(0, min(100, 50 - rep)))

    abuse = enrichments.get("abuseipdb", {})
    if abuse and "abuse_confidence_score" in abuse:
        scores.append(abuse["abuse_confidence_score"])

    shodan = enrichments.get("shodan", {})
    if shodan and shodan.get("vulnerabilities"):
        # Having known CVEs bumps the risk
        scores.append(min(100, 40 + len(shodan["vulnerabilities"]) * 10))

    return int(sum(scores) / len(scores)) if scores else 0
