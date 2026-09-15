import re
from bisect import bisect_right
from concurrent.futures import ThreadPoolExecutor
from functools import cache
from ipaddress import IPv4Address
from os import environ
from pathlib import Path
from tempfile import NamedTemporaryFile
from threading import local
from time import sleep

import requests
from requests.adapters import HTTPAdapter
from urllib3.util import Retry


LOCATIONS = ("CN", "HK")
RANKING_LIMIT = 100
HISTORY_LIMIT = 100
WORKERS = 16

BASE_DIR = Path(__file__).resolve().parent
LIST_FILES = (BASE_DIR / "apple.list", BASE_DIR / "openai.list")
DIRECT_FILE = BASE_DIR / "direct.list"
PROXY_FILE = BASE_DIR / "proxy.list"
REJECT_FILE = BASE_DIR / "reject.list"

RADAR_URL = "https://api.cloudflare.com/client/v4/radar/ranking/top"
DOH_URL = "https://cloudflare-dns.com/dns-query"
APNIC_URL = "https://ftp.apnic.net/stats/apnic/delegated-apnic-latest"
FILTER_URL = "https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt"

DOH_HEADERS = {"Accept": "application/dns-json"}
EXCLUDED_SUFFIXES = tuple(f".{location.lower()}" for location in LOCATIONS)
DOMAIN_PATTERN = re.compile(
    r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
)
FILTER_PATTERN = re.compile(r"\|\|([^\^]+)\^\|?(?:\$([^\s]+))?")

A = 1
NS = 2
SOA = 6

_thread = local()
_cn_ranges = ()
_cn_starts = ()


def fetch(url, *, headers=None, params=None):
    if not hasattr(_thread, "session"):
        _thread.session = requests.Session()
        _thread.session.mount("https://", HTTPAdapter(max_retries=Retry(
            total=3,
            backoff_factor=0.5,
            status_forcelist=(429, 500, 502, 503, 504),
            allowed_methods=frozenset({"GET"}),
        )))

    response = _thread.session.get(
        url,
        headers=headers,
        params=params,
        timeout=20,
    )
    response.raise_for_status()
    return response


def normalize_dns_name(domain):
    return domain.strip().lower().rstrip(".")


def is_domain(domain):
    return len(domain) <= 253 and DOMAIN_PATTERN.fullmatch(domain) is not None


def domain_suffixes(domain):
    """Yield the domain and its parents at label boundaries only."""
    while domain:
        yield domain
        _, separator, domain = domain.partition(".")
        if not separator:
            break


def fetch_top_domains(location):
    data = fetch(
        RADAR_URL,
        headers={"Authorization": f"Bearer {environ['CF_RADAR_TOKEN']}"},
        params={
            "location": location,
            "limit": RANKING_LIMIT,
            "rankingType": "POPULAR",
        },
    ).json()

    if data.get("success") is not True:
        raise RuntimeError(f"Radar ranking request failed for {location}")

    domains = [
        normalize_dns_name(item["domain"])
        for item in data["result"]["top_0"]
    ]
    if not domains or not all(is_domain(domain) for domain in domains):
        raise ValueError(f"Radar returned empty or invalid domains for {location}")
    return domains


def load_cn_ranges():
    global _cn_ranges, _cn_starts

    ranges = []

    for record in fetch(APNIC_URL).text.splitlines():
        fields = record.split("|")

        if fields[:3] == ["apnic", "CN", "ipv4"]:
            if len(fields) < 7:
                raise ValueError("Truncated APNIC IPv4 record")
            if fields[6] not in ("allocated", "assigned"):
                continue
            start = int(IPv4Address(fields[3]))
            count = int(fields[4])
            end = start + count - 1
            if count <= 0 or end > 0xFFFFFFFF:
                raise ValueError("Invalid APNIC IPv4 range")
            ranges.append((start, end))

    if not ranges:
        raise ValueError("APNIC returned no allocated CN IPv4 ranges")

    # A binary search by start is safe only after overlaps are merged.
    merged = []
    for start, end in sorted(ranges):
        if merged and start <= merged[-1][1] + 1:
            merged[-1] = (merged[-1][0], max(merged[-1][1], end))
        else:
            merged.append((start, end))
    _cn_ranges = tuple(merged)
    _cn_starts = tuple(
        start
        for start, _ in _cn_ranges
    )


def locate_ip(ip):
    value = int(IPv4Address(ip))
    index = bisect_right(_cn_starts, value) - 1

    return (
        "CN"
        if index >= 0 and value <= _cn_ranges[index][1]
        else "OTHER"
    )


@cache
def query_dns(domain, record_type):
    for attempt in range(3):
        data = fetch(
            DOH_URL,
            headers=DOH_HEADERS,
            params={"name": domain, "type": record_type},
        ).json()
        status = data.get("Status")
        # NOERROR and NXDOMAIN are valid answers; SERVFAIL is not "OTHER".
        if status in (0, 3) and not data.get("TC", False):
            return data
        if status != 2 or attempt == 2:
            raise RuntimeError(
                f"DNS query failed for {domain} ({record_type}): "
                f"Status={status}, TC={data.get('TC', False)}"
            )
        sleep(0.5 * (2 ** attempt))


@cache
def get_addresses(domain):
    return tuple(sorted({
        normalize_dns_name(record["data"])
        for record in query_dns(domain, "A").get("Answer", [])
        if record["type"] == A
    }))


@cache
def get_nameservers(domain):
    labels = domain.rstrip(".").split(".")

    for index in range(len(labels) - 1):
        data = query_dns(
            ".".join(labels[index:]),
            "NS",
        )
        nameservers = set()
        zone = None

        for record in data.get("Answer", []):
            if record["type"] == NS:
                nameservers.add(
                    normalize_dns_name(record["data"])
                )
                zone = (
                    zone
                    or normalize_dns_name(record["name"])
                )

        for record in data.get("Authority", []):
            if record["type"] == SOA:
                nameservers.add(
                    normalize_dns_name(
                        record["data"].split()[0]
                    )
                )
                zone = (
                    zone
                    or normalize_dns_name(record["name"])
                )

        if nameservers:
            return zone, tuple(sorted(nameservers))

    return None, ()


def trace_domain(
    domain,
    label,
    indent,
    visited,
):
    lines = [f"{indent}{label}"]

    for ip in get_addresses(domain):
        location = locate_ip(ip)
        lines.append(
            f"{indent}  A {ip} {location}"
        )

        if location == "CN":
            return True, lines

    zone, nameservers = get_nameservers(domain)

    if zone is None or zone in visited:
        return False, lines

    visited.add(zone)

    for nameserver in nameservers:
        found, branch = trace_domain(
            nameserver,
            f"NS {nameserver}",
            f"{indent}  ",
            visited,
        )
        lines.extend(branch)

        if found:
            return True, lines

    return False, lines


def classify_domain(domain):
    found, lines = trace_domain(
        domain,
        domain,
        "",
        set(),
    )

    return (
        domain,
        "CN" if found else "OTHER",
        lines,
    )


def load_list_domains():
    return {
        domain.removeprefix(".")
        for path in LIST_FILES
        for domain in read_list(path)
    }


def load_filter_domains():
    return parse_filter_domains(fetch(FILTER_URL).text)


def parse_filter_domains(text):
    """Extract concrete ||domain^ rules, not a general AdGuard rule engine.

    Preserve the existing whole-domain scope. Wildcards, regexes, exceptions,
    unanchored patterns and conditional modifiers cannot be flattened safely.
    A badfilter disables only the corresponding rule, including its modifiers.
    """
    rules = []
    disabled = set()
    for line in text.splitlines():
        match = FILTER_PATTERN.fullmatch(line.strip())
        if match is None:
            continue
        domain = normalize_dns_name(match[1])
        modifiers = frozenset(match[2].split(",") if match[2] else ())
        if not is_domain(domain) or modifiers - {"important", "badfilter"}:
            continue
        key = (domain, modifiers - {"badfilter"})
        if "badfilter" in modifiers:
            disabled.add(key)
        else:
            rules.append(key)

    if not rules:
        raise ValueError("AdGuard returned no supported blocking rules")
    # Dict keys give source order, deduplication and O(1) membership tests.
    return dict.fromkeys(
        domain for domain, flags in rules
        if (domain, flags) not in disabled
    )


def build_reject_list(direct, raw_proxy, filter_domains):
    """Match final direct suffixes and this run's unfiltered OTHER domains."""
    def domains(lines):
        return {
            normalize_dns_name(line.strip().removeprefix("."))
            for line in lines
            if line.strip()
        }

    direct_domains = domains(direct) - {"cn"}
    proxy_domains = domains(raw_proxy)
    reject = []

    for domain in filter_domains:
        # Only concrete domains are suitable for a domain-suffix list.
        if (
            domain == "cn"
            or domain.endswith(".cn")
            or not is_domain(domain)
        ):
            continue

        if domain in proxy_domains or any(
            suffix in direct_domains for suffix in domain_suffixes(domain)
        ):
            reject.append(f".{domain}")

    return reject


def build_lists(
    scans,
    list_domains,
    filter_domains,
):
    results = []
    direct = []
    proxy = []

    for domain, location, _ in scans:
        fields = [location]

        if domain in list_domains:
            fields.append("LIST")

        if domain in filter_domains:
            fields.append("FILTER")

        results.append(
            f"{domain}:{','.join(fields)}"
        )

        if len(fields) == 1:
            target = (
                direct
                if location == "CN"
                else proxy
            )
            target.append(f".{domain}")

    return results, direct, proxy


def write_outputs(outputs):
    """Prepare every file first, then replace each destination atomically."""
    temporary = []
    try:
        for path, lines in outputs.items():
            with NamedTemporaryFile(
                mode="w", encoding="utf-8", newline="\n",
                dir=path.parent, prefix=f".{path.name}.", delete=False,
            ) as handle:
                temp_path = Path(handle.name)
                temporary.append((temp_path, path))
                handle.writelines(f"{line}\n" for line in lines)
            temp_path.chmod(0o644)
        for temp_path, path in temporary:
            temp_path.replace(path)
    finally:
        for temp_path, _ in temporary:
            temp_path.unlink(missing_ok=True)


def read_list(path, *, missing_ok=False):
    try:
        text = path.read_text(encoding="utf-8-sig")
    except FileNotFoundError:
        if missing_ok:
            return []
        raise
    lines = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith(("#", "!")):
            continue
        domain = normalize_dns_name(line.removeprefix("."))
        if domain != "cn" and not is_domain(domain):
            raise ValueError(f"Invalid domain in {path.name}: {line!r}")
        lines.append(f".{domain}")
    return lines


def merge_history(
    path,
    current,
    pinned=(),
):
    previous = read_list(path, missing_ok=True)

    lines = list(dict.fromkeys((
        *pinned,
        *current,
        *previous,
    )))[:HISTORY_LIMIT]

    return lines


def main():
    if not environ.get("CF_RADAR_TOKEN", "").strip():
        raise RuntimeError("CF_RADAR_TOKEN is required")
    list_domains = load_list_domains()
    # Do not reuse previous DNS answers if main() is invoked again in-process.
    for cached in (query_dns, get_addresses, get_nameservers):
        cached.cache_clear()
    with ThreadPoolExecutor(
        max_workers=WORKERS
    ) as executor:
        ranges_future = executor.submit(
            load_cn_ranges
        )
        filter_future = executor.submit(
            load_filter_domains
        )

        ranked = executor.map(
            fetch_top_domains,
            LOCATIONS,
        )

        domains = list(dict.fromkeys(
            domain
            for group in ranked
            for domain in group
            if not domain.endswith(
                EXCLUDED_SUFFIXES
            )
        ))

        ranges_future.result()
        filter_domains = filter_future.result()

        scans = list(
            executor.map(
                classify_domain,
                domains,
            )
        )

    # Capture candidates before LIST/FILTER exclusion and HISTORY_LIMIT truncation.
    # Only this run's OTHER domains participate in proxy exact matching.
    raw_proxy = [domain for domain, location, _ in scans if location == "OTHER"]
    results, direct, proxy = build_lists(
        scans,
        list_domains,
        filter_domains,
    )

    direct = merge_history(
        DIRECT_FILE,
        direct,
        (".cn",),
    )
    proxy = merge_history(
        PROXY_FILE,
        proxy,
    )
    reject = build_reject_list(direct, raw_proxy, filter_domains)
    write_outputs({DIRECT_FILE: direct, PROXY_FILE: proxy, REJECT_FILE: reject})

    paths = []

    for _, _, lines in scans:
        paths.extend((*lines, ""))

    paths_output = "\n".join(paths).rstrip()
    results_output = "\n".join(results)
    cn_count = sum(
        location == "CN"
        for _, location, _ in scans
    )

    print(
        f"DNS paths:\n{paths_output}\n\n"
        f"Domain results:\n{results_output}\n\n"
        f"Summary: {len(results)} domains; "
        f"{cn_count} CN, "
        f"{len(results) - cn_count} OTHER; "
        f"{len(direct)} direct rules, "
        f"{len(proxy)} proxy rules, "
        f"{len(reject)} reject rules."
    )


if __name__ == "__main__":
    main()
